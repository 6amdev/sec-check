"""
โมดูล host — ตรวจการตั้งค่าความปลอดภัยของเครื่อง Linux นี้ (อ่านอย่างเดียว ไม่ต้องใช้ sudo)
Module host — read-only hardening checks of this Linux machine (no sudo needed)

ข้อที่ต้องใช้ root (เช่น ดูกฎ firewall จริง) จะบอกคำสั่งให้ไปรันเองใน Terminal
Checks that need root (e.g. real firewall rules) print the command for you to run yourself.
"""
import base64
import glob
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from pathlib import Path

from core.finding import Result, T
from i18n import _

RISKY_LISTEN = {21: "FTP", 23: "Telnet", 139: "NetBIOS", 445: "SMB", 2375: "Docker API", 3306: "MySQL",
                5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
                11211: "memcached", 27017: "MongoDB"}


def sh(*cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def listeners():
    """[(addr, port, process)] ของ socket TCP ที่รอรับการเชื่อมต่อ"""
    rc, out = sh("ss", "-H", "-tlnp")
    rows = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        addr, _sep, port = p[3].rpartition(":")
        proc = re.search(r'\(\("([^"]+)"', line)
        rows.append((addr.strip("[]"), int(port) if port.isdigit() else 0, proc.group(1) if proc else ""))
    return rows


def is_public(addr):
    return not (addr.startswith("127.") or addr in ("::1", "localhost") or addr.startswith("%lo"))


def check_listen(res):
    rows = listeners()
    exposed = [(a, p, n) for a, p, n in rows if is_public(a)]
    res.table("พอร์ตที่เครื่องนี้เปิดรอรับ", ["ที่อยู่", "พอร์ต", "โปรแกรม", "ใครต่อได้"],
              [[a, str(p), n or "?", "ทุกคนในเครือข่าย" if is_public(a) else "เฉพาะเครื่องนี้"]
               for a, p, n in sorted(set(rows), key=lambda x: x[1])])
    risky = [(a, p, n) for a, p, n in exposed if p in RISKY_LISTEN]
    for a, p, n in risky:
        res.add("host.listen_risky", f"{a}:{p}", f"{RISKY_LISTEN[p]} {n}")
    other = [(a, p, n) for a, p, n in exposed if p not in RISKY_LISTEN]
    if other:
        res.add("host.listen_exposed", "0.0.0.0",
                ", ".join(sorted({f"{p}" + (f" ({n})" if n else "") for a, p, n in other})))
    if not exposed:
        res.ok("ไม่มีบริการเปิดรับจากเครือข่าย (ฟังเฉพาะ localhost)", "ss -tln")
    return exposed


def check_firewall(res, exposed):
    conf = read("/etc/ufw/ufw.conf")
    if conf is None:
        res.add("host.firewall_off", "ufw", T("ไม่ได้ติดตั้ง ufw"), "high" if exposed else "medium")
    elif re.search(r"(?m)^ENABLED=yes", conf):
        res.ok("เปิด firewall (ufw) อยู่", "/etc/ufw/ufw.conf", "ENABLED=yes")
        res.note("ดูกฎ firewall จริงต้องใช้ root — รันเองใน Terminal:", "sudo ufw status verbose")
    else:
        res.add("host.firewall_off", "/etc/ufw/ufw.conf", "ENABLED=no", "high" if exposed else "medium")


def sshd_options():
    """อ่าน sshd_config + Include ตามลำดับ — ค่าที่เจอครั้งแรกชนะ (เหมือน sshd จริง)"""
    opts = {}

    def parse(path):
        text = read(path)
        if text is None:
            return
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.lower().startswith("match "):
                break       # ค่าใน Match ใช้เฉพาะบางกรณี / Match blocks are conditional
            key, _sep, val = line.partition(" ")
            if key.lower() == "include":
                for pattern in val.split():
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    for f in sorted(glob.glob(pattern)):
                        parse(f)
            else:
                opts.setdefault(key.lower(), val.strip())

    parse("/etc/ssh/sshd_config")
    return opts


def check_ssh(res, rows):
    if not (shutil.which("sshd") or os.path.exists("/usr/sbin/sshd")):
        res.ok("ไม่ได้ติดตั้ง SSH server (ไม่มีช่องให้ล็อกอินจากระยะไกล)", "sshd")
        return
    o = sshd_options()
    running = any(p == int(o.get("port", "22").split()[0] or 22) for _a, p, _n in rows)
    t = "/etc/ssh/sshd_config"
    prl = o.get("permitrootlogin", "prohibit-password").lower()
    if prl == "yes":
        res.add("host.ssh_root_login", t, f"PermitRootLogin {prl}")
    else:
        res.ok("SSH ไม่ยอมให้ root ล็อกอินด้วยรหัสผ่าน", t, f"PermitRootLogin {prl}")
    pa = o.get("passwordauthentication", "yes").lower()
    if pa == "yes":
        res.add("host.ssh_password", t, f"PasswordAuthentication {pa}" + ("" if running else " (sshd not listening)"),
                "medium" if running else "low")
    else:
        res.ok("SSH ใช้กุญแจ (key) แทนรหัสผ่าน", t, f"PasswordAuthentication {pa}")
    if o.get("permitemptypasswords", "no").lower() == "yes":
        res.add("host.ssh_empty_password", t, "PermitEmptyPasswords yes")


def check_updates(res):
    rc, out = sh("apt", "list", "--upgradable", timeout=60)
    if rc < 0:
        return
    pkgs = [l for l in out.splitlines() if "/" in l and "upgradable" in l]
    sec = [l.split("/")[0] for l in pkgs if "-security" in l]
    if sec:
        res.add("host.updates_security", "apt", T("{n} แพ็กเกจความปลอดภัย: {p}", n=len(sec), p=", ".join(sec[:10])))
    elif pkgs:
        res.add("host.updates_pending", "apt", T("{n} แพ็กเกจรออัปเดต", n=len(pkgs)))
    else:
        res.ok("แพ็กเกจเป็นเวอร์ชันล่าสุด (ตามข้อมูล apt ล่าสุด)", "apt")
    res.note("ข้อมูลอัปเดตมาจากรายการ apt ครั้งล่าสุด — รีเฟรชได้ด้วย:", "sudo apt update")
    auto = read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
    if re.search(r'Unattended-Upgrade\s+"1"', auto):
        res.ok("เปิดอัปเดตความปลอดภัยอัตโนมัติ (unattended-upgrades)", "/etc/apt/apt.conf.d/20auto-upgrades")
    else:
        res.add("host.no_auto_updates", "/etc/apt/apt.conf.d/20auto-upgrades")
    if os.path.exists("/var/run/reboot-required"):
        pk = (read("/var/run/reboot-required.pkgs") or "").split()
        res.add("host.reboot_required", "/var/run/reboot-required", ", ".join(pk[:8]))


def check_files(res):
    for path in ("/etc/shadow", "/etc/gshadow"):
        try:
            m = os.stat(path).st_mode
        except OSError:
            continue
        if m & stat.S_IROTH:
            res.add("host.shadow_readable", path, oct(m & 0o777))
        else:
            res.ok("ไฟล์รหัสผ่าน (hash) อ่านไม่ได้จากผู้ใช้ทั่วไป", path, oct(m & 0o777))
    home = Path.home()
    m = home.stat().st_mode
    if m & (stat.S_IROTH | stat.S_IXOTH):
        res.add("host.home_open", str(home), oct(m & 0o777))
    else:
        res.ok("โฟลเดอร์ home ผู้อื่นเปิดดูไม่ได้", str(home), oct(m & 0o777))
    ssh = home / ".ssh"
    if ssh.is_dir():
        if ssh.stat().st_mode & 0o077:
            res.add("host.ssh_dir_perms", str(ssh), oct(ssh.stat().st_mode & 0o777))
        for key in sorted(ssh.glob("id_*")):
            if key.suffix == ".pub" or not key.is_file():
                continue
            km = key.stat().st_mode
            if km & 0o077:
                res.add("host.ssh_key_perms", str(key), oct(km & 0o777))
            if not key_encrypted(key):
                res.add("host.ssh_key_no_passphrase", str(key), T("ไม่ได้ตั้ง passphrase (ไม่ได้แสดงเนื้อหากุญแจ)"))


def key_encrypted(path):
    """กุญแจ SSH มี passphrase ไหม — ดูเฉพาะชื่อ cipher ในหัวไฟล์ ไม่ได้อ่าน/ส่งออกกุญแจ"""
    text = read(path) or ""
    if "ENCRYPTED" in text:
        return True
    m = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END", text, re.S)
    if not m:
        return True     # ไม่รู้จักรูปแบบ — ไม่เตือน / unknown format, do not warn
    try:
        raw = base64.b64decode("".join(m.group(1).split())[:200] + "==")
        n = int.from_bytes(raw[15:19], "big")
        return raw[19:19 + n] != b"none"
    except (ValueError, IndexError):
        return True


def check_kernel(res):
    aslr = (read("/proc/sys/kernel/randomize_va_space") or "").strip()
    if aslr and aslr != "2":
        res.add("host.aslr_off", "/proc/sys/kernel/randomize_va_space", aslr)
    elif aslr:
        res.ok("ASLR เปิดเต็ม (สุ่มตำแหน่งหน่วยความจำ)", "kernel.randomize_va_space", "2")


def check_desktop(res):
    rc, out = sh("lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT")
    try:
        devs = json.loads(out).get("blockdevices", [])
    except ValueError:
        devs = []

    def walk(ds):
        for d in ds:
            yield d
            yield from walk(d.get("children") or [])

    if any(d.get("type") == "crypt" for d in walk(devs)):
        res.ok("ดิสก์เข้ารหัส (LUKS)", "lsblk")
    elif devs:
        res.add("host.no_disk_encryption", "lsblk")
    gdm = read("/etc/gdm3/custom.conf") or ""
    if re.search(r"(?mi)^\s*AutomaticLoginEnable\s*=\s*true", gdm):
        res.add("host.autologin", "/etc/gdm3/custom.conf", "AutomaticLoginEnable=true")
    if shutil.which("gsettings"):
        _rc, lock = sh("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled")
        _rc, idle = sh("gsettings", "get", "org.gnome.desktop.session", "idle-delay")
        idle_s = int(re.sub(r"\D", "", idle) or 0)
        if lock.strip() == "false" or idle_s == 0:
            res.add("host.no_screen_lock", "gsettings", f"lock-enabled={lock.strip()} idle-delay={idle_s}s")
        elif lock.strip() == "true":
            res.ok("ล็อกหน้าจออัตโนมัติ", "gsettings", T("หลังว่าง {s} วินาที", s=idle_s))
    smb = read("/etc/samba/smb.conf")
    if smb and re.search(r"(?mi)^\s*guest ok\s*=\s*yes", smb):
        res.add("host.samba_guest", "/etc/samba/smb.conf", "guest ok = yes")


def run(target, opts):
    res = Result("host", socket.gethostname())
    exposed = check_listen(res)
    rows = listeners()
    check_firewall(res, exposed)
    check_ssh(res, rows)
    check_updates(res)
    check_files(res)
    check_kernel(res)
    check_desktop(res)
    res.note("ตรวจเพิ่มแบบละเอียด (ต้องใช้ root) ด้วย Lynis:", "sudo apt install lynis && sudo lynis audit system")
    return res.done()
