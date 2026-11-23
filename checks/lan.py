"""
โมดูล lan — หาเครื่องและบริการที่เปิดอยู่ในวงแลนของตัวเอง / Find hosts and exposed services on your LAN

วิธีหาเครื่อง (ไม่ต้องใช้ root): อ่านตาราง ARP ของเครื่องเรา + ลองต่อ TCP พอร์ตยอดนิยม
ถ้าได้ "connection refused" ก็แปลว่ามีเครื่องอยู่ (เครื่องตอบว่าพอร์ตปิด) — เทคนิคเดียวกับ nmap -sT
แล้วตรวจพอร์ตยอดนิยม ~40 พอร์ตต่อเครื่อง และ "ทักทาย" บางบริการด้วยคำสั่งที่อ่านอย่างเดียว
(เช่น Redis PING, memcached version, Docker GET /version, VNC อ่านรายการวิธียืนยันตัวตน)
ไม่เดารหัสผ่าน ไม่ล็อกอิน ไม่ส่งคำสั่งที่เปลี่ยนข้อมูล

Discovery without root: the local ARP table plus TCP connects to popular ports ("connection refused"
still proves a host is there — same idea as nmap -sT). Then ~40 common ports per host, and a read-only
"hello" for a few services. No password guessing, no logins, no commands that change anything.
"""
import base64
import ipaddress
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from core import net, scope
from core.finding import Result, T
from i18n import _

DISCOVER_PORTS = [80, 443, 22, 445, 139, 53, 8080, 62078, 7000, 554]
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP",
    631: "IPP", 873: "rsync", 1433: "MSSQL", 1883: "MQTT", 2049: "NFS", 2323: "Telnet-alt",
    2375: "Docker API", 2376: "Docker TLS", 3000: "HTTP-dev", 3306: "MySQL", 3389: "RDP",
    5000: "HTTP-alt", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis", 7547: "TR-069",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8081: "HTTP-alt", 8443: "HTTPS-alt", 8554: "RTSP-alt",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9100: "JetDirect", 9200: "Elasticsearch",
    11211: "memcached", 27017: "MongoDB",
}
SIMPLE = {  # port -> kb id (เปิดอยู่ก็ควรรู้ / just being open is worth knowing)
    21: "lan.ftp", 23: "lan.telnet", 2323: "lan.telnet", 139: "lan.smb", 445: "lan.smb",
    3389: "lan.rdp", 27017: "lan.mongodb", 3306: "lan.database", 5432: "lan.database",
    1433: "lan.database", 1883: "lan.mqtt", 554: "lan.rtsp", 9100: "lan.printer_raw",
    2049: "lan.nfs", 111: "lan.nfs", 873: "lan.rsync", 7547: "lan.tr069",
}
RISKY = {"lan.telnet", "lan.redis_noauth", "lan.docker_api", "lan.vnc_noauth", "lan.vnc",
         "lan.elasticsearch", "lan.memcached", "lan.mongodb", "lan.rtsp_noauth", "lan.default_creds"}
HTTP_PORTS = [80, 8080, 8000, 8888, 3000, 5000, 9000, 8081, 8090]
# ชุดรหัส default ที่ใช้ทดสอบ (เฉพาะ HTTP Basic auth, เป็น GET อ่านอย่างเดียว ไม่เปลี่ยนค่า, ต้องเปิดด้วย --default-creds)
# well-known default credentials, tried ONLY via HTTP Basic auth (a GET — read-only), opt-in with --default-creds
DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
                 ("admin", "12345"), ("root", "root"), ("root", "admin"), ("user", "user"),
                 ("admin", "admin1234"), ("admin", "9999")]


def local_networks():
    """วงแลนของเครื่องนี้ จาก `ip -o -4 addr` / this machine's IPv4 networks"""
    nets = []
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return nets
    for line in out.splitlines():
        p = line.split()
        if len(p) > 3 and p[1] != "lo" and not p[1].startswith(("docker", "br-", "veth", "virbr")):
            nets.append((p[1], str(ipaddress.ip_interface(p[3]).network)))
    return nets


def arp_table():
    out = {}
    try:
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            p = line.split()
            if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                out[p[0]] = p[3]
    except OSError:
        pass
    return out


def alive(ip, timeout):
    for port in DISCOVER_PORTS:
        if net.tcp_state(ip, port, timeout) in ("open", "closed"):
            return True
    return False


def scan_host(ip, timeout):
    with ThreadPoolExecutor(16) as ex:
        states = dict(zip(PORTS, ex.map(lambda p: net.tcp_state(ip, p, timeout), PORTS)))
    return sorted(p for p, s in states.items() if s == "open")


def rtsp_needs_auth(ip, port, timeout=3):
    """ส่ง RTSP OPTIONS — กล้องที่ปลอดภัยจะตอบ 401 ขอ auth / does the camera challenge for auth?
    คืน (ตอบไหม, ต้อง auth ไหม, บรรทัดแรก) — ไม่ส่งรหัสผ่าน ไม่ขอสตรีม"""
    req = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
           f"User-Agent: {net.UA}\r\n\r\n").encode()
    b = net.banner(ip, port, send=req, timeout=timeout) or b""
    if not b.startswith(b"RTSP/"):
        return False, True, ""
    text = b.decode("latin-1", "replace")
    line0 = text.splitlines()[0] if text else ""
    code = line0.split()[1] if len(line0.split()) > 1 else ""
    needs = code in ("401", "403") or "www-authenticate" in text.lower()
    return True, needs, line0


def http_default_creds(base, res, t):
    """ลองรหัส default เฉพาะหน้า Basic auth (ส่ง GET พร้อม Authorization — อ่านอย่างเดียว) / Basic-auth only, GET"""
    import time as _time
    for user, pw in DEFAULT_CREDS:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        r = net.request(base, headers={"Authorization": f"Basic {token}"}, timeout=4, max_bytes=2048)
        if r.status and r.status not in (401, 403, 0):
            res.add("lan.default_creds", base, T("รหัส default ใช้ได้: {u} / {p}  (HTTP {s})",
                                                 u=user, p=pw or "(ว่าง)", s=r.status))
            return True
        _time.sleep(0.4)        # จำกัดอัตรา / rate-limit so nothing gets locked or overwhelmed
    res.ok("ลองรหัส default แล้วใช้ไม่ได้ (Basic auth)", base, T("{n} ชุด", n=len(DEFAULT_CREDS)))
    return False


# --- read-only service probes ------------------------------------------------------------------
def probe(ip, port, res, opts=None):
    t = f"{ip}:{port}"
    if port == 554:
        answered, needs, line0 = rtsp_needs_auth(ip, port)
        if answered and not needs:
            res.add("lan.rtsp_noauth", t, line0 or "RTSP OPTIONS → 200 OK, no auth challenge")
        else:
            res.add("lan.rtsp", t, line0 or PORTS.get(port, ""))
        return "RTSP"
    if port == 22:
        b = (net.banner(ip, port) or b"").decode("latin-1").strip()
        res.add("lan.ssh", t, b[:80])
        m = re.search(r"OpenSSH_(\d+)\.(\d+)", b)
        if m and (int(m.group(1)), int(m.group(2))) < (8, 0):
            res.add("lan.ssh_old", t, b[:80])
        return b[:60]
    if port in (21, 23, 2323, 873):
        b = (net.banner(ip, port, timeout=3) or b"").decode("latin-1", "replace").strip()
        res.add(SIMPLE[port], t, b[:100])
        return b[:60]
    if port == 6379:
        b = net.banner(ip, port, send=b"PING\r\n") or b""
        if b.startswith(b"+PONG"):
            res.add("lan.redis_noauth", t, "PING → +PONG")
        else:
            res.add("lan.redis", t, b[:60].decode("latin-1", "replace").strip())
        return "Redis"
    if port == 11211:
        b = net.banner(ip, port, send=b"version\r\n") or b""
        if b.startswith(b"VERSION"):
            res.add("lan.memcached", t, b.decode("latin-1").strip())
        return b[:40].decode("latin-1", "replace").strip()
    if port in (5900, 5901):
        return vnc(ip, port, res)
    if port in (2375, 9200):
        r = net.request(f"http://{ip}:{port}/" + ("version" if port == 2375 else ""), timeout=4)
        try:
            j = json.loads(r.body or b"{}")
        except ValueError:
            j = {}
        if port == 2375 and "ApiVersion" in j:
            res.add("lan.docker_api", t, f"Docker {j.get('Version', '')} · API {j.get('ApiVersion')}")
        elif port == 9200 and "cluster_name" in j:
            res.add("lan.elasticsearch", t, f"cluster {j.get('cluster_name')} · "
                                           f"{(j.get('version') or {}).get('number', '')}")
        return r.h("server")
    if port == 3306:
        b = net.banner(ip, port) or b""
        ver = re.search(rb"\n?([0-9]+\.[0-9]+\.[0-9]+[-\w.]*)", b[4:60])
        res.add("lan.database", t, "MySQL " + (ver.group(1).decode() if ver else ""))
        return "MySQL"
    if port in SIMPLE:
        res.add(SIMPLE[port], t, PORTS.get(port, ""))
        return ""
    if port in HTTP_PORTS:
        base = f"http://{ip}:{port}/"
        r = net.request(base, timeout=4, max_bytes=8192)
        title = re.search(rb"<title[^>]*>(.*?)</title>", r.body, re.I | re.S)
        titletxt = title.group(1).decode("utf-8", "replace").strip()[:60] if title else ""
        info = " · ".join(x for x in (r.h("server"), titletxt) if x)
        res.add("lan.http_service", base, info or f"HTTP {r.status}")
        auth = r.h("www-authenticate")
        if r.status == 401 and auth.lower().startswith("basic"):
            res.add("lan.http_basic", base, auth[:80])          # รหัสผ่านส่งแบบ base64 ไม่เข้ารหัส
            if getattr(opts, "default_creds", False):
                http_default_creds(base, res, t)
        elif getattr(opts, "default_creds", False) and r.status in (200, 403) and \
                re.search(r"login|password|sign in|เข้าสู่ระบบ|รหัสผ่าน", r.text, re.I):
            res.manual.append("lan.login_form")               # ฟอร์มล็อกอิน — ไม่ลองอัตโนมัติ (ดูหมายเหตุ)
        return info
    return ""


def vnc(ip, port, res):
    """อ่าน handshake ของ VNC (RFB) แค่ดูว่าต้องใช้รหัสผ่านไหม — ไม่ส่งรหัสผ่าน"""
    import socket
    t = f"{ip}:{port}"
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.settimeout(3)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return ""
            s.sendall(ver)
            data = s.recv(64)
            types = list(data[1:1 + data[0]]) if data and data[0] else []
    except OSError:
        res.add("lan.vnc", t)
        return "VNC"
    if 1 in types:
        res.add("lan.vnc_noauth", t, f"{ver.decode().strip()} · security types {types} (1 = None)")
    else:
        res.add("lan.vnc", t, f"{ver.decode().strip()} · security types {types}")
    return ver.decode().strip()


def run(target, opts):
    timeout = float(getattr(opts, "timeout", 0.8) or 0.8)
    if not target:
        nets = local_networks()
        if not nets:
            raise SystemExit(_("หาวงแลนของเครื่องนี้ไม่เจอ — ระบุเองได้ เช่น ./seccheck.py lan 192.168.1.0/24"))
        target = nets[0][1]
    netw = ipaddress.ip_network(target, strict=False)
    if not (netw.is_private or netw.is_loopback):
        raise SystemExit(_("สแกน LAN ได้เฉพาะวงเครือข่ายส่วนตัว (RFC1918: 10/8, 172.16/12, 192.168/16) หรือ loopback\n"
                           "เป้าหมายที่เป็น IP สาธารณะ ({n}) ตรวจไม่ได้ด้วยโมดูลนี้", n=netw))
    scope.check(str(netw))
    limit = int(getattr(opts, "max_hosts", 1024) or 1024)
    if netw.num_addresses > limit:
        raise SystemExit(_("วง {n} ใหญ่เกินไป ({c} address) — จำกัดที่ {l} (--max-hosts)",
                           n=netw, c=netw.num_addresses, l=limit))
    res = Result("lan", str(netw))
    hosts = [str(h) for h in (netw.hosts() if netw.num_addresses > 2 else netw)]
    arp = arp_table()
    print(_("  กำลังหาเครื่องใน {n} ({c} address)…", n=netw, c=len(hosts)), flush=True)
    with ThreadPoolExecutor(64) as ex:
        up = [ip for ip, a in zip(hosts, ex.map(lambda ip: ip in arp or alive(ip, timeout), hosts)) if a]
    print(_("  พบ {n} เครื่อง — กำลังตรวจพอร์ต…", n=len(up)), flush=True)
    rows = []
    with ThreadPoolExecutor(8) as ex:
        open_ports = dict(zip(up, ex.map(lambda ip: scan_host(ip, timeout), up)))
    for ip in sorted(up, key=ipaddress.ip_address):
        ports = open_ports[ip]
        details = []
        for p in ports:
            info = probe(ip, p, res, opts)
            details.append(f"{p}/{PORTS.get(p, '?')}" + (f" ({info})" if info else ""))
        rows.append([ip, net.rdns(ip), guess_device(ports, arp.get(ip, "")), arp.get(ip, ""),
                     "\n".join(details) or "-"])
    res.table("เครื่องที่พบ", ["IP", "ชื่อ", "น่าจะเป็น", "MAC", "พอร์ตที่เปิด"], rows)
    if not any(f.id in RISKY for f in res.findings):
        res.ok("ไม่พบบริการเสี่ยงสูงที่เปิดโล่ง", str(netw), T("{n} เครื่อง", n=len(up)))
    res.note("ตรวจเฉพาะพอร์ต TCP ยอดนิยม — เครื่องที่มี firewall บล็อกทุกพอร์ตอาจไม่ปรากฏ",
             f"{len(PORTS)} ports")
    if not getattr(opts, "default_creds", False):
        res.note("ยังไม่ได้ลองรหัส default — เพิ่ม --default-creds เพื่อทดสอบรหัสที่ตั้งมาจากโรงงาน "
                 "(เฉพาะหน้า Basic auth, อ่านอย่างเดียว, จำกัดอัตรา)")
    return res.done()


def guess_device(ports, mac):
    """เดาชนิดอุปกรณ์จากพอร์ต/บริการ / rough device guess from open ports"""
    s = set(ports)
    if 554 in s or 8554 in s:
        return "กล้อง/NVR (camera)"
    if 7547 in s or (53 in s and 80 in s):
        return "เราเตอร์ (router)"
    if 3389 in s or (445 in s and 139 in s and 5900 in s):
        return "Windows PC"
    if 9100 in s or 631 in s:
        return "เครื่องพิมพ์ (printer)"
    if 548 in s:
        return "Mac/NAS"
    if 22 in s:
        return "Linux/เซิร์ฟเวอร์"
    if 8009 in s or 8008 in s or 8443 in s:
        return "ทีวี/Chromecast"
    return ""
