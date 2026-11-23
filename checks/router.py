"""
โมดูล router — ตรวจเราเตอร์ / Wi-Fi ของตัวเองจากฝั่งในบ้าน / Check your own router & Wi-Fi from inside

ทำได้อัตโนมัติ: หา gateway, ดูพอร์ตที่เปิดบนเราเตอร์, หน้า admin ใช้ HTTP หรือ HTTPS,
UPnP เปิดอยู่ไหม (ถาม SSDP แบบอ่านอย่างเดียว), Wi-Fi ที่ต่ออยู่ใช้การเข้ารหัสแบบไหน, DNS ที่ใช้
ทำเองด้วยมือ (มี checklist ในรายงาน): รหัส admin, WPS, เฟิร์มแวร์, remote management, เครือข่าย guest
เราไม่ลองล็อกอินหน้า admin และไม่ลองรหัสผ่าน default ให้เด็ดขาด

Automatic: gateway, open ports on the router, admin page over HTTP vs HTTPS, UPnP (read-only SSDP
query), Wi-Fi encryption of the current network, DNS servers. A manual checklist covers what cannot be
seen from outside the router's admin page. It never tries to log in or tries default passwords.
"""
import re
import socket
import struct
import subprocess
import time
import urllib.parse

from core import net, scope
from core.finding import Result, T
from i18n import _

ROUTER_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 1900: "UPnP",
                5000: "UPnP/HTTP", 7547: "TR-069", 8080: "HTTP-alt", 8443: "HTTPS-alt", 49152: "UPnP"}
MANUAL = ["router.manual_admin_password", "router.manual_wps", "router.manual_firmware",
          "router.manual_remote_admin", "router.manual_guest_iot", "router.manual_port_forward"]


def gateway():
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            p = line.split()
            if p[1] == "00000000" and int(p[3], 16) & 2:
                return socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
    except (OSError, IndexError, ValueError):
        pass
    return None


def ssdp(timeout=2.5):
    """ส่ง M-SEARCH (ถามว่ามีใครรองรับ UPnP บ้าง) แล้วเก็บคำตอบ / ask who speaks UPnP"""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    out = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
                out.append((addr[0], data.decode("latin-1", "replace")))
            except socket.timeout:
                continue
        s.close()
    except OSError:
        pass
    return out


def wifi():
    """(ssid, security) ของ Wi-Fi ที่ต่ออยู่ / current Wi-Fi network"""
    try:
        out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,CHAN", "dev", "wifi", "list",
                              "--rescan", "no"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if parts and parts[0] == "yes":
            return parts[1].replace("\\:", ":"), (parts[2] if len(parts) > 2 else ""), \
                (parts[3] if len(parts) > 3 else "")
    return None


def dns_servers():
    try:
        out = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return " · ".join(sorted({ip for ip in re.findall(r"[\d.]{7,15}|[0-9a-f:]{6,}", out) if ip.count(".") == 3}))


def run(target, opts):
    gw = target or gateway()
    if not gw:
        raise SystemExit(_("หา gateway (เราเตอร์) ไม่เจอ — ระบุ IP เอง เช่น ./seccheck.py router 192.168.1.1"))
    scope.check(gw)
    res = Result("router", gw)
    timeout = float(getattr(opts, "timeout", 1.5) or 1.5)
    open_ports = [p for p in ROUTER_PORTS if net.tcp_state(gw, p, timeout) == "open"]
    res.table("พอร์ตที่เปิดบนเราเตอร์", ["พอร์ต", "บริการ"], [[str(p), ROUTER_PORTS[p]] for p in open_ports])
    if 23 in open_ports:
        res.add("router.telnet", f"{gw}:23", (net.banner(gw, 23, timeout=3) or b"").decode("latin-1", "replace")[:80])
    if 21 in open_ports:
        res.add("router.ftp", f"{gw}:21")
    if 7547 in open_ports:
        res.add("router.tr069", f"{gw}:7547")
    if 22 in open_ports:
        res.add("router.ssh", f"{gw}:22", (net.banner(gw, 22) or b"").decode("latin-1").strip()[:80])

    # admin page
    if 80 in open_ports or 8080 in open_ports:
        port = 80 if 80 in open_ports else 8080
        h = net.request(f"http://{gw}:{port}/", timeout=5, max_bytes=16384)
        title = re.search(rb"<title[^>]*>(.*?)</title>", h.body, re.I | re.S)
        info = (title.group(1).decode("utf-8", "replace").strip()[:80] if title else "") or h.h("server")
        to_https = h.status in (301, 302, 307, 308) and h.h("location").startswith("https://")
        if to_https:
            res.ok("หน้า admin เปลี่ยนไปใช้ HTTPS", f"http://{gw}:{port}/", h.h("location"))
        elif 443 in open_ports or 8443 in open_ports:
            res.add("router.admin_http", f"http://{gw}:{port}/", info + " · " + T("มี HTTPS แต่ไม่บังคับใช้"), "low")
        else:
            res.add("router.admin_http", f"http://{gw}:{port}/", info)
        res.note("รุ่น/หน้า admin ที่เห็น", info)

    # UPnP
    replies = [(ip, txt) for ip, txt in ssdp() if ip == gw]
    if replies:
        loc = re.search(r"(?im)^location:\s*(\S+)", replies[0][1])
        srv = re.search(r"(?im)^server:\s*(.+)$", replies[0][1])
        detail = srv.group(1).strip() if srv else ""
        if loc and urllib.parse.urlsplit(loc.group(1)).hostname == gw:
            d = net.request(loc.group(1), timeout=4, max_bytes=32768)
            fields = {k: re.search(rf"<{k}>(.*?)</{k}>", d.text, re.S) for k in
                      ("manufacturer", "modelName", "modelNumber", "friendlyName")}
            model = " ".join(m.group(1).strip() for m in fields.values() if m)
            if model:
                detail = f"{model} · {detail}"
        res.add("router.upnp", gw, detail)
    else:
        res.ok("ไม่พบ UPnP IGD ตอบจากเราเตอร์", gw, "SSDP M-SEARCH")

    # Wi-Fi
    w = wifi()
    if w is None:
        res.note("ไม่ได้ต่อ Wi-Fi (หรือไม่มี nmcli) — ข้ามการตรวจ Wi-Fi")
    else:
        ssid, sec, chan = w
        t = f"Wi-Fi '{ssid}'"
        su = sec.upper()
        if not su or su in ("--", "NONE"):
            res.add("router.wifi_open", t, T("ไม่มีการเข้ารหัส"))
        elif "WEP" in su:
            res.add("router.wifi_wep", t, sec)
        elif "WPA1" in su or su.strip() == "WPA":
            res.add("router.wifi_wpa1", t, sec)
        elif "WPA3" in su or "SAE" in su:
            res.ok("Wi-Fi ใช้ WPA3", t, sec)
        else:
            res.ok("Wi-Fi ใช้ WPA2", t, sec + " · " + T("ถ้าเราเตอร์รองรับ ลองเปิด WPA3 (หรือ WPA2/WPA3)"))
        if chan:
            res.note("ช่องสัญญาณ Wi-Fi", chan)
    dns = dns_servers()
    if dns:
        res.note("DNS ที่เครื่องนี้ใช้ (ถ้าไม่ใช่ที่ตั้งใจไว้ อาจโดนเปลี่ยน DNS)", dns)
    res.note("การตรวจนี้มองจากในบ้าน — ถ้าจะดูว่าคนนอกเห็นพอร์ตอะไร ต้องสแกนจากนอกเครือข่าย (เช่น จาก VPS ของตัวเอง)")
    res.manual = list(MANUAL)
    return res.done()
