"""
โมดูล iot — ตรวจอุปกรณ์ IoT / ทีวี / สมาร์ตโฮม ในวงของตัวเอง แบบ passive
Module iot — passive checks of your own IoT / TV / smart-home devices

ดูบริการที่เปิดและ "ทักทาย" ด้วยคำสั่งอ่านอย่างเดียว: Chromecast/Cast (eureka_info), Roku (ECP),
Telnet, MQTT — ไม่ส่งคำสั่งเล่น/หยุด ไม่เปลี่ยนการตั้งค่า ไม่เดารหัส
Looks at open services and says a read-only hello: Chromecast/Cast (eureka_info), Roku (ECP), Telnet,
MQTT — it never sends play/stop commands, never changes settings, never guesses passwords.
"""
import json as _json
import re

from core import net, scope
from core.finding import Result, T
from i18n import _

PORTS = {23: "Telnet", 2323: "Telnet", 1883: "MQTT", 8008: "Cast", 8009: "Cast(TLS)",
         8060: "Roku", 1900: "UPnP", 5353: "mDNS", 9999: "IoT"}


def cast_info(ip, res):
    """Chromecast/Google Cast: GET /setup/eureka_info (อ่านอย่างเดียว ไม่สั่งเล่น)"""
    r = net.request(f"http://{ip}:8008/setup/eureka_info?params=name,ssid", timeout=4, max_bytes=8192)
    try:
        j = _json.loads(r.body or b"{}")
    except ValueError:
        j = {}
    if r.status == 200 and ("name" in j or "ssid" in j or "cast" in r.body.lower()):
        name = j.get("name", "")
        res.add("iot.cast_open", f"{ip}:8008", T("Chromecast/Cast ตอบข้อมูลโดยไม่ต้องล็อกอิน: {n}", n=name))
        return True
    return False


def roku_info(ip, res):
    r = net.request(f"http://{ip}:8060/query/device-info", timeout=4, max_bytes=8192)
    if r.status == 200 and b"<device-info" in r.body:
        model = re.search(rb"<model-name>([^<]+)<", r.body)
        res.add("iot.media_device", f"{ip}:8060",
                "Roku" + (" " + model.group(1).decode() if model else ""))
        # Roku ECP คุมได้โดยไม่ต้องรหัสในวง / Roku ECP is controllable without auth on the LAN
        res.add("iot.cast_open", f"{ip}:8060", "Roku ECP (control without auth on the LAN)")
        return True
    return False


def run(target, opts):
    if not target:
        raise SystemExit(_("ระบุ IP ของอุปกรณ์ เช่น ./seccheck.py iot 192.168.1.50"))
    scope.check(target)
    res = Result("iot", target)
    state = {p: net.tcp_state(target, p, timeout=1.2) for p in PORTS}
    open_ports = [p for p, s in state.items() if s == "open"]
    res.table("พอร์ตที่เปิดบนอุปกรณ์", ["พอร์ต", "บริการ"], [[str(p), PORTS[p]] for p in open_ports] or [["-", "-"]])

    if state[23] == "open" or state[2323] == "open":
        port = 23 if state[23] == "open" else 2323
        b = (net.banner(target, port, timeout=3) or b"").decode("latin-1", "replace").strip()
        res.add("lan.telnet", f"{target}:{port}", b[:80])      # Mirai-style
    if state[1883] == "open":
        b = net.banner(target, 1883) or b""
        res.add("lan.mqtt", f"{target}:1883", b[:40].decode("latin-1", "replace").strip())
    if state[8008] == "open":
        if not cast_info(target, res):
            res.add("iot.media_device", f"{target}:8008", "Cast port open")
    if state[8060] == "open":
        roku_info(target, res)
    for p in (80, 8080):
        if net.tcp_state(target, p, timeout=1.0) == "open":
            r = net.request(f"http://{target}:{p}/", timeout=4, max_bytes=4096)
            title = re.search(rb"<title[^>]*>(.*?)</title>", r.body, re.I | re.S)
            res.add("lan.http_service", f"http://{target}:{p}/",
                    " · ".join(x for x in (r.h("server"),
                                           title.group(1).decode("utf-8", "replace").strip()[:50] if title else "")
                               if x) or f"HTTP {r.status}")
            if r.h("www-authenticate", "").lower().startswith("basic"):
                res.add("lan.http_basic", f"http://{target}:{p}/", r.h("www-authenticate")[:80])

    if not open_ports:
        res.note("ไม่พบพอร์ต IoT/ทีวีที่คุ้นเปิดบนเป้าหมายนี้", target)
    res.manual = ["iot.manual_segment"]
    res.note("ตรวจแบบ passive — ไม่สั่งเล่น/หยุด ไม่เปลี่ยนค่า ไม่เดารหัส")
    return res.done()
