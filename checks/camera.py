"""
โมดูล camera — ตรวจกล้อง IP / NVR ของตัวเอง (ONVIF, RTSP, ภาพที่เปิดดูได้) แบบไม่ทำลาย
Module camera — non-destructive checks of your own IP cameras / NVRs (ONVIF, RTSP, open snapshots)

ทำแค่ร้องขอตามปกติ (GET รูป, ถาม ONVIF ด้วยคำสั่งอ่านอย่างเดียว, RTSP OPTIONS) — ไม่เปลี่ยนการตั้งค่า
ไม่บันทึกภาพ ไม่สร้างผู้ใช้ ไม่ยิง exploit
Only ordinary requests (GET a snapshot, a read-only ONVIF call, an RTSP OPTIONS). It never changes
settings, saves footage, creates users, or sends exploits.
"""
import re

from core import net, scope
from core.finding import Result, T
from i18n import _
from checks.lan import rtsp_needs_auth

HTTP_PORTS = [80, 8080, 8000, 8899, 8081, 9000]
ONVIF_PATHS = ["/onvif/device_service", "/onvif/Device", "/onvif/services"]
SNAPSHOT_PATHS = [
    "/snapshot.jpg", "/snapshot.cgi", "/cgi-bin/snapshot.cgi", "/image/jpeg.cgi", "/jpg/image.jpg",
    "/axis-cgi/jpg/image.cgi", "/onvif-http/snapshot", "/tmpfs/auto.jpg", "/cgi-bin/currentpic.cgi",
    "/img/snapshot.cgi", "/webcapture.jpg",
]
SOAP = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body><{op} xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>')


def onvif_call(base, op, timeout=5):
    return net.request(base, method="POST", data=SOAP.format(op=op), timeout=timeout, max_bytes=8192,
                       headers={"Content-Type": "application/soap+xml; charset=utf-8"})


def check_onvif(ip, port, res):
    base = f"http://{ip}:{port}"
    for path in ONVIF_PATHS:
        r = onvif_call(base + path, "GetSystemDateAndTime")
        if r.status and (b"onvif.org" in r.body.lower() or b"systemdateandtime" in r.body.lower()):
            t = f"{base}{path}"
            res.add("camera.onvif_exposed", t)
            # คำสั่งที่ควรต้องล็อกอิน — ลองแบบไม่ใส่รหัส / a call that should need auth, tried without creds
            d = onvif_call(base + path, "GetDeviceInformation")
            body = d.body.decode("utf-8", "replace")
            if d.status == 200 and re.search(r"<.*?Manufacturer>", body) and "fault" not in body.lower():
                man = re.search(r"Manufacturer>([^<]+)<", body)
                model = re.search(r"Model>([^<]+)<", body)
                res.add("camera.onvif_noauth", t,
                        T("อ่านข้อมูลอุปกรณ์ได้โดยไม่ต้องล็อกอิน: {m}", m=(man.group(1) if man else "") +
                          (" " + model.group(1) if model else "")))
            else:
                res.ok("ONVIF บังคับยืนยันตัวตนสำหรับข้อมูลอุปกรณ์", t)
            return True
    return False


def check_snapshot(ip, port, res):
    base = f"http://{ip}:{port}"
    for path in SNAPSHOT_PATHS:
        r = net.request(base + path, timeout=4, max_bytes=4096, byte_range=2048)
        if r.status in (200, 206) and (r.h("content-type").lower().startswith("image")
                                       or r.body[:3] == b"\xff\xd8\xff"):      # JPEG magic
            res.add("camera.snapshot_exposed", f"{base}{path}", r.h("content-type") or "image")
            return True
    return False


def run(target, opts):
    host = target.split("://")[-1].split(":")[0].split("/")[0] if target else None
    if not host:
        raise SystemExit(_("ระบุ IP หรือ URL ของกล้อง เช่น ./seccheck.py camera 192.168.1.30"))
    scope.check(host)
    res = Result("camera", host)
    found = False

    # RTSP (ใช้ตัวตรวจเดียวกับโมดูล lan) / RTSP via the lan module's checker
    for rp in (554, 8554):
        if net.tcp_state(host, rp, timeout=1.5) == "open":
            answered, needs, line0 = rtsp_needs_auth(host, rp)
            if answered and not needs:
                res.add("lan.rtsp_noauth", f"{host}:{rp}", line0)
            else:
                res.add("lan.rtsp", f"{host}:{rp}", line0)
            found = True

    # ONVIF + snapshot บนพอร์ต HTTP / ONVIF + snapshot over HTTP
    for port in HTTP_PORTS:
        if net.tcp_state(host, port, timeout=1.0) != "open":
            continue
        found = True
        r = net.request(f"http://{host}:{port}/", timeout=4, max_bytes=4096)
        title = re.search(rb"<title[^>]*>(.*?)</title>", r.body, re.I | re.S)
        res.note("พบหน้าเว็บบนกล้อง/อุปกรณ์", f"http://{host}:{port}/ · "
                 + (r.h("server") or "") + (" · " + title.group(1).decode("utf-8", "replace").strip()[:50]
                                            if title else ""))
        if r.h("www-authenticate", "").lower().startswith("basic"):
            res.add("lan.http_basic", f"http://{host}:{port}/", r.h("www-authenticate")[:80])
        check_onvif(host, port, res)
        check_snapshot(host, port, res)

    if not found:
        res.note("ไม่พบพอร์ตกล้องที่คุ้น (RTSP 554/8554, HTTP 80/8080/8899) บนเป้าหมายนี้", host)
    res.manual = ["camera.web_login"]
    res.note("ตรวจแบบอ่านอย่างเดียว — ไม่เปลี่ยนค่า ไม่บันทึกภาพ ไม่ยิง exploit")
    return res.done()
