"""
โมดูล cve — จับคู่เวอร์ชันบริการที่เห็นกับช่องโหว่ที่รู้จัก (CVE) แบบออฟไลน์
Module cve — match detected service versions against known CVEs, offline

อ่าน banner ของบริการ (SSH, HTTP Server header, FTP, SMTP) แล้วเทียบกับตารางในเครื่อง (core/cvedb.py)
ไม่ได้ยิง exploit ไม่ต้องต่อเน็ต — แค่เทียบเวอร์ชัน
Reads service banners (SSH, HTTP Server header, FTP, SMTP) and compares them against a local table.
No exploits, no network needed — just a version comparison.
"""
import re

from core import cvedb, net, scope
from core.finding import Result, T
from i18n import _

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8008, 8081, 8899]


def grab_banners(host):
    """คืน [(ที่มา, banner_string)] จากบริการยอดนิยม / collect banners from common services"""
    out = []
    for port, send in ((22, None), (21, None), (25, b"EHLO sec-check\r\n")):
        if net.tcp_state(host, port, timeout=1.2) == "open":
            b = net.banner(host, port, send=send, timeout=3)
            if b:
                out.append((f"{host}:{port}", b.decode("latin-1", "replace").strip().splitlines()[0][:120]))
    for port in HTTP_PORTS:
        if net.tcp_state(host, port, timeout=1.0) != "open":
            continue
        scheme = "https" if port in (443, 8443) else "http"
        r = net.request(f"{scheme}://{host}:{port}/", method="HEAD", timeout=5, verify=False)
        srv = r.h("server") or r.h("x-powered-by")
        if srv:
            out.append((f"{scheme}://{host}:{port}/ (Server)", srv))
    return out


def run(target, opts):
    host = (target or "").split("://")[-1].split("/")[0].split(":")[0]
    if not host:
        raise SystemExit(_("ระบุ IP หรือโฮสต์ เช่น ./seccheck.py cve 192.168.1.1"))
    scope.check(host)
    res = Result("cve", host)
    banners = grab_banners(host)
    res.table("Banner ที่พบ", ["ที่มา", "banner"], [[src, b] for src, b in banners] or [["-", "-"]])

    seen = set()
    for src, banner in banners:
        product, version = cvedb.from_banner(banner)
        if not product or not version:
            continue
        for e in cvedb.match(product, version):
            key = (src, e.get("cve", ""), product)
            if key in seen:
                continue
            seen.add(key)
            label = f"{product} {version}"
            if e.get("eol"):
                res.add("cve.eol_software", src, Desc(label, "", e["th"], e["en"]), e["sev"])
            else:
                res.add("cve.known_vuln", src, Desc(label, e.get("cve", "?"), e["th"], e["en"]), e["sev"])

    if not seen:
        res.ok("ไม่พบเวอร์ชันบริการที่ตรงกับ CVE ในตาราง", host, T("{n} banner", n=len(banners)))
    res.note("เทียบจากตาราง CVE ในเครื่อง (ชุดเล็ก) — เป็นการเดาจากเวอร์ชันใน banner · บาง distro backport "
             "แพตช์ ทำให้เวอร์ชันดูเก่าแต่แก้แล้ว ควรยืนยันอีกครั้ง · ไม่ได้ยิง exploit")
    return res.done()


class Desc:
    """หลักฐาน CVE ที่เลือกภาษาไทย/อังกฤษตอนแสดงผล / CVE evidence that picks th/en at render time"""
    def __init__(self, label, cve, th, en):
        self.label, self.cve, self.th, self.en = label, cve, th, en

    def __str__(self):
        from i18n import get_lang
        desc = self.en if get_lang() == "en" else self.th
        ref = f" · https://nvd.nist.gov/vuln/detail/{self.cve.split('/')[0]}" if self.cve and self.cve != "?" else ""
        arrow = f" → {self.cve}" if self.cve else ""
        return f"{self.label}{arrow}: {desc}{ref}"
