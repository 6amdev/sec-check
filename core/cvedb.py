"""
ตาราง CVE แบบออฟไลน์ (ชุดเล็ก คัดเฉพาะที่รู้จักกันดี) / small offline banner→CVE table

จับคู่ชื่อ+เวอร์ชันของบริการที่เห็นจาก banner กับช่องโหว่ที่รู้จัก เพื่อบอกว่า "เวอร์ชันนี้เก่าและมี CVE"
ไม่ได้ยิง exploit — แค่เทียบเวอร์ชัน · ไม่ต้องต่อเน็ต (ตารางอยู่ในเครื่อง)
Maps a service's name+version (from its banner) to well-known CVEs to flag "outdated, known-vulnerable".
It never exploits anything — just compares versions — and needs no network (the table is local).

ข้อจำกัด: เป็นเพียงการเดาจากเวอร์ชันใน banner (อาจมี false positive ถ้าผู้ผลิต backport แพตช์)
Caveat: this is a version-string guess; distros that backport patches may make it a false positive.
"""
import re

# แต่ละรายการ: product, ช่วงเวอร์ชันที่เปราะ (lt/ge/exact), CVE, ความรุนแรง, คำอธิบายสั้น ไทย/อังกฤษ, ลิงก์
DB = [
    {"product": "openssh", "lt": (7, 7), "cve": "CVE-2018-15473", "sev": "medium",
     "th": "เดาได้ว่ามีชื่อผู้ใช้ใดในระบบ (user enumeration)", "en": "username enumeration"},
    {"product": "openssh", "lt": (7, 4), "cve": "CVE-2016-10012", "sev": "high",
     "th": "ช่องโหว่หน่วยความจำใน privilege separation", "en": "pre-auth memory flaw in privsep"},
    {"product": "apache", "lt": (2, 4, 39), "cve": "CVE-2019-0211", "sev": "high",
     "th": "ยกสิทธิ์เป็น root จาก worker ได้ในบางการตั้งค่า", "en": "local privilege escalation to root"},
    {"product": "apache", "ge": (2, 4, 49), "lt": (2, 4, 51), "cve": "CVE-2021-41773/42013", "sev": "critical",
     "th": "path traversal → อ่านไฟล์/รันคำสั่ง (RCE)", "en": "path traversal → file read / RCE"},
    {"product": "nginx", "lt": (1, 21, 0), "cve": "CVE-2021-23017", "sev": "high",
     "th": "ช่องโหว่ off-by-one ใน resolver", "en": "off-by-one in the DNS resolver"},
    {"product": "vsftpd", "exact": (2, 3, 4), "cve": "CVE-2011-2523", "sev": "critical",
     "th": "มี backdoor เปิด shell ที่พอร์ต 6200", "en": "backdoor opening a shell on port 6200"},
    {"product": "proftpd", "lt": (1, 3, 5, 1), "cve": "CVE-2015-3306", "sev": "critical",
     "th": "คำสั่ง mod_copy ให้ก็อป/รันไฟล์โดยไม่ต้องล็อกอิน", "en": "mod_copy unauth file copy → RCE"},
    {"product": "exim", "lt": (4, 92), "cve": "CVE-2019-10149", "sev": "critical",
     "th": "รันคำสั่งจากระยะไกล (RCE) ผ่านอีเมล", "en": "remote command execution via mail"},
    {"product": "samba", "ge": (3, 5, 0), "lt": (4, 6, 4), "cve": "CVE-2017-7494", "sev": "critical",
     "th": "SambaCry — อัปโหลด .so แล้วให้เซิร์ฟเวอร์รัน (RCE)", "en": "SambaCry — upload a shared lib → RCE"},
    {"product": "lighttpd", "lt": (1, 4, 51), "cve": "CVE-2019-11072", "sev": "medium",
     "th": "ช่องโหว่ buffer ใน mod_cgi", "en": "buffer flaw in mod_cgi"},
    {"product": "dropbear", "lt": (2016, 74), "cve": "CVE-2016-7406", "sev": "high",
     "th": "format string / ช่องโหว่ก่อนยืนยันตัวตน", "en": "format-string / pre-auth flaws"},
    {"product": "thttpd", "lt": (2, 30), "cve": "", "sev": "medium", "eol": True,
     "th": "เว็บเซิร์ฟเวอร์เก่ามาก (รุ่นปี ~2015) ไม่ได้อัปเดต/หมดการสนับสนุน", "en": "very old web server (~2015), unmaintained/EOL"},
    {"product": "boa", "lt": (99, 99), "cve": "", "sev": "medium", "eol": True,
     "th": "เว็บเซิร์ฟเวอร์ IoT ที่เลิกพัฒนาแล้ว (พบบ่อยในกล้อง/เราเตอร์เก่า)", "en": "abandoned IoT web server (common in old cameras/routers)"},
    {"product": "microhttpd", "lt": (0, 9, 70), "cve": "CVE-2021-3466", "sev": "high",
     "th": "ช่องโหว่ buffer overflow ใน libmicrohttpd", "en": "buffer overflow in libmicrohttpd"},
]
PRODUCT_ALIASES = {"apache": "apache", "httpd": "apache", "openssh": "openssh", "nginx": "nginx",
                   "vsftpd": "vsftpd", "proftpd": "proftpd", "exim": "exim", "samba": "samba",
                   "lighttpd": "lighttpd", "dropbear": "dropbear", "thttpd": "thttpd", "boa": "boa"}


def parse_version(s):
    nums = re.findall(r"\d+", s)
    return tuple(int(n) for n in nums[:4]) if nums else None


def _cmp(v, ref):
    v = v + (0,) * (len(ref) - len(v))
    ref = ref + (0,) * (len(v) - len(ref))
    return (v > ref) - (v < ref)


def match(product, version):
    """คืนลิสต์ CVE ที่ตรงกับ product+version / list of matching CVE entries"""
    product = (product or "").lower()
    product = PRODUCT_ALIASES.get(product, product)
    v = parse_version(version) if isinstance(version, str) else version
    if not product or not v:
        return []
    out = []
    for e in DB:
        if e["product"] != product:
            continue
        if "exact" in e and _cmp(v, e["exact"]) != 0:
            continue
        if "lt" in e and _cmp(v, e["lt"]) >= 0:
            continue
        if "ge" in e and _cmp(v, e["ge"]) < 0:
            continue
        out.append(e)
    return out


def from_banner(banner):
    """ดึง (product, version) จาก banner เช่น 'Apache/2.4.29 (Ubuntu)' หรือ 'SSH-2.0-OpenSSH_7.4p1'"""
    b = banner or ""
    m = re.search(r"OpenSSH[_/-]([0-9][0-9.p]*)", b, re.I)
    if m:
        return "openssh", m.group(1)
    m = re.search(r"dropbear[_/ -]?([0-9][0-9.]*)", b, re.I)
    if m:
        return "dropbear", m.group(1)
    m = re.search(r"([A-Za-z][A-Za-z\-]{1,20})/([0-9][0-9.]*)", b)
    if m:
        return m.group(1).lower(), m.group(2)
    return None, None
