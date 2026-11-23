"""
โมดูล webapp — ตรวจช่องโหว่เว็บแอปเบื้องต้น (SQLi/XSS/CSRF) แบบไม่ทำลาย
Module webapp — light web-app vulnerability checks (SQLi/XSS/CSRF), non-destructive

⚠️ โมดูลนี้ *ส่งค่าทดสอบ* ต่างจากโมดูลอื่น — จึงใช้กับ "เป้าฝึกบนเครื่องตัวเอง" (เช่น DVWA/Juice Shop
บน localhost) หรือเว็บของตัวเองที่อยู่ใน allow-list เท่านั้น
This module *sends test values*, unlike the others — so use it on LOCAL practice targets (DVWA/Juice
Shop on localhost) or your own sites in the allow-list only.

ทำแบบไม่ทำลาย: ใส่เครื่องหมาย ' เพื่อดู error ของ SQL (ไม่ใช้ OR 1=1/UNION/คำสั่งเขียน), ใส่เครื่องหมาย
ทดสอบที่ไม่เป็นอันตรายเพื่อดูว่า output ถูก encode ไหม, ตรวจฟอร์มว่ามี CSRF token ไหม — ทดสอบเฉพาะ
พารามิเตอร์แบบ GET, ไม่ส่งฟอร์ม POST จริง, ไม่ดึง/แก้ข้อมูล
Non-destructive: a single ' to surface a SQL error (no OR 1=1 / UNION / write statements), a harmless
marker to see whether output is encoded, and a form check for CSRF tokens — GET parameters only, never
submits a real POST form, never extracts or changes data.
"""
import re
import time
import urllib.parse

from core import net, scope
from core.finding import Result, T
from i18n import _

SQL_ERRORS = [b"sql syntax", b"mysql_fetch", b"ora-0", b"sqlstate", b"syntax error at or near",
              b"unclosed quotation mark", b"quoted string not properly terminated", b"sqlite_error",
              b"pg_query", b"you have an error in your sql", b"odbc", b"sqlexception", b"psql:"]
XSS_MARKER = 'sc6k">' + "<q9z>"           # เครื่องหมายทดสอบ ไม่เป็นอันตราย (ไม่ใช่ <script>)
XSS_RAW = "<q9z>"
COMMON_PARAMS = ["q", "search", "name", "id", "query", "s", "keyword", "page"]


def params_of(url, body):
    """พารามิเตอร์ที่จะทดสอบ: จาก query + ชื่อ input ในฟอร์ม GET บนหน้า / params from the URL + GET-form inputs"""
    found = list(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).keys())
    for form in re.findall(r"<form\b[^>]*>.*?</form>", body, re.I | re.S):
        if re.search(r'method\s*=\s*["\']?post', form, re.I):
            continue                       # ฟอร์ม POST: ไม่ยิงค่าทดสอบ (อาจมีผลข้างเคียง)
        for name in re.findall(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']?([^"\'\s>]+)', form, re.I):
            if name not in found:
                found.append(name)
    return found[:8]


def set_param(url, param, value):
    u = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qs(u.query)
    qs[param] = [value]
    return urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(qs, doseq=True)))


def check_csrf(url, body, baseline, res):
    forms = re.findall(r"<form\b[^>]*>.*?</form>", body, re.I | re.S)
    post_forms = [f for f in forms if re.search(r'method\s*=\s*["\']?post', f, re.I)]
    for f in post_forms:
        has_token = re.search(r'name\s*=\s*["\']?[^"\'>]*(csrf|token|nonce|authenticity)', f, re.I)
        if not has_token:
            action = re.search(r'action\s*=\s*["\']?([^"\'\s>]+)', f, re.I)
            res.add("webapp.no_csrf_token", url + (f" · form→{action.group(1)}" if action else ""))
            return
    if post_forms:
        res.ok("ฟอร์ม POST มี CSRF token", url)
    samesite = any("samesite" in c.lower() for c in baseline.all("set-cookie"))
    if baseline.all("set-cookie") and not samesite:
        res.note("cookie ไม่มี SameSite (เสริมการกัน CSRF ได้)", url)


def run(target, opts):
    scope.check(target if "://" in target else f"https://{target}")
    url = target if "://" in target else f"http://{target}"
    res = Result("webapp", url)
    delay = float(getattr(opts, "delay", 0.2) or 0)
    baseline = net.request(url, timeout=8, max_bytes=65536)
    if baseline.error:
        res.note("เชื่อมต่อเว็บแอปไม่ได้", baseline.error)
        return res.done()
    body = baseline.text
    params = params_of(url, body)
    if not params:
        params = COMMON_PARAMS            # ไม่มี param ให้เห็น — ลองชื่อยอดนิยม / none visible, try common names
    res.note("พารามิเตอร์ที่ทดสอบ (เฉพาะ GET)", ", ".join(params))

    sqli_hit, xss_hit = set(), set()
    for p in params:
        # SQLi error-based: ใส่ ' ตัวเดียว
        time.sleep(delay)
        r = net.request(set_param(url, p, f"sec{p}'"), timeout=8, max_bytes=65536)
        low = r.body.lower()
        if any(sig in low for sig in SQL_ERRORS) and not any(sig in baseline.body.lower() for sig in SQL_ERRORS):
            res.add("webapp.sqli_error", f"{url} · param={p}", T("ใส่ ' แล้วเจอ error ของฐานข้อมูล", ))
            sqli_hit.add(p)
        # Reflected XSS: เครื่องหมายทดสอบที่ไม่เป็นอันตราย
        time.sleep(delay)
        r = net.request(set_param(url, p, XSS_MARKER), timeout=8, max_bytes=65536)
        if XSS_RAW in r.text and XSS_RAW not in body:
            res.add("webapp.xss_reflected", f"{url} · param={p}", T("ค่าสะท้อนกลับแบบไม่ encode ({x})", x=XSS_RAW))
            xss_hit.add(p)
    if not sqli_hit:
        res.ok("ไม่พบสัญญาณ SQL error จากการใส่ '", url, ", ".join(params))
    if not xss_hit:
        res.ok("ค่าที่ทดสอบถูก encode ก่อนแสดง (ไม่พบ reflected XSS)", url, ", ".join(params))

    check_csrf(url, body, baseline, res)
    res.note("ทดสอบแบบไม่ทำลาย: ใส่ ' ดู error, ใส่เครื่องหมายทดสอบดูการ encode, ตรวจ CSRF token — "
             "ไม่ใช้ OR 1=1/UNION, ไม่ส่งฟอร์ม POST, ไม่ดึง/แก้ข้อมูล · ใช้กับเป้าฝึกหรือเว็บของตัวเองเท่านั้น")
    return res.done()
