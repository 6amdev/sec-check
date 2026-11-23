"""
โมดูล web — ตรวจเว็บไซต์ของตัวเองแบบไม่ทำลาย / Non-destructive checks for your own website

สิ่งที่ทำ: ส่ง GET/HEAD/OPTIONS แบบปกติเหมือนเบราว์เซอร์ (ประมาณ 40 request, หน่วงระหว่าง request)
แล้วดู: HTTPS/ใบรับรอง/TLS, security headers, cookie, CORS, ไฟล์ที่ไม่ควรเปิดให้โหลด, directory listing,
หน้า debug/error ที่เผยข้อมูล
สิ่งที่ไม่ทำ: ไม่ยิง SQL injection / XSS payload, ไม่ล็อกอิน, ไม่เดารหัสผ่าน, ไม่ส่งฟอร์ม, ไม่ตาม redirect
ออกนอก scope

What it does: ordinary browser-like GET/HEAD/OPTIONS requests (~40, rate-limited), then looks at HTTPS,
certificate, TLS versions, headers, cookies, CORS, files that should not be downloadable, directory listings
and verbose error pages. It never sends attack payloads, never logs in or guesses passwords, never submits
forms and never follows redirects out of scope.
"""
import re
import secrets
import ssl
import time
import urllib.parse
from datetime import datetime, timezone

from core import net, scope
from core.finding import Ev, Result, T
from i18n import _

SENSITIVE = [
    # (path, kb id, validator)  — validators look at the content so a "200 for everything" site is not a false alarm
    ("/.git/HEAD", "web.git_exposed", lambda b: b.startswith(b"ref: ") or re.fullmatch(rb"[0-9a-f]{40}\s*", b)),
    ("/.git/config", "web.git_exposed", lambda b: b"[core]" in b),
    ("/.env", "web.env_exposed", lambda b: _looks_env(b)),
    ("/.env.bak", "web.env_exposed", lambda b: _looks_env(b)),
    ("/.env.local", "web.env_exposed", lambda b: _looks_env(b)),
    ("/.svn/entries", "web.svn_exposed", lambda b: re.match(rb"\d+\s*\n", b) or b"svn" in b[:200]),
    ("/.svn/wc.db", "web.svn_exposed", lambda b: b.startswith(b"SQLite format 3")),
    ("/.DS_Store", "web.ds_store", lambda b: b[4:8] == b"Bud1"),
    ("/backup.zip", "web.backup_exposed", lambda b: b.startswith(b"PK\x03\x04")),
    ("/site.zip", "web.backup_exposed", lambda b: b.startswith(b"PK\x03\x04")),
    ("/www.zip", "web.backup_exposed", lambda b: b.startswith(b"PK\x03\x04")),
    ("/backup.tar.gz", "web.backup_exposed", lambda b: b.startswith(b"\x1f\x8b")),
    ("/backup.sql", "web.backup_exposed", lambda b: _looks_sql(b)),
    ("/db.sql", "web.backup_exposed", lambda b: _looks_sql(b)),
    ("/dump.sql", "web.backup_exposed", lambda b: _looks_sql(b)),
    ("/database.sql", "web.backup_exposed", lambda b: _looks_sql(b)),
    ("/wp-config.php.bak", "web.backup_exposed", lambda b: b"<?php" in b),
    ("/wp-config.php~", "web.backup_exposed", lambda b: b"<?php" in b),
    ("/config.php.bak", "web.backup_exposed", lambda b: b"<?php" in b),
    ("/phpinfo.php", "web.phpinfo", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/info.php", "web.phpinfo", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/server-status", "web.status_page", lambda b: b"Apache Server Status" in b),
    ("/nginx_status", "web.status_page", lambda b: b"Active connections:" in b),
    ("/phpmyadmin/", "web.admin_panel", lambda b: b"phpMyAdmin" in b),
    ("/pma/", "web.admin_panel", lambda b: b"phpMyAdmin" in b),
    ("/adminer.php", "web.admin_panel", lambda b: b"Adminer" in b),
]
LISTING_DIRS = ["/", "/uploads/", "/images/", "/files/", "/backup/", "/static/", "/assets/"]
LISTING_MARKS = [b"<title>Index of /", b"Directory listing for /", b"<h1>Index of /"]
DEBUG_MARKS = [b"Traceback (most recent call last)", b"Whoops, looks like something went wrong",
               b"<b>Fatal error</b>", b"Django tried these URL patterns", b"DEBUG = True",
               b"Exception in thread", b"at org.apache.", b"Stack trace:", b"Warning</b>:  "]
ROBOTS_WORDS = re.compile(r"admin|backup|private|secret|config|db|sql|old|test|dev|staging|internal|api",
                          re.I)
EVIL_ORIGIN = "https://evil.example"     # reserved domain (RFC 2606) — only a header value, never contacted


def _looks_env(b):
    if b.lstrip()[:1] in (b"<", b"{"):
        return False
    return len(re.findall(rb"(?m)^\s*[A-Z][A-Z0-9_]{1,60}\s*=", b)) >= 2


def _env_keys(b):
    return [k.decode() for k in re.findall(rb"(?m)^\s*([A-Z][A-Z0-9_]{1,60})\s*=", b)][:12]


def _looks_sql(b):
    return any(m in b for m in (b"CREATE TABLE", b"INSERT INTO", b"-- MySQL dump", b"PostgreSQL database dump"))


class Web:
    def __init__(self, target, opts):
        self.opts = opts
        self.delay = float(getattr(opts, "delay", 0.15) or 0)
        t = target if "://" in target else f"https://{target}"
        u = urllib.parse.urlsplit(t)
        self.host, self.scheme, self.port = u.hostname, u.scheme, u.port
        self.res = Result("web", t)
        self.verify = True
        self.requests = 0

    # --- helpers -------------------------------------------------------------------------------
    def base(self, scheme=None):
        scheme = scheme or self.scheme
        port = f":{self.port}" if self.port else ""
        return f"{scheme}://{self.host}{port}"

    def get(self, url, **kw):
        if self.requests and self.delay:
            time.sleep(self.delay)
        self.requests += 1
        kw.setdefault("verify", self.verify)
        return net.request(url, **kw)

    def follow_in_scope(self, url, **kw):
        """ตาม redirect เฉพาะที่ยังอยู่ใน scope / follow redirects only while they stay in scope"""
        chain = []
        for _hop in range(6):
            r = self.get(url, **kw)
            chain.append(r)
            loc = r.h("location")
            if r.status in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(url, loc)
                try:
                    scope.check(nxt)
                except scope.OutOfScope:
                    self.res.note("redirect ไปนอกขอบเขต — ไม่ตามไป", nxt)
                    break
                url = nxt
                continue
            break
        return chain[-1], chain

    # --- checks --------------------------------------------------------------------------------
    def run(self):
        r = self.res
        https_port = self.check_https()
        # หน้าหลักที่จะตรวจ: ใช้ HTTPS ถ้ามี (ยกเว้นผู้ใช้ระบุ http://host:พอร์ต เอง)
        if https_port and not (self.scheme == "http" and self.port):
            self.scheme, self.port = "https", (https_port if https_port != 443 else None)
        r.target = self.base()
        main, chain = self.follow_in_scope(self.base() + "/")
        if main.error:
            r.note("เชื่อมต่อเว็บไม่ได้", main.error)
            return r.done()
        final = urllib.parse.urlsplit(main.url)
        r.table("เส้นทาง redirect", ["URL", "สถานะ", "Server"],
                [[c.url, str(c.status or c.error), c.h("server")] for c in chain])
        self.check_headers(main, final.scheme == "https")
        self.check_cookies(main, final.scheme == "https")
        self.check_cors()
        self.check_methods()
        baseline = self.check_errors()
        self.check_files(baseline)
        self.check_listing()
        self.check_robots()
        r.note("จำนวน request ที่ส่ง", str(self.requests))
        return r.done()

    def check_https(self):
        """คืนพอร์ต HTTPS ที่ใช้ได้ หรือ None / return the working HTTPS port or None"""
        r, host = self.res, self.host
        port = self.port if (self.scheme == "https" and self.port) else 443
        tgt = f"{host}:{port}"
        st = net.tcp_state(host, port, timeout=3)
        if st != "open":
            r.add("web.no_https", tgt, T("พอร์ต {p} {s}", p=port, s=st))
            return None
        test = net.request(f"https://{tgt}/", method="HEAD", timeout=8)
        if test.error:
            if not test.error.startswith("cert:"):
                plain = net.request(f"https://{tgt}/", method="HEAD", timeout=8, verify=False)
                if plain.error:
                    r.add("web.no_https", tgt, test.error)
                    return None
            r.add("web.cert_invalid", tgt, test.error.replace("cert:", "").strip())
            self.verify = False
        else:
            r.ok("ใบรับรอง HTTPS ถูกต้อง เชื่อถือได้", tgt,
                 f"{test.tls.get('version', '')} {test.tls.get('cipher', '')}")
            self.check_cert_expiry(test.tls.get("cert") or {}, tgt)
        for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            acc = net.tls_accepts(host, port, ver)
            if acc:
                r.add("web.tls_old", tgt, T("เซิร์ฟเวอร์ยอมรับ {v}", v=name))
            elif acc is False:
                r.ok("ไม่รับ TLS รุ่นเก่า", tgt, name)
        # HTTP -> HTTPS
        plain_url = self.base("http") + "/" if self.scheme == "http" else f"http://{host}/"
        h = net.request(plain_url, timeout=6)
        if h.error:
            r.ok("พอร์ต 80 (HTTP) ไม่เปิด หรือไม่ตอบ", plain_url)
        elif h.status in (301, 302, 307, 308) and h.h("location").startswith("https://"):
            r.ok("HTTP เปลี่ยนเส้นทางไป HTTPS อัตโนมัติ", plain_url, f"{h.status} → {h.h('location')}")
        else:
            r.add("web.http_no_redirect", plain_url, f"HTTP {h.status}")
        return port

    def check_cert_expiry(self, cert, target):
        na = cert.get("notAfter")
        if not na:
            return
        try:
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(na), timezone.utc)
        except ValueError:
            return
        days = (exp - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []) if x).get("organizationName", "")
        detail = T("หมดอายุ {d} (อีก {n} วัน) · ออกโดย {i}", d=exp.strftime("%Y-%m-%d"), n=days, i=issuer)
        if days < 14:
            self.res.add("web.cert_expiring", target, detail, "high" if days < 3 else "medium")
        elif days < 30:
            self.res.add("web.cert_expiring", target, detail, "low")
        else:
            self.res.ok("ใบรับรองยังไม่ใกล้หมดอายุ", target, detail)

    def check_headers(self, m, is_https):
        r, t = self.res, m.url
        if is_https:
            hsts = m.h("strict-transport-security")
            if not hsts:
                r.add("web.no_hsts", t)
            else:
                age = re.search(r"max-age=(\d+)", hsts)
                if not age or int(age.group(1)) < 15552000:
                    r.add("web.hsts_short", t, hsts)
                else:
                    r.ok("มี HSTS (บังคับ HTTPS ในเบราว์เซอร์)", t, hsts)
        csp = m.h("content-security-policy")
        if not csp:
            r.add("web.no_csp", t)
        else:
            scripts = re.search(r"(?:script-src|default-src)([^;]*)", csp)
            if scripts and ("'unsafe-inline'" in scripts.group(1) or "*" in scripts.group(1).split()):
                r.add("web.csp_weak", t, csp[:300])
            else:
                r.ok("มี Content-Security-Policy", t, csp[:200])
        xfo = m.h("x-frame-options")
        if xfo or "frame-ancestors" in csp:
            r.ok("ป้องกัน clickjacking (ห้ามฝังเว็บใน iframe)", t, xfo or "CSP frame-ancestors")
        else:
            r.add("web.no_clickjack", t)
        if m.h("x-content-type-options").lower() != "nosniff":
            r.add("web.no_nosniff", t)
        else:
            r.ok("X-Content-Type-Options: nosniff", t)
        if not m.h("referrer-policy"):
            r.add("web.no_referrer_policy", t)
        else:
            r.ok("มี Referrer-Policy", t, m.h("referrer-policy"))
        if not m.h("permissions-policy"):
            r.add("web.no_permissions_policy", t)
        leaks = [f"{k}: {v}" for k, v in m.headers
                 if k.lower() in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                                  "x-generator", "x-drupal-cache", "x-runtime")
                 and (re.search(r"\d", v) or k.lower() != "server")]
        if leaks:
            r.add("web.version_leak", t, " · ".join(leaks))
        else:
            r.ok("ไม่เผยเวอร์ชันซอฟต์แวร์ใน header", t, m.h("server"))

    def check_cookies(self, m, is_https):
        cookies = m.all("set-cookie")
        if not cookies:
            return
        rows = []
        for c in cookies:
            parts = [p.strip() for p in c.split(";")]
            name = parts[0].split("=", 1)[0]
            attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
            missing = []
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if is_https and "secure" not in attrs:
                missing.append("Secure")
            if "samesite" not in attrs:
                missing.append("SameSite")
            elif str(attrs["samesite"]).lower() == "none" and "secure" not in attrs:
                missing.append("Secure (SameSite=None)")
            rows.append([name, ", ".join(missing) or "✓"])
            if missing:
                self.res.add("web.cookie_flags", f"{m.url} · {name}",
                             T("cookie '{n}' ขาด: {m}", n=name, m=", ".join(missing)))
            else:
                self.res.ok("cookie ตั้งค่าปลอดภัย", name, "HttpOnly · Secure · SameSite")
        self.res.table("Cookies", ["ชื่อ", "ขาด"], rows)

    def check_cors(self):
        m = self.get(self.base() + "/", headers={"Origin": EVIL_ORIGIN})
        acao, acac = m.h("access-control-allow-origin"), m.h("access-control-allow-credentials").lower()
        if acao == EVIL_ORIGIN:
            self.res.add("web.cors_reflect", m.url,
                         f"Access-Control-Allow-Origin: {acao} · Allow-Credentials: {acac or '-'}",
                         "high" if acac == "true" else "medium")
        elif acao == "*":
            self.res.add("web.cors_wildcard", m.url, "Access-Control-Allow-Origin: *")
        else:
            self.res.ok("CORS ไม่เปิดให้เว็บอื่นอ่านข้อมูล", m.url, acao or "-")

    def check_methods(self):
        m = self.get(self.base() + "/", method="OPTIONS")
        allow = (m.h("allow") or m.h("access-control-allow-methods")).upper()
        risky = [x for x in ("TRACE", "PUT", "DELETE", "PROPFIND") if x in allow]
        if risky:
            self.res.add("web.risky_methods", m.url, f"Allow: {allow}")

    def check_errors(self):
        path = f"/sec-check-{secrets.token_hex(4)}"
        m = self.get(self.base() + path)
        hit = next((mk for mk in DEBUG_MARKS if mk in m.body), None)
        if hit:
            self.res.add("web.debug_errors", m.url, T("หน้า error มี: {s}", s=hit.decode()))
        elif m.status == 200:
            self.res.note("เว็บตอบ 200 แม้หน้าที่ไม่มีอยู่ (soft-404) — ใช้การดูเนื้อหาแทนรหัสสถานะ", path)
        else:
            self.res.ok("หน้า error ไม่เผยรายละเอียดภายใน", m.url, f"HTTP {m.status}")
        return m

    def check_files(self, baseline):
        hits = {}
        for path, kid, valid in SENSITIVE:
            m = self.get(self.base() + path, byte_range=8192, max_bytes=8192)
            if m.status in (200, 206) and m.body and m.body[:200] != baseline.body[:200] and valid(m.body):
                ev = Ev([f"{path} → HTTP {m.status} · {len(m.body)} bytes"])
                if kid == "web.env_exposed":
                    ev += " · " + T("ตัวแปร (ซ่อนค่าไว้): {k}", k=", ".join(_env_keys(m.body)))
                elif kid == "web.git_exposed":
                    ev += " · " + m.body[:60].decode("utf-8", "replace").strip().splitlines()[0]
                hits.setdefault(kid, []).append((m.url, ev))
        for kid, items in hits.items():      # 1 การ์ดต่อปัญหา / one card per problem
            self.res.add(kid, items[0][0], Ev(sum(([ev, "\n"] for _u, ev in items), [])[:-1]))
        if not hits:
            self.res.ok("ไม่พบไฟล์ลับ/ไฟล์สำรองที่โหลดได้", self.base(), T("{n} path", n=len(SENSITIVE)))

    def check_listing(self):
        hits = []
        for d in LISTING_DIRS:
            m = self.get(self.base() + d, max_bytes=16384)
            if m.status == 200 and any(mk in m.body for mk in LISTING_MARKS):
                hits.append(d)
                self.res.add("web.dir_listing", m.url)
        if not hits:
            self.res.ok("ไม่เปิด directory listing", self.base(), ", ".join(LISTING_DIRS))

    def check_robots(self):
        m = self.get(self.base() + "/robots.txt", max_bytes=32768)
        if m.status == 200 and b"<html" not in m.body[:500].lower():
            paths = re.findall(r"(?im)^\s*disallow:\s*(\S+)", m.text)
            hint = [p for p in paths if ROBOTS_WORDS.search(p)]
            if hint:
                self.res.add("web.robots_hint", m.url, ", ".join(hint[:15]))
        s = self.get(self.base() + "/.well-known/security.txt", max_bytes=8192)
        if s.status == 200 and b"contact:" in s.body.lower():
            self.res.ok("มี security.txt (ช่องทางแจ้งช่องโหว่)", s.url)
        else:
            self.res.add("web.no_security_txt", self.base() + "/.well-known/security.txt")


def run(target, opts):
    scope.check(target if "://" in target else f"https://{target}")
    return Web(target, opts).run()
