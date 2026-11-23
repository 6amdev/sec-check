"""
เครื่องมือเครือข่ายแบบปลอดภัย / Safe, read-only network helpers

ทุกอย่างในนี้แค่ "ถาม" — เชื่อมต่อ, อ่านแบนเนอร์, ส่ง HTTP GET/HEAD/OPTIONS — ไม่มีการส่ง payload โจมตี,
ไม่เดารหัสผ่าน, ไม่เขียน/ลบข้อมูลบนเป้าหมาย
Everything here only *asks*: connect, read a banner, send GET/HEAD/OPTIONS. No attack payloads,
no password guessing, nothing is written or deleted on the target.
"""
import errno
import http.client
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field

from core import VERSION

UA = f"sec-check/{VERSION} (self-audit; +https://github.com/6amdev/sec-check)"


def tcp_state(host, port, timeout=1.0):
    """'open' / 'closed' (host ตอบว่าไม่มีบริการ = host มีอยู่จริง) / 'filtered' (ไม่ตอบ)"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            return "closed"
        return "filtered"


def banner(host, port, send=None, timeout=2.0, limit=2048):
    """เชื่อมต่อ อ่านแบนเนอร์ (ส่งข้อความสั้นๆ ที่ไม่มีผลข้างเคียงได้) / read a service banner"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            if send is None:
                try:
                    data = s.recv(limit)
                except socket.timeout:
                    pass
            else:
                s.sendall(send)
                end = time.time() + timeout
                while len(data) < limit and time.time() < end:
                    try:
                        chunk = s.recv(limit - len(data))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if data.endswith(b"\n"):
                        break
            return data
    except OSError:
        return None


@dataclass
class Resp:
    url: str
    status: int = 0
    headers: list = field(default_factory=list)   # [(name, value)] — keeps every Set-Cookie
    body: bytes = b""
    error: str = ""
    tls: dict = field(default_factory=dict)

    def h(self, name, default=""):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return default

    def all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


def unverified_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(url, method="GET", headers=None, timeout=8.0, max_bytes=65536, verify=True, byte_range=None):
    """ส่ง HTTP 1 ครั้ง ไม่ตาม redirect / one HTTP request, redirects are NOT followed"""
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if byte_range:
        hdrs["Range"] = f"bytes=0-{byte_range - 1}"
    hdrs.update(headers or {})
    r = Resp(url)
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context() if verify else unverified_ctx()
            conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        conn.request(method, path, headers=hdrs)
        resp = conn.getresponse()
        r.status, r.headers = resp.status, resp.getheaders()
        if method != "HEAD":
            r.body = resp.read(max_bytes)
        if u.scheme == "https" and conn.sock is not None:
            try:
                r.tls = {"version": conn.sock.version(), "cipher": (conn.sock.cipher() or [""])[0],
                         "cert": conn.sock.getpeercert() if verify else {}}
            except (OSError, ValueError):
                pass
        conn.close()
    except ssl.SSLCertVerificationError as e:
        r.error = f"cert: {e.verify_message or e}"
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        r.error = f"{type(e).__name__}: {e}"
    return r


def follow(url, max_hops=5, **kw):
    """ตาม redirect ไม่เกิน max_hops ครั้ง คืน (คำตอบสุดท้าย, เส้นทาง) / follow redirects, return (final, chain)"""
    chain = []
    for _ in range(max_hops + 1):
        r = request(url, **kw)
        chain.append(r)
        loc = r.h("location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
            continue
        break
    return chain[-1], chain


def tls_accepts(host, port, version, timeout=5.0):
    """เซิร์ฟเวอร์ยอมรับ TLS เวอร์ชันนี้ไหม (None = เครื่องเราเองทดสอบเวอร์ชันนี้ไม่ได้)"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.version() is not None
    except ssl.SSLError as e:
        if "NO_PROTOCOLS_AVAILABLE" in str(e) or "NO_CIPHERS_AVAILABLE" in str(e):
            return None
        return False
    except OSError:
        return False


def resolve(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""
