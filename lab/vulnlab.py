#!/usr/bin/env python3
"""
สนามฝึก (lab) — เซิร์ฟเวอร์ที่ "ตั้งใจให้มีช่องโหว่" สำหรับฝึกบนเครื่องตัวเองเท่านั้น
Practice lab — deliberately vulnerable services, bound to loopback only

  python3 lab/vulnlab.py            เปิดสนามฝึก / start the lab (Ctrl+C to stop)

  เว็บแบบมีช่องโหว่  / weak web      http://127.0.0.2:8808
  เว็บแบบแก้แล้ว     / hardened web  http://127.0.0.3:8808
  บริการเสี่ยงบน 127.0.0.2: Telnet 2323, Redis 6379 (no auth), VNC 5900 (no auth), memcached 11211,
  Docker API 2375, Elasticsearch 9200 — ทั้งหมดเป็นของปลอม ตอบแค่พอให้ตัวตรวจเจอ ไม่มีข้อมูลจริง
  All fake: they answer just enough for the checker to recognise them; no real data, no real shell.

แล้วลองตรวจ / then try:
  ./seccheck.py web http://127.0.0.2:8808      vs   ./seccheck.py web http://127.0.0.3:8808
  ./seccheck.py lan 127.0.0.2

ฟังเฉพาะ 127.0.0.x — เครื่องอื่นในเครือข่ายเข้าไม่ได้ / loopback only — unreachable from the network.
"""
import json
import os
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEAK, SAFE = "127.0.0.2", "127.0.0.3"

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto">
<h1>{title}</h1><p>{desc}</p><p>sec-check practice lab · loopback only</p>
<form action="/login" method="post"><input name="u" placeholder="user"> <input name="p" type="password"
placeholder="password"> <button>Login</button></form></body></html>"""

WEAK_FILES = {
    "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
    "/.git/config": ("text/plain", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
    "/.env": ("text/plain", "APP_NAME=LabShop\nAPP_KEY=base64:LAB-FAKE-KEY-NOT-REAL\n"
                            "DB_HOST=127.0.0.1\nDB_PASSWORD=lab-fake-password\nPAYMENT_SECRET=lab-fake-payment-secret\n"),
    "/backup.sql": ("application/sql", "-- MySQL dump 10.13\nCREATE TABLE users (id int, email varchar(99));\n"
                                       "INSERT INTO users VALUES (1,'demo@example.invalid');\n"),
    "/phpinfo.php": ("text/html", "<html><head><title>phpinfo()</title></head><body>PHP Version 7.2.24</body></html>"),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /cart/\n"),
    "/uploads/": ("text/html", "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>"
                               "<a href='invoice-0001.pdf'>invoice-0001.pdf</a></body></html>"),
}
TRACEBACK = ("<h1>Server Error</h1><pre>Traceback (most recent call last):\n  File \"/srv/shop/app.py\", line 42, "
             "in handler\n    row = db.query(sql)\nsqlite3.OperationalError: no such table: products</pre>")

SAFE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Weak(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29 (Ubuntu)"
    sys_version = ""

    def log_message(self, *a):
        pass

    def send(self, code, ctype, body, extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.2.24")
        origin = self.headers.get("Origin")
        if origin:                                  # ❌ สะท้อน Origin ทุกเว็บ / reflects any origin
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.send(200, "text/html", PAGE.format(title="Lab Shop (intentionally vulnerable)",
                                                   desc="Every weakness here is on purpose."),
                      {"Set-Cookie": "PHPSESSID=lab0123456789; path=/"})
        elif path in WEAK_FILES:
            self.send(200, *WEAK_FILES[path])
        else:
            self.send(404, "text/html", TRACEBACK)

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send(200, "text/plain", "", {"Allow": "GET, POST, OPTIONS, TRACE, PUT"})


class Safe(BaseHTTPRequestHandler):
    server_version = "web"
    sys_version = ""

    def log_message(self, *a):
        pass

    def send(self, code, ctype, body, extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in {**SAFE_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.send(200, "text/html; charset=utf-8", PAGE.format(title="Lab Shop (hardened)",
                                                                  desc="Same shop, weaknesses fixed."),
                      {"Set-Cookie": "session=lab0123456789; Path=/; HttpOnly; Secure; SameSite=Lax"})
        elif path == "/.well-known/security.txt":
            self.send(200, "text/plain", "Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n")
        elif path == "/robots.txt":
            self.send(200, "text/plain", "User-agent: *\nAllow: /\n")
        else:
            self.send(404, "text/html", "<h1>Not found</h1>")

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send(204, "text/plain", "", {"Allow": "GET, HEAD, POST"})


# --- fake TCP services ---------------------------------------------------------------------------
class Telnet(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"\r\nLab-Router v1.0\r\nlogin: ")


class Redis(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(256)
        self.request.sendall(b"+PONG\r\n" if data.upper().startswith(b"PING") else b"-ERR lab: PING only\r\n")


class Memcached(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(256)
        self.request.sendall(b"VERSION 1.4.15\r\n" if data.startswith(b"version") else b"ERROR\r\n")


class Vnc(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"RFB 003.008\n")
        self.request.recv(12)
        self.request.sendall(bytes([1, 1]))       # 1 security type: None  ❌


class JsonAPI(BaseHTTPRequestHandler):
    payload = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps(self.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BasicAuth(BaseHTTPRequestHandler):
    """อุปกรณ์ที่ยังใช้รหัส default admin/admin ผ่าน HTTP Basic / fake device with default creds"""
    server_version = "HTTPD"
    sys_version = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        import base64 as _b64
        want = "Basic " + _b64.b64encode(b"admin:admin").decode()
        if self.headers.get("Authorization") == want:
            body = b"<html><title>Router Admin</title><body>Welcome admin</body></html>"
            self.send_response(200)
        else:
            body = b"<html><body>401</body></html>"
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="USER LOGIN"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET


class Rtsp(socketserver.BaseRequestHandler):
    """กล้องที่ตอบ OPTIONS 200 OK โดยไม่ขอ auth / camera answering with no auth challenge"""
    def handle(self):
        self.request.recv(1024)
        self.request.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
                             b"Public: DESCRIBE, SETUP, PLAY, OPTIONS\r\n\r\n")


class Docker(JsonAPI):
    payload = {"Version": "20.10.7-lab", "ApiVersion": "1.41", "Os": "linux"}


class Elastic(JsonAPI):
    payload = {"name": "lab", "cluster_name": "lab-cluster", "version": {"number": "6.8.0"}}


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(name, server_cls, addr, handler):
    try:
        srv = server_cls(addr, handler)
    except OSError as e:
        print(f"  ⏭  {name:<22} {addr[0]}:{addr[1]}  skipped ({e.strerror})")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"  ✅ {name:<22} {addr[0]}:{addr[1]}")
    return srv


def self_signed_cert():
    """สร้างใบรับรอง self-signed ชั่วคราวด้วย openssl (ไว้ทดสอบโมดูล tls) / temp self-signed cert for the tls module"""
    import shutil
    import ssl
    import subprocess
    import tempfile
    if not shutil.which("openssl"):
        return None
    d = tempfile.mkdtemp(prefix="seccheck-lab-tls-")
    pem = os.path.join(d, "cert.pem")
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", pem, "-out", pem,
                        "-days", "365", "-nodes", "-subj", "/CN=lab.local"],
                       capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)
    return ctx


def start_https(name, addr, handler, ctx):
    if ctx is None:
        print(f"  ⏭  {name:<22} {addr[0]}:{addr[1]}  skipped (no openssl)")
        return None
    try:
        srv = ThreadingHTTPServer(addr, handler)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    except OSError as e:
        print(f"  ⏭  {name:<22} {addr[0]}:{addr[1]}  skipped ({e.strerror})")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"  ✅ {name:<22} {addr[0]}:{addr[1]}")
    return srv


def main():
    sys.stdout.reconfigure(line_buffering=True)
    print("sec-check lab — loopback only / ฟังเฉพาะเครื่องนี้  (Ctrl+C to stop)")
    servers = [
        start("weak web", ThreadingHTTPServer, (WEAK, 8808), Weak),
        start("hardened web", ThreadingHTTPServer, (SAFE, 8808), Safe),
        start("telnet (fake)", TCP, (WEAK, 2323), Telnet),
        start("redis no-auth (fake)", TCP, (WEAK, 6379), Redis),
        start("vnc no-auth (fake)", TCP, (WEAK, 5900), Vnc),
        start("memcached (fake)", TCP, (WEAK, 11211), Memcached),
        start("docker api (fake)", ThreadingHTTPServer, (WEAK, 2375), Docker),
        start("elasticsearch (fake)", ThreadingHTTPServer, (WEAK, 9200), Elastic),
        start("router admin+default (fake)", ThreadingHTTPServer, (WEAK, 8081), BasicAuth),
        start("rtsp no-auth (fake)", TCP, (WEAK, 8554), Rtsp),
        start_https("https self-signed (fake)", (WEAK, 8443), Weak, self_signed_cert()),
    ]
    if not any(servers):
        sys.exit(1)
    print("\n  ./seccheck.py web http://127.0.0.2:8808\n  ./seccheck.py web http://127.0.0.3:8808\n"
          "  ./seccheck.py lan 127.0.0.2\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
