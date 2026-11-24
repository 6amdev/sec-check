#!/usr/bin/env python3
"""
สนามเจาะ CTF ของ sec-check / sec-check CTF attack lab

เป้าหมายที่ "จงใจให้มีช่องโหว่" สำหรับฝึกเจาะด้วยเทคนิคจริง — เก็บ flag เหมือน CTF
Deliberately-vulnerable targets to practice REAL exploitation (capture flags like a CTF).

⚠️ ทั้งหมดรันบน 127.0.0.1 เท่านั้น · ใช้ฐานข้อมูล/ไฟล์/เชลล์ "ปลอม" (in-memory, แซนด์บ็อกซ์)
flag เป็นของปลอม ไม่มีความลับจริง และเจาะได้แค่ภายในสนามนี้ ไม่กระทบเครื่องจริงของคุณ
Everything binds to loopback only, uses fake in-memory DB / filesystem / shell, and fake flags.
The techniques are authentic; the blast radius is zero — you can't touch the real host.

  python3 lab/ctf.py           เปิดสนาม (http://127.0.0.1:8900)  ·  Ctrl+C เพื่อหยุด
  ./seccheck.py ctf

โจทย์ไล่จากง่าย→ยาก ตามเลเวลในหน้า Learn: recon/default-cred/exposed → SQLi/XSS/cmdi/traversal/IDOR
"""
import html
import http.cookies
import json
import re
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = html.escape
HOST, PORT = "127.0.0.1", 8900

FLAGS = {
    "c1": "SECCHECK{d3fault_admin_admin}",
    "c2": "SECCHECK{sql1_auth_bypass_OR_1_eq_1}",
    "c3": "SECCHECK{un10n_select_dumps_secrets}",
    "c4": "SECCHECK{reflect3d_xss_pops}",
    "c5": "SECCHECK{c0mmand_inj3ction_semicolon}",
    "c6": "SECCHECK{path_tr4versal_dotdot}",
    "c7": "SECCHECK{id0r_change_the_number}",
    "c8": "SECCHECK{exp0sed_dotenv_secrets}",
}
CHALLENGES = [
    ("c1", 1, "Default credentials", "เจาะ login ด้วยรหัสที่ตั้งมาจากโรงงาน",
     "ลองรหัสยอดฮิต admin/admin, admin/password ที่หน้า /c1"),
    ("c8", 1, "Exposed .env", "หาไฟล์ลับที่เผลอเปิดให้โหลด",
     "ลองเดา path ที่ไม่ควรเปิด เช่น /c8/.env /c8/.git/config"),
    ("c6", 2, "Path traversal", "อ่านไฟล์นอกโฟลเดอร์ที่ควรเข้าถึง",
     "พารามิเตอร์ ?file= ไม่กรอง ../ ลองไต่ออกไปหา flag"),
    ("c2", 2, "SQL injection — auth bypass", "ข้าม login โดยไม่รู้รหัส",
     "ช่อง user/pass ต่อเข้า SQL ตรงๆ ลอง ' OR '1'='1' -- "),
    ("c3", 4, "SQL injection — UNION extract", "ดูดข้อมูลลับจากฐานข้อมูล",
     "?id= ใส่ใน query ตรงๆ ลอง UNION SELECT เพื่อดึงตาราง secret (คอลัมน์ flag)"),
    ("c7", 4, "IDOR", "เข้าถึงข้อมูลของคนอื่นด้วยการเปลี่ยน id",
     "/c7?order=1001 คือของคุณ ลองเปลี่ยนเลขไปดูออเดอร์ของ admin"),
    ("c5", 4, "Command injection", "สั่งรันคำสั่งผ่านช่องกรอก (เชลล์จำลอง)",
     "เครื่องมือ ping ต่อ input เข้า shell ลอง ; cat flag หรือ | id"),
    ("c4", 4, "Reflected XSS", "ทำให้ input กลายเป็นสคริปต์ที่รันบนหน้า",
     "?name= สะท้อนกลับแบบไม่ encode ลองหลุดแท็กด้วย <script>…</script>"),
]

# --- แซนด์บ็อกซ์: ฐานข้อมูล/ไฟล์ปลอม / sandboxed fake DB & FS -----------------------------------
FAKE_FS = {
    "report.txt": "Quarterly sales report — nothing secret here.",
    "notes.txt": "TODO: move secrets out of the web root.",
    "/etc/ctf_flag": FLAGS["c6"],          # เป้าของ path traversal / traversal target
}
ORDERS = {
    1001: {"name": "you", "item": "USB drive", "total": "฿250"},
    1000: {"name": "admin", "item": "— internal —", "total": FLAGS["c7"]},
}


def fresh_db():
    con = sqlite3.connect(":memory:")       # in-memory, throwaway — ไม่มีข้อมูลจริง
    con.executescript("""
        CREATE TABLE users(id INTEGER, user TEXT, pass TEXT);
        INSERT INTO users VALUES (1,'alice','wonderland'),(2,'bob','builder');
        CREATE TABLE products(id INTEGER, name TEXT, price TEXT);
        INSERT INTO products VALUES (1,'Keyboard','฿900'),(2,'Mouse','฿350');
        CREATE TABLE secret(flag TEXT);
        INSERT INTO secret VALUES ('%s');
    """ % FLAGS["c3"])
    return con


def fake_shell(cmd):
    """เชลล์จำลอง — ไม่รันคำสั่งจริงบนเครื่อง แต่เข้าใจ injection แล้วคืนผลเหมือนจริง
    simulated shell: never runs real commands; recognises the injection and returns canned output"""
    out = []
    # แยกคำสั่งที่ถูก inject ด้วย ; | && ` $() / split on common injection separators
    parts = re.split(r"[;&|`\n]|\$\(", cmd)
    for seg in parts:
        seg = seg.strip().strip(")")
        first = seg.split()[0] if seg.split() else ""
        if first in ("cat", "more", "head", "type") and "flag" in seg.lower():
            out.append(FLAGS["c5"])
        elif first == "id":
            out.append("uid=0(root) gid=0(root) groups=0(root)")
        elif first in ("ls", "dir"):
            out.append("app.py  config.php  flag  index.html")
        elif first == "whoami":
            out.append("root")
        elif first == "pwd":
            out.append("/var/www/ctf")
        elif first in ("ping",) and seg:
            out.append(f"PING {seg.split()[-1]}: 64 bytes — 1 packets transmitted, 1 received")
    return "\n".join(out) or "(no output)"


# --- หน้าเว็บ / pages ---------------------------------------------------------------------------
CSS = """
*{box-sizing:border-box}body{margin:0;font-family:system-ui,"Noto Sans Thai",sans-serif;
background:radial-gradient(1000px 700px at 70% -10%,#1a1030,#0a0e18 60%);color:#e6ebf5;min-height:100vh}
.wrap{max-width:900px;margin:0 auto;padding:26px 18px 70px}
a{color:#b9a9ff}h1{margin:0}.mut{color:#8a97b1}code{background:#0e1422;border:1px solid #243049;
padding:1px 6px;border-radius:6px;font-family:ui-monospace,monospace}
.card{background:#121826;border:1px solid #243049;border-radius:14px;padding:16px 18px;margin:12px 0}
.lv{display:inline-block;font-size:12px;font-weight:700;padding:2px 9px;border-radius:99px;margin-right:8px}
.l1{background:#22c55e22;color:#4ade80}.l2{background:#f59e0b22;color:#fbbf24}.l4{background:#ef444422;color:#f87171}
.btn{display:inline-block;background:#7c5cff;color:#fff;border:0;border-radius:9px;padding:9px 15px;
font:600 14px inherit;text-decoration:none;cursor:pointer}.btn.g{background:transparent;border:1px solid #7c5cff;color:#b9a9ff}
input,textarea{font:inherit;background:#0e1422;border:1px solid #243049;color:#e6ebf5;border-radius:8px;padding:8px 10px}
.flag{background:#0c1322;border:1px dashed #7c5cff;border-radius:10px;padding:10px 12px;font-family:ui-monospace,monospace;color:#9ff5c8}
.solved{color:#4ade80;font-weight:700}.warn{background:#f59e0b18;border:1px solid #f59e0b55;border-radius:10px;padding:10px 14px;font-size:13.5px}
details summary{cursor:pointer;color:#8a97b1;margin:8px 0}
pre{background:#0c1322;border:1px solid #243049;border-radius:10px;padding:12px;overflow:auto;white-space:pre-wrap}
"""


def page(title, body, solved=None):
    bar = ""
    if solved is not None:
        bar = f'<p class="mut">เก็บ flag แล้ว <b class="solved">{len(solved)}/{len(FLAGS)}</b></p>'
    return f"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>sec-check CTF · {E(title)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<p class="mut"><a href="/">⬅ สนามเจาะ CTF</a></p>{bar}{body}</div></body></html>"""


def landing(solved):
    rows = ""
    for cid, lv, name, desc, hint in CHALLENGES:
        done = '<span class="solved">✔ เก็บแล้ว</span>' if cid in solved else ""
        rows += f"""<div class="card"><span class="lv l{lv}">LEVEL {lv}</span>
<b>{E(name)}</b> {done}<br><span class="mut">{E(desc)}</span><br>
<a class="btn g" href="/{cid}" style="margin-top:10px">เปิดโจทย์ →</a>
<details><summary>คำใบ้</summary><span class="mut">{E(hint)}</span></details></div>"""
    body = f"""<h1>🚩 sec-check CTF — สนามเจาะ</h1>
<p class="mut">เจาะเป้าหมายที่จงใจให้มีช่องโหว่ด้วยเทคนิคจริง แล้วเก็บ flag รูปแบบ <code>SECCHECK{{...}}</code></p>
<div class="warn">⚠️ ทุกอย่างรันบน localhost · ฐานข้อมูล/ไฟล์/เชลล์เป็นของปลอมในแซนด์บ็อกซ์ · เจาะได้แค่ในสนามนี้
ฝึกเทคนิคเดียวกับของจริง แต่ไม่กระทบเครื่องคุณ · เอาไปใช้กับระบบคนอื่นไม่ได้และผิดกฎหมาย</div>
{rows}
<div class="card"><b>ส่ง flag</b>
<form method="post" action="/submit"><input name="flag" placeholder="SECCHECK{{...}}" style="width:320px;max-width:100%">
<button class="btn">ส่ง</button></form>
<p class="mut" style="font-size:12.5px">เก็บครบทั้ง {len(FLAGS)} ข้อไหม? · อ่านเฉลยทีละขั้นได้ที่ docs/CTF.md</p></div>"""
    return page("สนามเจาะ", body, solved)


def handler_class():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def solved(self):
            ck = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return set(ck["solved"].value.split(",")) if "solved" in ck and ck["solved"].value else set()

        def send(self, body, code=200, ctype="text/html; charset=utf-8", cookie=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

        def q(self):
            return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            s = self.solved()
            if path == "/":
                return self.send(landing(s))
            if path == "/c1":
                return self.send(self.c1())
            if path == "/c2":
                return self.send(self.c2())
            if path == "/c3":
                return self.send(self.c3())
            if path == "/c4":
                return self.send(self.c4())
            if path == "/c5":
                return self.send(self.c5())
            if path == "/c6":
                return self.send(self.c6())
            if path == "/c7":
                return self.send(self.c7())
            if path == "/c8" or path == "/c8/":
                return self.send(self.c8_index())
            if path.startswith("/c8/"):
                return self.send(self.c8_file(path[4:]))
            self.send(page("404", "<div class='card'>ไม่พบหน้านี้</div>"), 404)

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            if path in ("/c1", "/c2"):
                return self.send(getattr(self, path[1:] + "_post")(form))
            if path == "/submit":
                flag = form.get("flag", [""])[0].strip()
                s = self.solved()
                cid = next((k for k, v in FLAGS.items() if v == flag), None)
                if cid:
                    s.add(cid)
                    cookie = f"solved={','.join(sorted(s))}; Path=/; Max-Age=86400"
                    body = (f"<div class='card'><h2 class='solved'>✔ ถูกต้อง!</h2>"
                            f"<p>flag นี้คือข้อ <b>{E(cid)}</b> · เก็บแล้ว {len(s)}/{len(FLAGS)}</p>"
                            f"<a class='btn' href='/'>กลับไปทำข้อต่อไป</a></div>")
                    return self.send(page("ถูกต้อง", body, s), cookie=cookie)
                return self.send(page("ผิด", "<div class='card'>flag ไม่ถูก ลองใหม่ 🙂 <a href='/'>กลับ</a></div>", s))
            self.send("404", 404)

        # ---- โจทย์ / challenges --------------------------------------------------------------
        def c1(self, msg=""):
            return page("C1 default creds", f"""<div class="card"><h2>🔐 Admin Login</h2>
<p class="mut">ระบบหลังบ้าน — ต้องเป็น admin เท่านั้น</p>{msg}
<form method="post" action="/c1"><p><input name="u" placeholder="username"></p>
<p><input name="p" type="password" placeholder="password"></p><button class="btn">เข้าสู่ระบบ</button></form></div>""")

        def c1_post(self, form):
            u, p = form.get("u", [""])[0], form.get("p", [""])[0]
            if u == "admin" and p in ("admin", "password", "1234"):
                return page("C1 solved", f"<div class='card'><h2 class='solved'>เข้าได้!</h2>"
                            f"<p>รหัส default ใช้ได้จริง flag:</p><div class='flag'>{E(FLAGS['c1'])}</div>"
                            f"<p class='mut'>เอา flag ไปส่งที่หน้าแรก</p></div>")
            return self.c1("<div class='warn'>ล็อกอินไม่ผ่าน</div>")

        def c2(self, msg=""):
            return page("C2 SQLi auth bypass", f"""<div class="card"><h2>🏬 Shop Admin</h2>
<p class="mut">query ที่ใช้: <code>SELECT * FROM users WHERE user='$u' AND pass='$p'</code></p>{msg}
<form method="post" action="/c2"><p><input name="u" placeholder="username"></p>
<p><input name="p" placeholder="password"></p><button class="btn">Login</button></form></div>""")

        def c2_post(self, form):
            u, p = form.get("u", [""])[0], form.get("p", [""])[0]
            con = fresh_db()
            try:
                # ❌ จงใจต่อสตริงตรงๆ = SQLi จริง (ฐานข้อมูลในหน่วยความจำ) / real SQLi on a throwaway DB
                query = "SELECT user FROM users WHERE user='%s' AND pass='%s'" % (u, p)
                try:
                    rows = con.execute(query).fetchall()
                except sqlite3.Error as e:
                    return self.c2(f"<pre>SQL error: {E(str(e))}</pre>")
            finally:
                con.close()
            if rows:
                return page("C2 solved", f"<div class='card'><h2 class='solved'>ข้าม login สำเร็จ!</h2>"
                            f"<p>query กลายเป็นจริงเสมอด้วย injection · ล็อกอินเป็น <b>{E(rows[0][0])}</b></p>"
                            f"<div class='flag'>{E(FLAGS['c2'])}</div></div>")
            return self.c2("<div class='warn'>ล็อกอินไม่ผ่าน — ลองคิดแบบ SQL</div>")

        def c3(self):
            idv = self.q().get("id", ["1"])[0]
            con = fresh_db()
            try:
                query = "SELECT name, price FROM products WHERE id='%s'" % idv   # ❌ SQLi
                try:
                    rows = con.execute(query).fetchall()
                    err = ""
                except sqlite3.Error as e:
                    rows, err = [], f"<pre>SQL error: {E(str(e))}</pre>"
            finally:
                con.close()
            table = "".join(f"<tr><td>{E(str(a))}</td><td>{E(str(b))}</td></tr>" for a, b in rows)
            got = FLAGS["c3"] in (r[0] for r in rows) or any(FLAGS["c3"] in str(r) for r in rows)
            note = (f"<div class='card'><h2 class='solved'>ดูดข้อมูลลับได้!</h2><div class='flag'>{E(FLAGS['c3'])}</div></div>"
                    if got else "")
            return page("C3 UNION", f"""<div class="card"><h2>🛒 ค้นหาสินค้า</h2>
<p class="mut">query: <code>SELECT name, price FROM products WHERE id='$id'</code> · ตาราง <code>secret(flag)</code> ซ่อนอยู่</p>
<form method="get" action="/c3"><input name="id" value="{E(idv)}" style="width:420px;max-width:100%"> <button class="btn">ค้นหา</button></form>
{err}<table style="margin-top:10px"><tr><th>name</th><th>price</th></tr>{table}</table></div>{note}""")

        def c4(self):
            name = self.q().get("name", [""])[0]
            # ❌ สะท้อนดิบ ไม่ encode = reflected XSS จริง / raw reflection
            got = bool(re.search(r"<script\b", name, re.I))
            note = (f"<div class='card'><h2 class='solved'>สคริปต์หลุด!</h2>"
                    f"<p>input ของคุณกลายเป็น &lt;script&gt; บนหน้า — นั่นคือ XSS</p>"
                    f"<div class='flag'>{E(FLAGS['c4'])}</div></div>" if got else "")
            return page("C4 XSS", f"""<div class="card"><h2>👋 ทักทาย</h2>
<p class="mut">?name= จะถูกเอาไปแสดงดิบๆ</p>
<form method="get"><input name="name" value="{E(name)}" style="width:420px;max-width:100%"> <button class="btn">ทัก</button></form>
<h3>สวัสดี {name}</h3></div>{note}""")

        def c5(self):
            hostv = self.q().get("host", [""])[0]
            out = ""
            if hostv:
                res = fake_shell("ping -c1 " + hostv)      # ❌ ต่อ input เข้า shell (จำลอง)
                out = f"<pre>$ ping -c1 {E(hostv)}\n{E(res)}</pre>"
            return page("C5 cmdi", f"""<div class="card"><h2>📡 เครื่องมือ Ping</h2>
<p class="mut">รันคำสั่ง: <code>ping -c1 $host</code> (เชลล์จำลอง — ไม่รันจริงบนเครื่อง)</p>
<form method="get"><input name="host" value="{E(hostv)}" placeholder="8.8.8.8" style="width:320px"> <button class="btn">Ping</button></form>
{out}</div>""")

        def c6(self):
            f = self.q().get("file", ["report.txt"])[0]
            # ❌ ไม่กรอง ../ — path traversal จริงบน FS ปลอม / traversal on a fake FS
            norm, content = f, FAKE_FS.get(f)
            if content is None and ".." in f:
                # แปลง ../ ให้เป็น path ที่ชี้ถึงจริง แล้วหาใน FAKE_FS / resolve the traversal target
                target = "/" + f.replace("..", "").replace("//", "/").lstrip("/")
                for key in FAKE_FS:
                    if key == target or (key.startswith("/") and f.rstrip("/").endswith(key.split("/")[-1])):
                        content, norm = FAKE_FS[key], key
                        break
            got = content == FLAGS["c6"]
            body = f"<pre>{E(content) if content else '(ไม่พบไฟล์ — ลองไต่ ../ ออกไป)'}</pre>"
            note = f"<div class='card'><h2 class='solved'>อ่านไฟล์ลับได้! ({E(norm)})</h2></div>" if got else ""
            return page("C6 traversal", f"""<div class="card"><h2>📄 ดูเอกสาร</h2>
<p class="mut">?file= อ่านจากโฟลเดอร์เอกสาร · มีไฟล์ flag ซ่อนที่ <code>/etc/ctf_flag</code></p>
<form method="get"><input name="file" value="{E(f)}" style="width:420px;max-width:100%"> <button class="btn">เปิด</button></form>
{body}</div>{note}""")

        def c7(self):
            oid = self.q().get("order", ["1001"])[0]
            try:
                o = ORDERS.get(int(oid))
            except ValueError:
                o = None
            got = o and o["total"] == FLAGS["c7"]
            body = (f"<pre>order #{E(oid)}\nname : {E(o['name'])}\nitem : {E(o['item'])}\ntotal: {E(o['total'])}</pre>"
                    if o else "<pre>order not found</pre>")
            note = "<div class='card'><h2 class='solved'>เข้าถึงออเดอร์ของ admin ได้!</h2></div>" if got else ""
            return page("C7 IDOR", f"""<div class="card"><h2>🧾 ใบเสร็จของฉัน</h2>
<p class="mut">ออเดอร์ของคุณคือ #1001 · ลองเปลี่ยนเลขดู</p>
<form method="get"><input name="order" value="{E(oid)}" style="width:160px"> <button class="btn">ดู</button></form>
{body}</div>{note}""")

        def c8_index(self):
            return page("C8 exposed files", """<div class="card"><h2>🌐 เว็บร้าน (Lab)</h2>
<p class="mut">หน้าเว็บปกติ — แต่เผลอวางไฟล์บางอย่างไว้ใน web root</p>
<p>ลองเดา path ที่ไม่ควรเปิด เช่น <code>/c8/.env</code>, <code>/c8/.git/config</code>, <code>/c8/backup.zip</code></p></div>""")

        def c8_file(self, name):
            files = {
                ".env": f"APP_ENV=production\nDB_PASSWORD=sup3rs3cret\nFLAG={FLAGS['c8']}\n",
                ".git/config": "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:shop/app.git",
                "backup.zip": "PK\x03\x04 (ไฟล์ zip เสีย — ลอง .env ดูน่าจะเจอ flag)",
            }
            body = files.get(name.strip("/"))
            if body is not None:
                hit = FLAGS["c8"] in body
                note = "<div class='card'><h2 class='solved'>เจอไฟล์ลับที่ไม่ควรเปิด!</h2></div>" if hit else ""
                return page(f"/c8/{name}", f"<div class='card'><p class='mut'>GET /c8/{E(name)}</p>"
                            f"<pre>{E(body)}</pre></div>{note}")
            return page("404", "<div class='card'>ไม่พบไฟล์นี้ — ลอง <code>/c8/.env</code> หรือ "
                        "<code>/c8/.git/config</code></div>")

    return H


def main():
    import sys
    sys.stdout.reconfigure(line_buffering=True)
    srv = ThreadingHTTPServer((HOST, PORT), handler_class())
    print(f"🚩 sec-check CTF — http://{HOST}:{PORT}  (localhost only · Ctrl+C to stop)")
    print(f"   {len(FLAGS)} challenges · flags look like SECCHECK{{...}} · solutions in docs/CTF.md")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
