# แคตตาล็อกโจทย์ฝึกเจาะ — ครบทั้งสาย ง่าย → ยาก
# Hands-on challenge catalog (beginner → advanced), by topic

> ⚖️ ทำกับ **เป้าฝึก/เครื่องของตัวเอง** เท่านั้น · lab ต้อง **แยกวง ไม่ต่อเน็ต** (bind 127.0.0.1 หรือ Docker network ภายใน)
> นี่คือ "แผนที่ทั้งหมดที่ควรมี" — บางอันทำได้เลย บางอันต้องติดตั้งเพิ่ม (ดูคอลัมน์ "ต้องมี") ค่อยๆ ทำเท่าที่ทรัพยากรไหว

**สัญลักษณ์ระดับ:** 🟢 ง่าย · 🟡 กลาง · 🔴 ยาก · ⚫ โหด
**สัญลักษณ์สภาพแวดล้อม:** ✅ มีแล้ว (CTF lab / DVWA / Juice Shop) · 🐳 Docker (ติดตั้งง่าย) · 🖥️ VM · 🔧 ติดตั้งซอฟต์แวร์เอง · ☁️ นอกเครื่อง/สมัครฟรี

เครื่องที่ใช้ได้ดี: **Home Server (Ryzen 9 + 4070 Ti)** — เหมาะมากโดยเฉพาะเฟสเจาะรหัส (hashcat ใช้ GPU)

---

## A. 🐧 รากฐาน Linux & เครือข่าย (ต้องผ่านก่อน)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| A1 | OverTheWire **Bandit** level 0→34 | 🟢→🟡 | Linux CLI, ssh, permission, การหาข้อมูลในระบบ | ☁️ (ฟรี ออนไลน์) |
| A2 | อ่าน/เขียน bash script หา SUID, พอร์ตเปิด, cron | 🟢 | พื้นฐานที่ใช้ตอน privesc | 🔧 เครื่อง Ubuntu |
| A3 | ตั้ง lab network แยก (Docker network / host-only VM) | 🟡 | isolation, ทำไม lab ต้องไม่ต่อเน็ต | 🐳/🖥️ |
| A4 | เข้าใจ HTTP ด้วยมือ: `curl -v`, อ่าน header/cookie, ส่ง POST | 🟢 | พื้นฐานก่อนเจาะเว็บ | ✅ |

## B. 🔍 Recon & Scanning
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| B1 | nmap เป้าใน lab: หาพอร์ต/บริการ/เวอร์ชันทั้งหมด | 🟢 | port scan, service/version detection | 🐳 nmap + เป้า |
| B2 | nmap NSE `--script vuln`, `--script smb-*` | 🟡 | สแกนช่องโหว่อัตโนมัติ | 🐳 |
| B3 | Directory/file brute ด้วย ffuf/gobuster บน DVWA | 🟢 | หา endpoint ที่ซ่อน | ✅ DVWA |
| B4 | Enumeration SMB/SNMP/FTP (enum4linux, snmpwalk) | 🟡 | ดึงข้อมูล user/share/ชื่อเครื่อง | 🖥️ Metasploitable |
| B5 | OSINT: theHarvester, Shodan, cert transparency (โดเมนตัวเอง) | 🟡 | passive recon | ☁️ |

## C. 💉 SQL Injection (ครบทุกแบบ)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| C1 | DVWA SQLi (Low) — ดึง user/pass | 🟢 | error/union-based พื้นฐาน | ✅ DVWA |
| C2 | DVWA SQLi (Medium/High) — bypass filter | 🟡 | encoding, filter evasion | ✅ DVWA |
| C3 | **Blind SQLi** (Boolean/Time-based) ด้วยมือ | 🔴 | ดึงข้อมูลทั้งที่ไม่เห็นผลลัพธ์ | ✅ DVWA Blind |
| C4 | automate ด้วย **sqlmap** (`--dump`, `--os-shell`) | 🟡 | ใช้เครื่องมือ pro, เมื่อไรควรใช้มือ | 🔧 sqlmap |
| C5 | SQLi บน **MySQL** จริงที่ติดตั้งเอง (เว็บต่อ DB) | 🔴 | เจาะ stack จริง → อ่าน schema | 🔧 MySQL + PHP |
| C6 | **NoSQL injection** (MongoDB `$ne`/`$gt`) | 🔴 | ต่างจาก SQL ยังไง | 🔧 MongoDB + app |
| C7 | SQLi → RCE (`INTO OUTFILE` / stacked queries) | ⚫ | จาก DB ไปยึดเครื่อง | 🔧 MySQL |

## D. 🪝 XSS / CSRF / SSRF
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| D1 | DVWA/Juice Shop **Reflected XSS** → alert | 🟢 | input กลายเป็น HTML/JS | ✅ |
| D2 | **Stored XSS** → ขโมย cookie ไปเครื่องเรา | 🟡 | ผลกระทบจริงของ XSS, session hijack | ✅ DVWA |
| D3 | **DOM XSS** | 🔴 | XSS ฝั่ง client ล้วน | ✅ Juice Shop |
| D4 | **CSRF** เปลี่ยนรหัสเหยื่อผ่านหน้าปลอม | 🟡 | ทำไม cookie อย่างเดียวไม่พอ | ✅ DVWA |
| D5 | **SSRF** หลอก server ยิง request ภายใน / cloud metadata | 🔴 | เจาะเครือข่ายภายในผ่าน server | 🐳 app ที่มี SSRF |
| D6 | XSS ขั้นสูง: bypass CSP, polyglot, BeEF hook | ⚫ | เลี่ยงการป้องกัน | ✅/🔧 |

## E. 🔐 Authentication / Session / Access Control
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| E1 | เจาะ login ด้วยรหัส default + brute (**hydra**) | 🟢 | online password attack, rate-limit | 🔧 hydra + เป้า |
| E2 | **IDOR** เปลี่ยน id เข้าถึงของคนอื่น | 🟢 | broken access control | ✅ CTF/Juice Shop |
| E3 | **Path/Directory traversal** อ่านไฟล์ระบบ | 🟡 | `../`, LFI | ✅ CTF/DVWA |
| E4 | **JWT attacks**: alg=none, weak secret (jwt_tool/hashcat) | 🔴 | โทเคนปลอม, ความลับอ่อน | ✅ Juice Shop |
| E5 | **LFI → RCE** (log poisoning / php wrapper) | 🔴 | จากอ่านไฟล์ไปรันโค้ด | 🔧 PHP app |
| E6 | **File upload** webshell (bypass ชนิดไฟล์) | 🔴 | จากอัปโหลดไปยึดเว็บ | ✅ DVWA Upload |
| E7 | privilege escalation แนวนอน/ตั้งในแอป (user→admin) | 🟡 | access control ที่พลาด | ✅ Juice Shop |

## F. 🧩 Injection ขั้นสูง
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| F1 | **Command injection** (DVWA) → reverse shell | 🟡 | จากช่องกรอกไปรันคำสั่ง | ✅ DVWA |
| F2 | **XXE** (XML external entity) อ่านไฟล์/SSRF | 🔴 | ช่องโหว่ XML parser | 🐳 app XXE |
| F3 | **SSTI** (template injection) → RCE (Jinja2/Twig) | 🔴 | template engine พลาด | 🐳 Flask/PHP app |
| F4 | **Deserialization** (PHP/Python/Java) → RCE | ⚫ | object injection | 🔧 app เฉพาะ |

## G. 🗄️ Database & Service Exploitation (ติดตั้งซอฟต์แวร์เองบน Home Server)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| G1 | **Redis** ไม่มีรหัส → เขียน SSH key / webshell | 🔴 | บริการไม่ auth → ยึดเครื่อง | 🔧 Redis |
| G2 | **MongoDB** เปิดไม่มี auth → dump ข้อมูล | 🟡 | NoSQL exposure | 🔧 MongoDB |
| G3 | **MySQL/PostgreSQL** รหัสอ่อน → เข้า DB → `xp_cmdshell`/UDF | 🔴 | DB → OS | 🔧 MySQL/PG |
| G4 | **Elasticsearch/memcached** เปิดโล่ง → อ่านข้อมูล | 🟡 | data exposure | 🔧 |
| G5 | **SMTP** open relay / user enumeration (VRFY) | 🟡 | mail service abuse | 🔧 Postfix |
| G6 | **Docker API / docker.sock** เปิด → หลุด container เป็น root | ⚫ | container escape | 🐳 |

## H. 💣 เจาะบริการด้วย Metasploit / CVE (เครื่องเต็ม)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| H1 | **Metasploitable 2** — เจาะให้ได้ root หลายทาง | 🟡 | วิธีการครบวงจร, Metasploit, meterpreter | 🖥️ VM |
| H2 | **EternalBlue** (MS17-010) บน Windows lab | 🔴 | exploit SMB ชื่อดัง (WannaCry) | 🖥️ Win7 VM |
| H3 | **vulhub** — เจาะ CVE เฉพาะตัว (Struts, Log4Shell, Confluence) | 🔴 | จาก CVE → PoC → exploit | 🐳 vulhub |
| H4 | เขียน exploit ด้วยมือ (ไม่พึ่ง Metasploit) | ⚫ | เข้าใจกลไกจริง | 🐳/🖥️ |
| H5 | `msfvenom` สร้าง payload + หลบ AV เบื้องต้น | 🔴 | payload, encoding | 🖥️ |

## I. 🔑 Password & Crypto (GPU 4070 Ti ของคุณจะได้ใช้!)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| I1 | crack hash (MD5/SHA/bcrypt) ด้วย **hashcat** + rockyou | 🟢 | ชนิด hash, wordlist, GPU cracking | 🔧 hashcat |
| I2 | **rules & mask attack** (ต่อยอด wordlist) | 🟡 | เดารหัสฉลาดขึ้น | 🔧 hashcat |
| I3 | crack `/etc/shadow`, NTLM, Kerberos (จาก lab) | 🔴 | hash จากของจริง | 🔧 |
| I4 | **padding oracle** / ECB / weak crypto challenge | ⚫ | โจมตีการเข้ารหัสที่ผิด | ☁️ CryptoHack |
| I5 | crack WPA2 handshake **ของ Wi-Fi ตัวเอง** | 🔴 | จาก handshake → รหัส | 🔧 aircrack+hashcat |

## J. 🧗 Privilege Escalation
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| J1 | **Linux privesc**: SUID + GTFOBins → root | 🟡 | ไต่สิทธิ์จากช่องคลาสสิก | 🖥️/🐳 |
| J2 | sudo misconfig, cron, PATH hijack, capabilities | 🔴 | หลายเทคนิค privesc | 🖥️ |
| J3 | ใช้ **linpeas** อ่านผล หาเส้นทาง | 🟡 | automate การหาช่อง | 🖥️ |
| J4 | **Windows privesc**: service/unquoted path/token | 🔴 | ฝั่ง Windows | 🖥️ Win VM |
| J5 | kernel exploit (DirtyCow/DirtyPipe) ใน lab เก่า | ⚫ | ช่องระดับ kernel | 🖥️ |

## K. 🏢 Active Directory (สายองค์กร)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| K1 | ตั้ง **GOAD** lab | 🔴 | โครงสร้าง AD | 🖥️ หลาย VM (RAM เยอะ — เครื่องคุณไหว) |
| K2 | **BloodHound** หาเส้นทางสู่ Domain Admin | 🔴 | enumeration AD | 🖥️ |
| K3 | **Kerberoasting / AS-REP roasting** → crack | 🔴 | ขโมย+ถอดตั๋ว Kerberos | 🖥️ |
| K4 | **NTLM relay** (ตรงกับ finding `windows.smb_signing`!) | ⚫ | สวมรอยในวง | 🖥️ |
| K5 | **DCSync / Golden Ticket** | ⚫ | ยึด domain เบ็ดเสร็จ | 🖥️ |

## L. 📶 Wireless (เครือข่ายตัวเอง)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| L1 | จับ WPA2 handshake AP ตัวเอง → crack | 🔴 | ความแข็งของรหัส Wi-Fi จริง | 🔧 การ์ด monitor mode |
| L2 | WPS brute (Reaver) บนเราเตอร์ตัวเอง | 🔴 | ทำไมต้องปิด WPS | 🔧 |

## M. 🧬 Binary Exploitation & RE (สายลึก)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| M1 | **exploit.education Phoenix** — stack overflow | 🔴 | memory corruption พื้นฐาน | 🖥️/🐳 |
| M2 | **ROP** (bypass NX) — ROP Emporium | ⚫ | return-oriented programming | 🐳 |
| M3 | format string, bypass ASLR/canary | ⚫ | เทคนิค exploit สมัยใหม่ | 🐳 |
| M4 | RE ด้วย **Ghidra/gdb-pwndbg** — picoCTF | 🔴 | อ่าน binary หา logic/flag | 🔧 |

## N. ☁️ Cloud / Container / K8s / API / Mobile / IoT (สายเฉพาะทาง)
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| N1 | **flaws.cloud** / **CloudGoat** (AWS misconfig) | 🔴 | IAM, S3, metadata SSRF | ☁️ AWS ฟรีทัวร์ |
| N2 | **Kubernetes Goat** | 🔴 | เจาะ k8s | 🐳 k8s |
| N3 | **API security** (crAPI/VAmPI): BOLA, mass assignment | 🟡 | REST/GraphQL abuse | 🐳 |
| N4 | **Mobile** (DIVA/InsecureBankv2): APK, Frida, jadx | 🔴 | เจาะแอป Android | 🔧 |
| N5 | **IoT firmware**: binwalk แกะเฟิร์มแวร์ หา key/creds | 🔴 | firmware analysis | 🔧 |

## O. 🏁 ฝึกต่อเนื่อง + ระเบียบวิธี
| # | โจทย์ | ระดับ | เรียนเรื่อง | ต้องมี |
|---|---|---|---|---|
| O1 | **TryHackMe** learning paths (มือใหม่สุด มีไกด์) | 🟢→🔴 | ทุกอย่างแบบมีเฉลย | ☁️ |
| O2 | **HackTheBox** machines (ไล่ Easy→Insane) | 🟡→⚫ | เจาะเครื่องครบวงจร | ☁️ |
| O3 | **PortSwigger Web Security Academy** (ฟรี ดีสุดสายเว็บ) | 🟢→⚫ | ครบทุกช่องโหว่เว็บ | ☁️ |
| O4 | เขียน **writeup** ทุกเครื่องที่เจาะได้ | — | ตกผลึก + portfolio | — |
| O5 | สายใบเซอร์: eJPT → **PNPT/OSCP** | — | มาตรฐานอุตสาหกรรม | ☁️ |

---

## ✅ เริ่มได้เลยตอนนี้ (มีสภาพแวดล้อมแล้ว)
- **CTF lab ของเรา** (`./ctf.sh`) — A4, C-D-E-F เบื้องต้น (รันอยู่แล้ว)
- **DVWA + Juice Shop** (`lab/pentest/docker compose up -d`) — B3, C1-3, D1-4, E2-7, F1
- รออะไรแค่ **sqlmap/hydra/nmap/hashcat** (ติดตั้งเพิ่มได้) → C4, E1, B1, I1

## 🔧 ขั้นต่อไปที่ควรติดตั้งบน Home Server (ตามลำดับความคุ้ม)
1. **เครื่องมือโจมตี:** `sqlmap`, `nmap`, `hashcat`, `hydra`, `john`, `ffuf`, `gobuster` (apt/pip)
2. **DVWA + Juice Shop** (docker) — เริ่มเฟสเว็บ
3. **ซอฟต์แวร์เป้า:** MySQL, MongoDB, Redis, Nginx/Apache + PHP — เฟส G (เจาะ stack จริง)
4. **Metasploit + Metasploitable 2 VM** — เฟส H/J (เจาะเครื่อง + privesc)
5. **GOAD** (Active Directory, เครื่องคุณ RAM/CPU ไหว) — เฟส K
6. **vulhub** (CVE เฉพาะตัว) — เฟส H

> บอกผมได้เลยว่าจะเริ่มหมวดไหน — ผมจะพาทำทีละข้อ **เจาะสด + อธิบายว่าเรียนเรื่องอะไร ทำไมได้ผล กันยังไง**
> ของที่ยังไม่มี เดี๋ยวเราติดตั้งด้วยกันทีละชิ้นเท่าที่ทรัพยากรไหว
