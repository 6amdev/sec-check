#!/usr/bin/env python3
"""
sec-check workbench — ศูนย์รวมคำสั่งในเทอร์มินอล / an interactive terminal command-center

เมนูโต้ตอบไว้เรียกสแกน · เปิด lab/CTF · เช็ก/ติดตั้งเครื่องมือ · จัดการ allow-list · เปิดหน้าเว็บ
ทั้งหมดในที่เดียว — stdlib ล้วน ไม่ต้องจำคำสั่ง

  ./sc            หรือ   ./seccheck.py menu
"""
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m", "c": "\033[36m",
     "m": "\033[35m", "gray": "\033[90m", "bold": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def col(s, c):
    return f"{C.get(c, '')}{s}{C['x']}"


def port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def sh(cmd, wait=True):
    """รันคำสั่ง (ในฐานะผู้ใช้) / run a command as the user, show its output"""
    print(col(f"\n$ {' '.join(cmd)}\n", "gray"))
    try:
        if wait:
            subprocess.run(cmd, cwd=str(HERE))
        else:
            subprocess.Popen(cmd, cwd=str(HERE))
    except (OSError, KeyboardInterrupt) as e:
        print(col(f"(หยุด/ผิดพลาด: {e})", "y"))


def ask(prompt):
    try:
        return input(col(prompt, "c")).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def scope_count():
    try:
        import json
        return len(json.loads((HERE / "scope.json").read_text()).get("targets", []))
    except (OSError, ValueError):
        return 0


TOOLS = ["nmap", "sqlmap", "hashcat", "hydra", "john", "ffuf", "gobuster", "nikto", "msfconsole", "docker"]


def header():
    os.system("clear" if os.name != "nt" else "cls")
    up = []
    if port_open(8900):
        up.append(col("CTF:on", "g"))
    if port_open(8770):
        up.append(col("web:on", "g"))
    if port_open(4280):
        up.append(col("DVWA:on", "g"))
    if port_open(4300):
        up.append(col("Juice:on", "g"))
    have = sum(1 for t in TOOLS if shutil.which(t))
    print(col("╔════════════════════════════════════════════════╗", "m"))
    print(col("║   🛡️  sec-check workbench · terminal center     ║", "m"))
    print(col("╚════════════════════════════════════════════════╝", "m"))
    print(f"  {col('เป้าใน allow-list:', 'gray')} {scope_count()}   "
          f"{col('เครื่องมือ:', 'gray')} {have}/{len(TOOLS)}   "
          f"{col('ทำงานอยู่:', 'gray')} {' '.join(up) or '-'}")
    print()


MENUS = {
    "main": [
        ("สแกน (Scan)", "scan"),
        ("สนามฝึก / CTF (Labs)", "labs"),
        ("เครื่องมือเจาะ (Tools)", "tools"),
        ("เรียนรู้ (Learn/Docs)", "learn"),
        ("เป้าหมาย allow-list (Targets)", "targets"),
    ],
}


def menu(title, items):
    """items: list of (label, callable|str). คืน None เมื่อย้อนกลับ"""
    while True:
        header()
        print(col(f"  {title}", "bold"))
        print()
        for i, (label, _a) in enumerate(items, 1):
            print(f"   {col(str(i), 'y')}. {label}")
        print(f"   {col('b', 'gray')}. ย้อนกลับ    {col('q', 'gray')}. ออก")
        choice = ask("\n  เลือก > ")
        if choice in ("q", "quit", "exit"):
            sys.exit(0)
        if choice in ("b", "back", ""):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            action = items[int(choice) - 1][1]
            if callable(action):
                action()
                ask(col("\n  [Enter เพื่อกลับเมนู]", "gray"))
            else:
                SUBMENUS[action]()


def cli(*args):
    return lambda: sh([sys.executable, str(HERE / "seccheck.py"), *args])


def scan_menu():
    menu("สแกน — ตรวจระบบของคุณ (ไม่ทำลาย)", [
        ("ตรวจเครื่องนี้ (host audit)", cli("host")),
        ("ตรวจ Wi-Fi ที่ต่ออยู่", cli("wifi")),
        ("สแกนวงแลน (อัตโนมัติ)", cli("lan")),
        ("ตรวจเว็บไซต์ (ถาม URL)", lambda: sh([sys.executable, "seccheck.py", "web", ask("  URL > ") or "https://example.com"])),
        ("ตรวจ TLS/SSL (ถาม host)", lambda: sh([sys.executable, "seccheck.py", "tls", ask("  host > ") or "example.com"])),
        ("ตรวจเราเตอร์ (gateway)", cli("router")),
        ("จับเวอร์ชัน↔CVE (ถาม host)", lambda: sh([sys.executable, "seccheck.py", "cve", ask("  host > ") or "127.0.0.1"])),
        ("ตรวจทุกอย่างใน scope (all)", cli("all")),
    ])


def labs_menu():
    menu("สนามฝึก / CTF (เป้าฝึกบน localhost)", [
        ("เปิดสนาม CTF (ของเรา) → :8900", lambda: sh([sys.executable, str(HERE / "lab" / "ctf.py")], wait=False)),
        ("เปิดเป้าฝึกจริง DVWA+JuiceShop (docker)", lambda: sh(["bash", "-c", "cd lab/pentest && docker compose up -d"])),
        ("ปิดเป้าฝึก docker", lambda: sh(["bash", "-c", "cd lab/pentest && docker compose down"])),
        ("เปิดหน้าเว็บ sec-check (./web.sh) → :8770", lambda: sh(["bash", str(HERE / "web.sh")], wait=False)),
    ])


def tools_menu():
    def check():
        print()
        for t in TOOLS:
            p = shutil.which(t)
            print(f"   {col('✔','g') if p else col('✘','r')} {t:<12} {col(p or 'ยังไม่ได้ติดตั้ง','gray')}")
        print(col("\n  ติดตั้ง (Ubuntu): sudo apt install nmap hydra john nikto · pipx install sqlmap", "gray"))
        print(col("  hashcat: sudo apt install hashcat · ffuf/gobuster: ผ่าน go/apt · metasploit: มี installer", "gray"))

    menu("เครื่องมือเจาะ", [
        ("เช็กว่ามีเครื่องมืออะไรบ้าง", check),
        ("ดูคำสั่งติดตั้ง (คัดลอกไปรันเอง)", lambda: print(col(
            "\n  sudo apt update && sudo apt install -y nmap hydra john nikto hashcat netcat-openbsd\n"
            "  pipx install sqlmap    # หรือ pip install --user sqlmap\n"
            "  # ffuf/gobuster: go install, metasploit: https://docs.metasploit.com/", "c"))),
    ])


def learn_menu():
    menu("เรียนรู้", [
        ("เปิดหน้า Learn (เว็บ) → :8770/learn", lambda: sh(["bash", str(HERE / "web.sh")], wait=False)),
        ("ดูรายการบทเรียนทั้งหมด (lessons)", cli("lessons")),
        ("อ่านคำอธิบายช่องโหว่ (ถาม id)", lambda: sh([sys.executable, "seccheck.py", "explain", ask("  id (เช่น lan.redis_noauth) > ") or "web.git_exposed"])),
        ("เปิดเอกสาร (หลักสูตร/โจทย์/CTF)", lambda: print(col(
            "\n  docs/LEARN-PENTEST.md   — หลักสูตร ง่าย→ยาก"
            "\n  docs/CHALLENGES.md      — แคตตาล็อกโจทย์ 60+"
            "\n  docs/CTF.md             — เฉลยสนาม CTF"
            "\n  docs/CURRICULUM.md      — เจาะ→ป้องกัน"
            "\n  lab/pentest/README.md   — เปิดเป้าฝึกจริง", "c"))),
    ])


def targets_menu():
    def add():
        t = ask("  เป้าหมาย (เช่น 192.168.1.0/24 หรือ https://mysite.com) > ")
        if not t:
            return
        print(col("  ⚠️ ยืนยันว่าคุณเป็นเจ้าของ/ได้รับอนุญาตทดสอบเป้านี้", "y"))
        if ask("  พิมพ์ yes เพื่อยืนยัน > ") == "yes":
            sh([sys.executable, "seccheck.py", "scope", "add", t, "--yes"])
        else:
            print(col("  ยกเลิก", "gray"))

    menu("เป้าหมาย (allow-list)", [
        ("ดูรายการเป้าหมาย", cli("scope", "list")),
        ("เพิ่มเป้าหมาย (ยืนยันความเป็นเจ้าของ)", add),
        ("ลบเป้าหมาย (ถาม)", lambda: sh([sys.executable, "seccheck.py", "scope", "remove", ask("  เป้าที่จะลบ > ") or "x"])),
    ])


SUBMENUS = {"scan": scan_menu, "labs": labs_menu, "tools": tools_menu,
            "learn": learn_menu, "targets": targets_menu}


def main():
    if not sys.stdin.isatty():
        print("workbench ต้องรันในเทอร์มินอลจริง (interactive) — ลอง ./sc")
        return
    try:
        menu("เมนูหลัก — เลือกหมวด", MENUS["main"])
    except KeyboardInterrupt:
        pass
    print(col("\n  bye 👋", "gray"))


if __name__ == "__main__":
    main()
