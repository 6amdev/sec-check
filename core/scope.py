"""
ขอบเขตการตรวจ (allow-list) / Scan scope (allow-list)

sec-check จะไม่ยอมตรวจอะไรที่ไม่อยู่ใน scope.json — ต้องเพิ่มเป้าหมายเองและยืนยันว่าเป็นเจ้าของ
หรือได้รับอนุญาตเป็นลายลักษณ์อักษร (การสแกนระบบของคนอื่นโดยไม่ได้รับอนุญาตผิดกฎหมาย
เช่น พ.ร.บ.คอมพิวเตอร์ฯ มาตรา 5-7)

sec-check refuses to touch anything that is not in scope.json. You add each target yourself and
confirm you own it or have written permission. Loopback (127.0.0.0/8, ::1) — this machine — is always allowed.

scope.json is git-ignored: your list of hosts is private.
"""
import ipaddress
import json
import time
import urllib.parse
from pathlib import Path

from i18n import _

HERE = Path(__file__).resolve().parent.parent
SCOPE_FILE = HERE / "scope.json"
LOOPBACK = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
CONFIRM_WORD = "yes"


class OutOfScope(Exception):
    pass


def normalize(target):
    """URL / host / IP / CIDR -> (kind, value). kind: url, net, host"""
    t = target.strip()
    if "://" in t:
        u = urllib.parse.urlsplit(t)
        return "url", f"{u.scheme.lower()}://{(u.hostname or '').lower()}" + (f":{u.port}" if u.port else "")
    try:
        return "net", str(ipaddress.ip_network(t, strict=False))
    except ValueError:
        pass
    return "host", t.lower().rstrip(".")


def load():
    try:
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8")).get("targets", [])
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(_("อ่าน scope.json ไม่ได้: {e}", e=e))


def save(entries):
    SCOPE_FILE.write_text(json.dumps({"targets": entries}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def add(target, note="", assume_yes=False):
    kind, value = normalize(target)
    entries = load()
    if any(e["target"] == value for e in entries):
        print(_("มีอยู่แล้วใน scope: {t}", t=value))
        return
    print(_("⚠️  กำลังเพิ่ม {t} เข้าในขอบเขตการตรวจ", t=value))
    print(_("   ตรวจได้เฉพาะระบบที่คุณเป็นเจ้าของ หรือได้รับอนุญาตเป็นลายลักษณ์อักษรจากเจ้าของเท่านั้น"))
    print(_("   การสแกนระบบของผู้อื่นโดยไม่ได้รับอนุญาตอาจผิดกฎหมาย"))
    if not assume_yes:
        ans = input(_("   พิมพ์ '{w}' เพื่อยืนยันว่าคุณเป็นเจ้าของ/ได้รับอนุญาต: ", w=CONFIRM_WORD)).strip().lower()
        if ans != CONFIRM_WORD:
            print(_("ยกเลิก — ไม่ได้เพิ่ม"))
            return
    entries.append({"target": value, "kind": kind, "note": note,
                    "confirmed": time.strftime("%Y-%m-%d %H:%M")})
    save(entries)
    print(_("✅ เพิ่มแล้ว: {t}", t=value))


def remove(target):
    _kind, value = normalize(target)
    entries = load()
    left = [e for e in entries if e["target"] != value]
    save(left)
    print(_("ลบแล้ว: {t}", t=value) if len(left) < len(entries) else _("ไม่พบใน scope: {t}", t=value))


def _ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _host_allowed(host, entries):
    host = host.lower().rstrip(".")
    ip = _ip(host)
    if ip is not None:
        if any(ip in n for n in LOOPBACK):
            return True
        for e in entries:
            if e["kind"] == "net" and ip in ipaddress.ip_network(e["target"]):
                return True
            if e["kind"] == "url" and urllib.parse.urlsplit(e["target"]).hostname == host:
                return True
        return False
    if host == "localhost":
        return True
    for e in entries:
        v = e["target"]
        if e["kind"] == "url":
            v = urllib.parse.urlsplit(v).hostname or ""
        if e["kind"] in ("host", "url"):
            if v == host or (v.startswith("*.") and (host == v[2:] or host.endswith(v[1:]))):
                return True
    return False


def check(target):
    """ยกข้อผิดพลาด OutOfScope ถ้าไม่อยู่ในขอบเขต / raise OutOfScope when not allowed"""
    entries = load()
    kind, value = normalize(target)
    if kind == "net":
        net = ipaddress.ip_network(value)
        ok = any(net.subnet_of(n) for n in LOOPBACK if n.version == net.version) or any(
            e["kind"] == "net" and ipaddress.ip_network(e["target"]).version == net.version
            and net.subnet_of(ipaddress.ip_network(e["target"])) for e in entries)
    elif kind == "url":
        ok = _host_allowed(urllib.parse.urlsplit(value).hostname or "", entries)
    else:
        ok = _host_allowed(value, entries)
    if not ok:
        raise OutOfScope(_("{t} ไม่อยู่ในขอบเขตการตรวจ (scope.json)\n"
                           "ถ้าเป็นระบบของคุณจริง เพิ่มด้วย:  ./seccheck.py scope add {t}", t=target))
    return True


def show():
    entries = load()
    print(_("ขอบเขตการตรวจ (scope.json):"))
    print("  127.0.0.0/8, ::1, localhost   " + _("(เครื่องนี้ — อนุญาตเสมอ)"))
    for e in entries:
        print(f"  {e['target']:<30} {e.get('note', '')}  [{e.get('confirmed', '')}]")
    if not entries:
        print(_("  (ยังไม่มี — เพิ่มด้วย ./seccheck.py scope add <เป้าหมาย>)"))
