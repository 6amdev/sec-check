"""
โมดูล wifi — ตรวจความปลอดภัย Wi-Fi ของตัวเอง / audit your OWN Wi-Fi

ทำแบบ "ฟังเฉยๆ" (passive) อ่านข้อมูลที่ Wi-Fi รอบตัวประกาศออกมาเองด้วย nmcli — เหมือนที่เมนู Wi-Fi
ของเครื่องเห็น ไม่ได้ส่งอะไรไปโจมตี ไม่ยิง deauth ไม่จับ handshake ไม่ตัดการเชื่อมต่อของใคร
Passive only: it reads what nearby Wi-Fi already broadcasts (via nmcli), the same the OS Wi-Fi menu sees.
It never transmits an attack, never sends deauth, never captures a handshake, never disconnects anyone.

ตรวจเครือข่ายที่ "เครื่องนี้ต่ออยู่" เป็นหลัก (ถือว่าเป็นของผู้ใช้) — ระบุ --ssid เพื่อเจาะจงได้
It audits the network THIS machine is connected to (treated as yours); use --ssid to target one.

--passphrase 'xxx'  ตรวจความแข็งแรงของรหัส Wi-Fi ในเครื่อง (ไม่เก็บ ไม่ส่งออก ไม่แสดงตัวรหัส)
                    local passphrase-strength check (never stored, sent, or shown)

sec-check ตั้งใจ *ไม่* ทำ handshake capture / deauth / brute-force ให้ — การยิง deauth คือการตัด
สัญญาณ (DoS) เราจึงไม่สร้างเครื่องมือนั้น ถ้าจะทดสอบแบบจับ handshake บนเครือข่ายของตัวเองจริงๆ
ใช้ aircrack-ng/hcxtools ใน Terminal ของคุณเอง (ต้องใช้ root + การ์ดที่รองรับ monitor mode)
sec-check deliberately does NOT capture handshakes, send deauth, or brute-force for you.
"""
import re
import subprocess

from core.finding import Result, T
from i18n import _

# รหัส Wi-Fi ยอดฮิต/ค่าโรงงานที่เจอบ่อย (ชุดเล็กในเครื่อง — ไว้เทียบความอ่อนของรหัส ไม่ได้ใช้โจมตี)
COMMON = {
    "password", "12345678", "123456789", "1234567890", "qwertyuiop", "password1", "admin123",
    "00000000", "11111111", "88888888", "internet", "wireless", "changeme", "letmein", "welcome",
    "iloveyou", "whatsthewifi", "freewifi", "guest1234", "administrator", "p@ssw0rd", "abcd1234",
    "qwerty123", "home1234", "default", "router123",
}


def nmcli(*args):
    try:
        return subprocess.run(["nmcli", *args], capture_output=True, text=True, timeout=12).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def aps():
    """รายการ AP รอบตัว / nearby access points (passive, no rescan)"""
    out = nmcli("-t", "-f", "ACTIVE,SSID,BSSID,SECURITY,CHAN,SIGNAL", "dev", "wifi", "list", "--rescan", "no")
    rows = []
    for line in out.splitlines():
        p = re.split(r"(?<!\\):", line)          # BSSID มี \: คั่น / BSSID uses escaped colons
        if len(p) < 6:
            continue
        rows.append({"active": p[0] == "yes", "ssid": p[1].replace("\\:", ":"),
                     "bssid": p[2].replace("\\:", ":"), "security": p[3].strip(),
                     "chan": p[4], "signal": p[5]})
    return rows


def classify(res, ssid, security, target):
    su = security.upper().strip()
    if not su or su in ("--", "NONE", ""):
        res.add("wifi.open", target, _("ไม่มีการเข้ารหัส"))
    elif "WEP" in su:
        res.add("wifi.wep", target, security)
    elif ("WPA1" in su and "WPA2" in su) or ("WPA" in su and "WPA2" in su and "WPA1" not in su and "WPA3" not in su and su.count("WPA") > 1):
        res.add("wifi.wpa_mixed", target, security)
    elif su.strip() in ("WPA1", "WPA"):
        res.add("wifi.wpa1", target, security)
    elif "WPA3" in su or "SAE" in su:
        res.ok("Wi-Fi ใช้ WPA3 (ดีที่สุด)", target, security)
    elif "WPA2" in su:
        res.ok("Wi-Fi ใช้ WPA2", target, security)
        res.add("wifi.wpa2_suggest_wpa3", target, security)
    else:
        res.ok("ตรวจการเข้ารหัส Wi-Fi", target, security)


def passphrase_strength(res, pw, ssid=""):
    """ตรวจความแข็งแรงของรหัสในเครื่อง — ไม่เก็บ ไม่ส่ง ไม่ใส่ตัวรหัสลงรายงาน"""
    reasons = []
    n = len(pw)
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
    low = pw.lower()
    if n < 8:
        reasons.append(_("สั้นกว่า 8 ตัว (ต่ำกว่าขั้นต่ำของ WPA)"))
    elif n < 12:
        reasons.append(_("สั้นกว่า 12 ตัว"))
    if low in COMMON:
        reasons.append(_("อยู่ในรายการรหัสยอดฮิต"))
    if ssid and low == ssid.lower():
        reasons.append(_("เหมือนชื่อ Wi-Fi (SSID)"))
    if re.fullmatch(r"\d+", pw):
        reasons.append(_("เป็นตัวเลขล้วน"))
    elif re.fullmatch(r"[a-z]+", pw):
        reasons.append(_("เป็นตัวพิมพ์เล็กล้วน"))
    if classes <= 1 and n < 16:
        reasons.append(_("ประเภทตัวอักษรน้อย"))
    tgt = f"Wi-Fi '{ssid}'" if ssid else "Wi-Fi"
    ev = T("ยาว {n} ตัว · ประเภทตัวอักษร {c}/4 (ไม่แสดงตัวรหัส)", n=n, c=classes)
    if reasons:
        sev = "critical" if n < 8 or low in COMMON else "high"
        res.add("wifi.weak_passphrase", tgt, ev + (" · " + _("จุดอ่อน") + ": ") + "; ".join(reasons), sev)
    else:
        res.ok("รหัส Wi-Fi แข็งแรง (ผ่านการตรวจในเครื่อง)", tgt, str(ev))


def run(target, opts):
    res = Result("wifi", target or "Wi-Fi")
    pw = getattr(opts, "passphrase", None)
    want_ssid = getattr(opts, "ssid", None) or target
    all_aps = aps()

    if not all_aps and not pw:
        res.note("ไม่พบอุปกรณ์/สัญญาณ Wi-Fi (หรือไม่มี nmcli) — ข้ามการตรวจ Wi-Fi",
                 "nmcli dev wifi list")
        return res.done()

    # เลือกเครือข่ายที่จะตรวจ: ที่ต่ออยู่ หรือที่ระบุด้วย --ssid
    active = next((a for a in all_aps if a["active"]), None)
    pick = None
    if want_ssid:
        pick = next((a for a in all_aps if a["ssid"] == want_ssid), None)
    pick = pick or active

    if pick:
        ssid = pick["ssid"] or "(hidden)"
        res.target = f"Wi-Fi '{ssid}'"
        res.note("เครือข่ายที่ตรวจ (ยืนยันว่าเป็นของคุณ)", f"{ssid} · BSSID {pick['bssid']} · ch {pick['chan']}")
        classify(res, ssid, pick["security"], f"Wi-Fi '{ssid}'")
        # ชื่อซ้ำหลาย BSSID → อาจเป็น mesh ของเราเอง หรือ evil twin
        same = sorted({a["bssid"] for a in all_aps if a["ssid"] == ssid and a["bssid"]})
        if len(same) > 1:
            res.add("wifi.duplicate_ssid", f"Wi-Fi '{ssid}'",
                    T("{n} BSSID: {b}", n=len(same), b=", ".join(same)))
    elif not pw:
        res.note("เครื่องนี้ไม่ได้ต่อ Wi-Fi — ระบุเครือข่ายของคุณด้วย --ssid ชื่อ", "")

    # นับ AP รอบตัวแบบไม่เปิดเผยของเพื่อนบ้าน (บริบทเฉยๆ)
    if all_aps:
        enc = {}
        for a in all_aps:
            k = (a["security"] or "open").split()[0].upper() or "OPEN"
            enc[k] = enc.get(k, 0) + 1
        res.note("AP รอบตัว (บริบท — ไม่ใช่เป้าหมาย)",
                 f"{len(all_aps)} · " + ", ".join(f"{k}:{v}" for k, v in sorted(enc.items())))

    # ตรวจความแข็งแรงของรหัส (เฉพาะเมื่อผู้ใช้ให้มาเอง)
    if pw:
        passphrase_strength(res, pw, want_ssid or (pick["ssid"] if pick else ""))

    res.manual = ["wifi.manual_wps", "wifi.manual_pmf", "wifi.manual_passphrase_test", "wifi.manual_admin"]
    res.note("sec-check ไม่ยิง deauth / ไม่จับ handshake / ไม่เดารหัส Wi-Fi ให้ — ตรวจรหัสด้วย --passphrase "
             "หรือใช้เครื่องมือมาตรฐานในเครื่องของคุณเองสำหรับเครือข่ายของคุณ")
    return res.done()
