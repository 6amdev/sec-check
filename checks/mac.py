"""
โมดูล mac — ตรวจเครื่อง macOS ในวงของตัวเอง แบบไม่ทำลาย / non-destructive checks of your own Mac

ดูบริการแชร์/รีโมตที่เปิดอยู่: Screen Sharing (VNC 5900), AFP (548), Apple Remote Desktop (3283),
SMB (445), SSH (22) — ใช้การเจรจาโปรโตคอลแบบอ่านอย่างเดียว ไม่ล็อกอิน ไม่เดารหัส
Looks at exposed sharing/remote services: Screen Sharing (VNC 5900), AFP (548), Apple Remote Desktop
(3283), SMB (445), SSH (22) — read-only protocol negotiation, no login, no password guessing.
"""
import re

from core import net, scope
from core.finding import Result
from i18n import _
from checks.lan import vnc
from checks.windows import smb_probe

PORTS = {22: "SSH", 445: "SMB", 548: "AFP", 3283: "ARD", 5900: "Screen Sharing (VNC)", 5988: "WBEM"}


def run(target, opts):
    if not target:
        raise SystemExit(_("ระบุ IP ของเครื่อง Mac เช่น ./seccheck.py mac 192.168.1.40"))
    scope.check(target)
    res = Result("mac", target)
    state = {p: net.tcp_state(target, p, timeout=1.5) for p in PORTS}
    res.table("บริการที่เปิดบนเครื่อง Mac", ["พอร์ต", "บริการ", "สถานะ"],
              [[str(p), PORTS[p], state[p]] for p in PORTS if state[p] == "open"] or [["-", "-", "-"]])

    if state[5900] == "open":
        res.add("mac.screen_sharing", f"{target}:5900")
        vnc(target, 5900, res)                         # ตรวจว่า VNC ไม่มีรหัสไหม (lan.vnc_noauth)
    if state[548] == "open":
        res.add("mac.afp", f"{target}:548")
    if state[3283] == "open":
        res.add("mac.ard", f"{target}:3283")
    if state[445] == "open":
        smb_probe(target, res, f"{target}:445")        # SMB signing / SMBv1 (ใช้ตัวตรวจเดียวกับ windows)
    if state[22] == "open":
        b = (net.banner(target, 22) or b"").decode("latin-1").strip()
        res.add("lan.ssh", f"{target}:22", b[:80])
        m = re.search(r"OpenSSH_(\d+)\.(\d+)", b)
        if m and (int(m.group(1)), int(m.group(2))) < (8, 0):
            res.add("lan.ssh_old", f"{target}:22", b[:80])

    if all(st != "open" for st in state.values()):
        res.note("ไม่พบบริการแชร์/รีโมตของ Mac ที่เปิดอยู่บนเป้าหมายนี้", target)
    res.manual = ["mac.manual_firewall"]
    res.note("ตรวจแบบอ่านอย่างเดียว — ไม่ล็อกอิน ไม่เดารหัส ไม่ส่ง exploit")
    return res.done()
