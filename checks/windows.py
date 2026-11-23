"""
โมดูล windows — ตรวจเครื่อง Windows ในวงของตัวเอง (SMB/RDP) แบบไม่ทำลาย
Module windows — non-destructive SMB/RDP checks of your own Windows hosts

ทำแค่ "เจรจาโปรโตคอล" (protocol negotiation) ตามปกติ: ถาม SMB ว่ารองรับ dialect ไหน/บังคับเซ็นไหม,
ถาม RDP ว่าบังคับ NLA ไหม — ไม่ล็อกอิน ไม่เดารหัส ไม่ส่ง exploit ไม่เปิด session จริง
Only normal protocol negotiation: ask SMB which dialects/signing it offers, ask RDP whether it
requires NLA. No login, no password guessing, no exploit, no real session is opened.
"""
import socket
import struct

from core import net, scope
from core.finding import Result, T
from i18n import _


def recv_nbss(sock, timeout=4):
    """อ่าน 1 ข้อความ SMB ที่หุ้มด้วย NetBIOS session header / read one NBSS-framed message"""
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = struct.unpack(">I", b"\x00" + hdr[1:4])[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def smb1_negotiate(dialects):
    """สร้าง SMB1 NEGOTIATE request / build an SMB1 NEGOTIATE request"""
    header = b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + b"\x53\xc8" + b"\x00" * 18 + \
        b"\x00\x00" + struct.pack("<H", 0xFEFF) + b"\x00\x00" + b"\x00\x00"
    body = b"\x00"                           # WordCount = 0
    dblock = b"".join(b"\x02" + d.encode() + b"\x00" for d in dialects)
    body += struct.pack("<H", len(dblock)) + dblock
    smb = header + body
    return b"\x00" + struct.pack(">I", len(smb))[1:] + smb


SMB2_NEGOTIATE = bytes.fromhex(
    "fe534d4240000100000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "2400010000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000200000202021002220224020000")


def smb_probe(ip, res, t, port=445):
    """ตรวจ SMBv1 เปิดไหม + บังคับ signing ไหม / SMBv1 enabled? signing required?"""
    # 1) SMBv1: ส่ง negotiate ที่มีเฉพาะ dialect เก่า
    smbv1 = None
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.sendall(smb1_negotiate(["NT LM 0.12"]))
            data = recv_nbss(s)
        if data and data[:4] == b"\xffSMB" and data[4] == 0x72 and len(data) >= 37:
            status = struct.unpack("<I", data[5:9])[0]
            dialect_index = struct.unpack("<H", data[37:39])[0] if len(data) >= 39 else 0xFFFF
            smbv1 = status == 0 and dialect_index != 0xFFFF
        elif data and data[:4] == b"\xfeSMB":
            smbv1 = False                    # ตอบ SMB2 แทน = ปิด SMBv1 แล้ว
    except OSError:
        pass
    if smbv1:
        res.add("windows.smbv1", t, "SMB1 NEGOTIATE accepted (NT LM 0.12)")
    elif smbv1 is False:
        res.ok("ปิด SMBv1 แล้ว (ตอบด้วย SMB2)", t)

    # 2) signing: อ่าน SecurityMode จาก SMB2 NEGOTIATE response
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.sendall(b"\x00" + struct.pack(">I", len(SMB2_NEGOTIATE))[1:] + SMB2_NEGOTIATE)
            data = recv_nbss(s)
        if data and data[:4] == b"\xfeSMB" and len(data) >= 68:
            security_mode = struct.unpack("<H", data[66:68])[0]
            required = bool(security_mode & 0x0002)     # SIGNING_REQUIRED
            if required:
                res.ok("SMB บังคับการเซ็น (signing required)", t, f"SecurityMode=0x{security_mode:02x}")
            else:
                res.add("windows.smb_signing", t, f"SecurityMode=0x{security_mode:02x} (signing not required)")
    except OSError:
        pass


def rdp_probe(ip, res, t, port=3389):
    """ถาม RDP ว่าบังคับ NLA ไหม (X.224 negotiation) / does RDP require NLA?"""
    # X.224 Connection Request ขอ 'standard RDP' (PROTOCOL_RDP=0) เพื่อดูว่าเซิร์ฟเวอร์ยอมไหม
    neg_req = b"\x01\x00\x08\x00" + struct.pack("<I", 0)     # type=1, flags, length, requestedProtocols=0
    cr = b"\x0e\xe0\x00\x00\x00\x00\x00" + neg_req           # X.224 CR
    tpkt = b"\x03\x00" + struct.pack(">H", 4 + len(cr)) + cr
    try:
        with socket.create_connection((ip, port), timeout=5) as s:
            s.sendall(tpkt)
            s.settimeout(5)
            data = s.recv(512)
    except OSError:
        return
    if not data or len(data) < 19 or data[0] != 0x03 or data[5] != 0xd0:
        res.note("RDP เปิดอยู่แต่ไม่ตอบการเจรจา X.224 — ตรวจ NLA เองในเครื่อง", t)
        return
    # rdpNegRsp/rdpNegFailure อยู่หลัง TPKT(4)+X.224 CC header(7) / after TPKT + X.224 CC header
    body = data[11:]
    if body and body[0] == 0x02 and len(body) >= 8:
        selected = struct.unpack("<I", body[4:8])[0]
        if selected == 0:                   # PROTOCOL_RDP — ไม่บังคับ NLA/TLS
            res.add("windows.rdp_no_nla", t, "server accepted PROTOCOL_RDP (no NLA/TLS)")
        else:
            names = {1: "TLS", 2: "CredSSP/NLA", 8: "RDSTLS"}
            res.ok("RDP บังคับ TLS/NLA", t, names.get(selected, f"protocol {selected}"))
    elif body and body[0] == 0x03 and len(body) >= 8:
        res.ok("RDP ปฏิเสธการเชื่อมต่อแบบไม่มี NLA (บังคับ NLA)", t, "rdpNegFailure (SSL/NLA required)")


def run(target, opts):
    if not target:
        raise SystemExit(_("ระบุ IP ของเครื่อง Windows เช่น ./seccheck.py windows 192.168.1.20"))
    scope.check(target)
    res = Result("windows", target)
    ports = {p: net.tcp_state(target, p, timeout=1.5) for p in (139, 445, 3389)}
    if ports[445] == "open":
        res.add("windows.smb_exposed", f"{target}:445")
        smb_probe(target, res, f"{target}:445")
    if ports[139] == "open":
        res.add("windows.netbios", f"{target}:139")
    if ports[3389] == "open":
        res.add("windows.rdp_exposed", f"{target}:3389")
        rdp_probe(target, res, f"{target}:3389")
    if all(st != "open" for st in ports.values()):
        res.note("ไม่พบพอร์ต Windows (139/445/3389) เปิดบนเครื่องนี้", target)
    res.note("ตรวจแบบเจรจาโปรโตคอลเท่านั้น — ไม่ล็อกอิน ไม่เดารหัส ไม่ส่ง exploit")
    return res.done()
