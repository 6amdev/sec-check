"""
โมดูล tls — ตรวจความแข็งแรงของ TLS/SSL บนบริการของตัวเอง / audit TLS/SSL on your own service

ทำแบบ handshake ปกติ (ไม่ส่ง payload โจมตี): เปิดการเชื่อมต่อด้วยเวอร์ชัน/ชุด cipher ต่างๆ เพื่อดูว่า
เซิร์ฟเวอร์ยอมรับอะไรบ้าง แล้วอ่านใบรับรองมาตรวจวันหมดอายุ/ชื่อ/ผู้ออก
A normal handshake only (no attack payloads): it offers various versions/cipher sets to see what the
server accepts, then reads the certificate to check expiry, hostname and issuer.

stdlib ล้วน · ถ้ามี openssl จะใช้ดูขนาดกุญแจ/อัลกอริทึมลายเซ็นเพิ่ม (ไม่มีก็ยังทำงานได้)
Standard library only; if `openssl` is present it also reports key size / signature algorithm.
"""
import re
import shutil
import socket
import ssl
import subprocess
import urllib.parse
from datetime import datetime, timezone

from core import net, scope
from core.finding import Result, T
from i18n import _

PROTOCOLS = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]
# ชุด cipher ที่ถือว่าอ่อน (ชื่อ OpenSSL) / cipher groups considered weak
WEAK_CIPHERS = {"RC4": "RC4", "3DES": "3DES", "DES": "DES-CBC", "NULL": "eNULL:aNULL", "EXPORT": "EXPORT",
                "MD5": "MD5"}


def split_target(target):
    t = target if "://" in target else "https://" + target
    u = urllib.parse.urlsplit(t)
    return u.hostname, (u.port or 443)


# ชื่อ cipher ที่อ่อน (DES ครอบทั้ง single-DES และ 3DES/DES-CBC3 · ไม่มี cipher แข็งตัวใดมีคำว่า DES)
WEAK_CIPHER_RE = re.compile(r"RC4|DES|NULL|EXPORT|EXP-|MD5|RC2|IDEA|-ANON|ADH", re.I)


def key_weak(bits, keytype):
    """กุญแจอ่อนไหม — เกณฑ์ต่างกันตามชนิด: RSA/DSA <2048, EC(DSA) <256 / weak-key rule by key type"""
    return bool(bits) and bits < (256 if keytype == "ec" else 2048)


def accepts_cipher(host, port, cipher, timeout=5):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # สำคัญ: TLS 1.3 ไม่สน cipher list ที่ตั้ง — ต้องจำกัดที่ TLS 1.2 ไม่งั้นจะ false positive
        # (เซิร์ฟเวอร์ตกไปใช้ TLS 1.3 cipher แข็งแต่ handshake สำเร็จ ทำให้ดูเหมือน cipher อ่อนผ่าน)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(cipher + ":@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None                     # OpenSSL ของเราไม่มี cipher ชุดนี้ให้ลอง
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                neg = (s.cipher() or ("",))[0]
                return bool(WEAK_CIPHER_RE.search(neg))   # ยืนยันว่า cipher ที่เจรจาได้อ่อนจริงๆ
    except ssl.SSLError:
        return False
    except OSError:
        return None


def verify_result(host, port, timeout=6):
    """ลองเชื่อมแบบตรวจสอบเต็ม → (ok, reason) / full verification → (ok, reason-string)"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as e:
        return False, (e.verify_message or str(e)).lower()
    except ssl.SSLError as e:
        return False, str(e).lower()
    except OSError as e:
        return None, str(e)


def peer_cert(host, port, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.getpeercert(), s.version()
    except OSError:
        return None, None


def openssl_cert_info(host, port):
    """ขนาดกุญแจ + อัลกอริทึมลายเซ็น (ถ้ามี openssl) / key size + signature algo via openssl, if present"""
    if not shutil.which("openssl"):
        return {}
    try:
        p = subprocess.run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
                           input="", capture_output=True, text=True, timeout=10)
        p2 = subprocess.run(["openssl", "x509", "-noout", "-text"], input=p.stdout,
                            capture_output=True, text=True, timeout=10)
        out = p2.stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    info = {}
    m = re.search(r"Signature Algorithm:\s*(\S+)", out)
    if m:
        info["sig"] = m.group(1)
    m = re.search(r"Public-Key:\s*\((\d+) bit\)", out)
    if m:
        info["bits"] = int(m.group(1))
    if re.search(r"id-ecPublicKey|ecPublicKey|Public Key Algorithm:\s*id-ec", out):
        info["keytype"] = "ec"            # ECDSA/ECC — 256 บิตถือว่าแข็ง (ไม่ใช่เกณฑ์ RSA)
    elif "rsaEncryption" in out:
        info["keytype"] = "rsa"
    return info


def run(target, opts):
    scope.check(target if "://" in target else f"https://{target}")
    host, port = split_target(target)
    res = Result("tls", f"{host}:{port}")
    if net.tcp_state(host, port, timeout=4) != "open":
        res.note("เชื่อมต่อ TLS ไม่ได้ (พอร์ตไม่เปิด?)", f"{host}:{port}")
        return res.done()

    # เวอร์ชันโปรโตคอล / protocol versions
    supported = []
    for name, ver in PROTOCOLS:
        if ver is None:
            continue
        acc = net.tls_accepts(host, port, ver)
        if acc:
            supported.append(name)
            if name == "SSLv3":
                res.add("tls.sslv3", f"{host}:{port}")
            elif name in ("TLS 1.0", "TLS 1.1"):
                res.add("tls.old_protocol", f"{host}:{port}", T("เซิร์ฟเวอร์ยอมรับ {v}", v=name))
    if "TLS 1.2" in supported or "TLS 1.3" in supported:
        res.ok("รองรับ TLS รุ่นใหม่", f"{host}:{port}", ", ".join(supported))
    if "TLS 1.3" not in supported:
        res.add("tls.no_tls13", f"{host}:{port}", ", ".join(supported) or "-")
    res.table("เวอร์ชัน TLS ที่เซิร์ฟเวอร์ยอมรับ", ["เวอร์ชัน", "สถานะ"],
              [[n, "✔" if n in supported else "✘"] for n, v in PROTOCOLS if v is not None])

    # cipher อ่อน / weak ciphers
    weak = [label for label, spec in WEAK_CIPHERS.items() if accepts_cipher(host, port, spec)]
    if weak:
        res.add("tls.weak_cipher", f"{host}:{port}", ", ".join(weak))
    else:
        res.ok("ไม่พบ cipher อ่อนที่ทดสอบ (RC4/3DES/DES/NULL/EXPORT/MD5)", f"{host}:{port}")

    # ใบรับรอง / certificate
    ok, reason = verify_result(host, port)
    cert, ver = peer_cert(host, port)
    if ok:
        res.ok("ใบรับรองถูกต้องและเชื่อถือได้", f"{host}:{port}", ver or "")
    elif ok is False:
        if "expired" in reason:
            res.add("tls.cert_expired", f"{host}:{port}", reason[:120])
        elif "self-signed" in reason or "self signed" in reason:
            res.add("tls.cert_self_signed", f"{host}:{port}", reason[:120])
        elif "hostname mismatch" in reason or "doesn't match" in reason or "no match" in reason:
            res.add("tls.cert_hostname_mismatch", f"{host}:{port}", reason[:120])
        else:
            res.add("tls.cert_untrusted", f"{host}:{port}", reason[:120])

    if cert:
        na = cert.get("notAfter")
        if na:
            try:
                exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(na), timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", []) if x).get("organizationName", "")
                detail = T("หมดอายุ {d} (อีก {n} วัน) · ออกโดย {i}", d=exp.strftime("%Y-%m-%d"), n=days, i=issuer)
                if 0 <= days < 30 and ok:
                    res.add("tls.cert_expiring", f"{host}:{port}", detail, "high" if days < 7 else "medium")
                elif ok:
                    res.ok("ใบรับรองยังไม่ใกล้หมดอายุ", f"{host}:{port}", str(detail))
            except ValueError:
                pass

    info = openssl_cert_info(host, port)
    bits, keytype = info.get("bits"), info.get("keytype", "rsa")
    if bits:
        label = f"{keytype.upper()} {bits}-bit"
        if key_weak(bits, keytype):
            res.add("tls.weak_key", f"{host}:{port}", label)
        else:
            res.ok("ขนาดกุญแจเพียงพอ", f"{host}:{port}", label)
    if info.get("sig") and "sha1" in info["sig"].lower():
        res.add("tls.sha1_sig", f"{host}:{port}", info["sig"])

    return res.done()
