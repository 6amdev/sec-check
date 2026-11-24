"""
ทดสอบตรรกะ TLS ที่เคยรายงานผิด (regression) / regression tests for the TLS false-positive fixes

ไม่ต้องต่อเน็ต — ทดสอบเฉพาะตรรกะการตัดสิน / no network; pure decision logic only.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checks import tls  # noqa: E402


class KeyWeak(unittest.TestCase):
    def test_rsa(self):
        self.assertTrue(tls.key_weak(1024, "rsa"))
        self.assertFalse(tls.key_weak(2048, "rsa"))
        self.assertFalse(tls.key_weak(4096, "rsa"))

    def test_ec_not_flagged(self):
        # บั๊กเดิม: EC 256-bit โดนหาว่าอ่อน — ต้องไม่อ่อน / the old false positive
        self.assertFalse(tls.key_weak(256, "ec"))
        self.assertFalse(tls.key_weak(384, "ec"))
        self.assertTrue(tls.key_weak(160, "ec"))

    def test_none(self):
        self.assertFalse(tls.key_weak(None, "rsa"))


class WeakCipherRegex(unittest.TestCase):
    def test_flags_weak(self):
        for name in ("ECDHE-RSA-RC4-SHA", "DES-CBC3-SHA", "RC4-MD5", "NULL-SHA", "EXP-DES-CBC-SHA"):
            self.assertTrue(tls.WEAK_CIPHER_RE.search(name), name)

    def test_strong_not_flagged(self):
        # บั๊กเดิม: TLS1.3 ตกไปใช้ cipher แข็งแต่ถูกนับว่า 'อ่อนผ่าน' — ชื่อ cipher แข็งต้องไม่ match
        for name in ("TLS_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384",
                     "ECDHE-RSA-CHACHA20-POLY1305", "TLS_CHACHA20_POLY1305_SHA256"):
            self.assertIsNone(tls.WEAK_CIPHER_RE.search(name), name)


if __name__ == "__main__":
    unittest.main()
