"""
ทดสอบแกนกลาง: การให้คะแนน, ฐานความรู้, cvedb, dnsq / core engine, knowledge base, cvedb, dnsq

    python3 -m unittest discover -s tests
"""
import glob
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import cvedb, dnsq, kb  # noqa: E402
from core.finding import Result, SEVERITIES, effective_severity, grade, score  # noqa: E402


class Scoring(unittest.TestCase):
    def test_grade_bands(self):
        self.assertEqual(grade(100), "A")
        self.assertEqual(grade(90), "A")
        self.assertEqual(grade(89), "B")
        self.assertEqual(grade(0), "F")

    def test_score_penalties_and_dedup(self):
        k = kb.load()
        r = Result("web", "https://x")
        r.add("web.git_exposed", "https://x/.git/HEAD")      # critical -30
        r.add("web.git_exposed", "https://x/.git/config")    # same id+host → ไม่หักซ้ำ
        r.add("web.no_hsts", "https://x/")                   # medium -6
        self.assertEqual(effective_severity(r.findings[0], k), "critical")
        self.assertEqual(score([r], k), 100 - 30 - 6)        # git หักครั้งเดียว

    def test_info_no_penalty(self):
        k = kb.load()
        r = Result("web", "https://x")
        r.add("web.robots_hint", "https://x/robots.txt")     # info
        self.assertEqual(score([r], k), 100)


class KnowledgeIntegrity(unittest.TestCase):
    """ทุกบทเรียนต้องสมบูรณ์และสองภาษา (คุณภาพการเรียนรู้) / every lesson must be well-formed & bilingual"""
    def setUp(self):
        self.k = kb.load()

    def test_all_valid(self):
        valid_sev = set(SEVERITIES) | {"check"}
        for id, e in self.k.items():
            self.assertIn(e.get("severity"), valid_sev, f"{id}: bad severity")
            self.assertIn(e.get("level", 3), (1, 2, 3, 4, 5), f"{id}: bad level")
            for field in ("title", "what", "attack", "fix"):
                v = e.get(field)
                self.assertIsInstance(v, dict, f"{id}.{field} missing")
                self.assertTrue(v.get("th", "").strip(), f"{id}.{field} has no Thai")
                self.assertTrue(v.get("en", "").strip(), f"{id}.{field} has no English")

    def test_ids_unique_across_files(self):
        seen = {}
        for f in glob.glob(str(ROOT / "knowledge" / "*.json")):
            with open(f, encoding="utf-8") as fh:
                ids = json.load(fh)
            for id in ids:
                self.assertNotIn(id, seen, f"duplicate id {id} in {f} and {seen.get(id)}")
                seen[id] = f


class CveDb(unittest.TestCase):
    def test_version_parse(self):
        self.assertEqual(cvedb.parse_version("2.4.29 (Ubuntu)"), (2, 4, 29))
        self.assertEqual(cvedb.parse_version("7.4p1"), (7, 4, 1))

    def test_match(self):
        self.assertTrue(any(e["cve"] == "CVE-2019-0211" for e in cvedb.match("Apache httpd", "2.4.29")))
        self.assertEqual(cvedb.match("apache", "2.4.99"), [])          # ใหม่พอแล้ว ไม่ match
        self.assertTrue(cvedb.match("vsftpd", "2.3.4"))                # exact backdoor
        self.assertEqual(cvedb.match("vsftpd", "3.0.3"), [])

    def test_from_banner(self):
        self.assertEqual(cvedb.from_banner("Apache/2.4.29 (Ubuntu)"), ("apache", "2.4.29"))
        self.assertEqual(cvedb.from_banner("SSH-2.0-OpenSSH_7.4p1")[0], "openssh")


class DnsWire(unittest.TestCase):
    def test_name_roundtrip(self):
        enc = dnsq._encode("_dmarc.example.com")
        name, off = dnsq._read_name(enc, 0)
        self.assertEqual(name, "_dmarc.example.com")
        self.assertEqual(off, len(enc))

    def test_txt_rdata(self):
        raw = b"\x0bv=spf1 -all"                     # length-prefixed string
        self.assertEqual(dnsq._rdata(dnsq.TXT, raw, 0, len(raw)), "v=spf1 -all")


if __name__ == "__main__":
    unittest.main()
