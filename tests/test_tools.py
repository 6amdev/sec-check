"""ทดสอบ parser ของโมดูล tools ด้วยตัวอย่างผลจริง (ไม่ต้องติดตั้งเครื่องมือ)
Test the external-tool parsers against sample outputs (no tool install needed).

    python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checks import tools  # noqa: E402

NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.1"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.29"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port>
</ports></host></nmaprun>"""

NUCLEI = ('{"template-id":"tech-detect","info":{"name":"Apache Detect","severity":"info"},"matched-at":"http://x/"}\n'
          'garbage line\n'
          '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical"},'
          '"matched-at":"http://x/cgi-bin/"}')

TESTSSL = ('[{"id":"SSLv3","severity":"HIGH","finding":"offered"},'
           '{"id":"cert_expiration","severity":"OK","finding":"fine"},'
           '{"id":"TLS1_1","severity":"MEDIUM","finding":"offered (deprecated)"}]')

LYNIS = ("warning[]=SSH root login is possible|test:SSH-7412|\n"
         "suggestion[]=Install a file integrity tool|test:FINT-4350|\n"
         "warning[]=No firewall active|test:FIRE-4512|\n")


class ToolParsers(unittest.TestCase):
    def test_nmap(self):
        rows = tools.parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(rows), 2)                      # เฉพาะพอร์ตที่ open
        self.assertEqual(rows[0], ("22", "tcp", "ssh", "OpenSSH", "7.4"))
        self.assertIn(("80", "tcp", "http", "Apache httpd", "2.4.29"), rows)

    def test_nmap_feeds_cve(self):
        from core import cvedb
        rows = tools.parse_nmap_xml(NMAP_XML)
        hits = [e for p, pr, s, prod, ver in rows for e in cvedb.match(prod or s, ver)]
        self.assertTrue(any(e.get("cve") == "CVE-2019-0211" for e in hits))

    def test_nuclei(self):
        rows = tools.parse_nuclei_jsonl(NUCLEI)
        self.assertEqual(len(rows), 2)                      # ข้ามบรรทัดขยะ
        self.assertEqual(rows[1][0], "critical")

    def test_testssl(self):
        rows = tools.parse_testssl_json(TESTSSL)
        ids = [r[1] for r in rows]
        self.assertIn("SSLv3", ids)
        self.assertNotIn("cert_expiration", ids)            # OK ถูกข้าม

    def test_lynis(self):
        rows = tools.parse_lynis_report(LYNIS)
        warns = [d for t, d in rows if t == "warning"]
        self.assertEqual(len(warns), 2)
        self.assertEqual([t for t, d in rows].count("suggestion"), 1)


if __name__ == "__main__":
    unittest.main()
