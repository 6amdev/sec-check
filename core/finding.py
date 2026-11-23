"""
ผลการตรวจ / Check results

Finding = สิ่งที่ควรแก้ 1 ข้อ (อ้างถึง id ในฐานความรู้ knowledge/*.json)
Passed  = สิ่งที่ตรวจแล้วผ่าน (แสดงไว้ให้เห็นว่าเราตรวจอะไรไปบ้าง — ได้เรียนรู้ทั้งข้อดีและข้อเสีย)
Note    = ข้อความอธิบาย/ข้อที่ตรวจไม่ได้ (เช่น ต้องใช้ sudo)
"""
import time
from dataclasses import dataclass, field, asdict

from i18n import _


class T:
    """ข้อความที่แปลตอนแสดงผล (รายงานมีทั้งไทย/อังกฤษ) / text translated when rendered, not when found"""

    def __init__(self, text, **kw):
        self.text, self.kw = text, kw

    def __str__(self):
        return _(self.text, **self.kw)

    def __add__(self, other):
        return Ev([self, other])

    def __radd__(self, other):
        return Ev([other, self])


class Ev(list):
    """หลายส่วนต่อกัน / several parts joined"""

    def __str__(self):
        return "".join(str(p) for p in self)

    def __add__(self, other):
        return Ev(list(self) + [other])

    def __radd__(self, other):
        return Ev([other] + list(self))


SEVERITIES = ["critical", "high", "medium", "low", "info"]
PENALTY = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}


@dataclass
class Finding:
    id: str                 # knowledge-base id, e.g. "web.git_exposed"
    target: str             # what was checked (URL, ip:port, file …)
    evidence: object = ""   # what we actually saw (str or T; never secrets — values are redacted)
    severity: str = ""      # empty = default severity from the knowledge base


@dataclass
class Passed:
    label: str              # Thai source text, translated via i18n
    target: str = ""
    detail: object = ""


@dataclass
class Result:
    module: str             # web / lan / host / router
    target: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    findings: list = field(default_factory=list)
    passed: list = field(default_factory=list)
    notes: list = field(default_factory=list)      # (Thai source text, detail)
    tables: list = field(default_factory=list)     # extra tables: {"title", "cols", "rows"}
    manual: list = field(default_factory=list)     # knowledge ids the user should check by hand

    def add(self, id, target, evidence="", severity=""):
        self.findings.append(Finding(id, str(target), evidence, severity))

    def ok(self, label, target="", detail=""):
        self.passed.append(Passed(label, str(target), detail))

    def note(self, text, detail=""):
        self.notes.append((text, str(detail)))

    def table(self, title, cols, rows):
        self.tables.append({"title": title, "cols": cols, "rows": rows})

    def done(self):
        self.finished = time.time()
        return self

    def to_dict(self):
        d = asdict(self)
        for f in d["findings"]:
            f["evidence"] = str(f["evidence"])
        for p in d["passed"]:
            p["detail"] = str(p["detail"])
        d["notes"] = [list(n) for n in self.notes]
        return d


def effective_severity(f, kb):
    return f.severity or kb.get(f.id, {}).get("severity", "info")


def score(results, kb):
    """คะแนน 0-100 — หักตามความรุนแรง (นับ 1 ครั้งต่อ id ต่อเป้าหมาย) / score, one penalty per id per target"""
    seen, total = set(), 100
    for r in results:
        for f in r.findings:
            key = (f.id, f.target.split("/")[0] if r.module == "web" else f.target)
            if key in seen:
                continue
            seen.add(key)
            total -= PENALTY.get(effective_severity(f, kb), 0)
    return max(0, total)


def grade(points):
    for g, minimum in (("A", 90), ("B", 75), ("C", 55), ("D", 35)):
        if points >= minimum:
            return g
    return "F"
