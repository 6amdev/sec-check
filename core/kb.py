"""
ฐานความรู้ / Knowledge base — knowledge/*.json

แต่ละ id มี: severity, tag (OWASP/CWE), title, what (เจออะไร), attack (ผู้โจมตีใช้ยังไง), fix (แก้ยังไง), refs
Each id has: severity, tag, title, what, attack, fix, refs — every text in {"th": ..., "en": ...}
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
_KB = {}


def load():
    if not _KB:
        for f in sorted((HERE / "knowledge").glob("*.json")):
            _KB.update(json.loads(f.read_text(encoding="utf-8")))
    return _KB


def text(entry, field, lang):
    v = entry.get(field, "")
    if isinstance(v, dict):
        return v.get(lang) or v.get("en") or v.get("th") or ""
    return v


def get(id):
    return load().get(id, {"severity": "info", "title": {"th": id, "en": id}})


def level(id):
    """ระดับความยาก 1–5 ของเช็กนี้ / difficulty level of this check (1 = easy win)"""
    return load().get(id, {}).get("level", 3)


def filter_level(results, max_level):
    """เก็บเฉพาะ finding/manual ที่ระดับ <= max_level / keep only findings up to max_level (in place)"""
    if not max_level or max_level >= 5:
        return results
    for r in results:
        r.findings = [f for f in r.findings if level(f.id) <= max_level]
        r.manual = [m for m in r.manual if level(m) <= max_level]
    return results
