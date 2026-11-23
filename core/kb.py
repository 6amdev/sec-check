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
