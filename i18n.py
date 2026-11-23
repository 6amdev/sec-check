"""
ระบบหลายภาษา / Multi-language support

ใช้ข้อความภาษาไทยเป็นต้นฉบับ (key) แล้วแปลด้วยพจนานุกรมใน locales/<lang>*.json
Thai text is the source key; translations live in locales/<lang>*.json ({"ข้อความไทย": "English text"}).

    from i18n import _
    _("ตรวจเสร็จ")                          -> "Done" (en) / "ตรวจเสร็จ" (th)
    _("พบ {n} ลูก", n=3)                     -> "Found 3 disks"
    with using("en"): ...                    -> สลับภาษาชั่วคราว / temporarily switch language

ภาษาที่ใช้ตอนนี้เก็บแบบ contextvar — แต่ละ request ของเว็บตั้งภาษาของตัวเองได้โดยไม่ชนกัน
The current language is a contextvar, so each web request can use its own language safely.
"""
import contextlib
import contextvars
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LANGS = {"th": "ไทย", "en": "English"}
SOURCE = "th"

_default = SOURCE
_current = contextvars.ContextVar("seccheck_lang", default=None)
_catalog = {}


def _load():
    for f in sorted((HERE / "locales").glob("*.json")):
        lang = f.stem.split("_")[0]
        try:
            _catalog.setdefault(lang, {}).update(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[i18n] อ่าน {f.name} ไม่ได้ / cannot read: {e}")


_load()


def norm(lang):
    lang = (lang or "").lower()[:2]
    return lang if lang in LANGS else None


def set_default(lang):
    """ภาษาเริ่มต้นของทั้งโปรแกรม / process-wide default"""
    global _default
    _default = norm(lang) or SOURCE


def set_lang(lang):
    """ภาษาของ context นี้ (เช่น 1 request) / language for the current context"""
    _current.set(norm(lang))


def get_lang():
    return _current.get() or _default


@contextlib.contextmanager
def using(lang):
    token = _current.set(norm(lang) or get_lang())
    try:
        yield
    finally:
        _current.reset(token)


def _(text, **kw):
    """แปลข้อความ (ไม่มีคำแปล = ใช้ภาษาไทย) แล้วแทนค่า {ตัวแปร} / translate, then fill {placeholders}"""
    if not isinstance(text, str):
        return text
    lang = get_lang()
    out = text if lang == SOURCE else _catalog.get(lang, {}).get(text, text)
    if kw:
        try:
            return out.format(**kw)
        except (KeyError, IndexError, ValueError):
            return text.format(**kw)
    return out


def has(text, lang=None):
    """มีคำแปลหรือยัง / is there a translation"""
    lang = norm(lang) or get_lang()
    return lang == SOURCE or text in _catalog.get(lang, {})
