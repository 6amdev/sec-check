#!/usr/bin/env python3
"""
หน้าเว็บ sec-check / sec-check web UI  (เสิร์ฟด้วย Python ล้วน ไม่มี build step — เหมือน disk-check)

  ./web.sh                      เปิดที่ 127.0.0.1:8770 (เฉพาะเครื่องนี้)
  ./web.sh --host 0.0.0.0 --pin 1234   เปิดให้ดูจากมือถือในวงแลน (ตั้ง PIN)

หน้า: Dashboard · Scan (สั่งสแกน เห็นผลสด) · Network Map · Report · Targets(allow-list) · History
ความปลอดภัย: สแกนได้เฉพาะเป้าใน scope.json เท่านั้น (เหมือน CLI) · non-destructive · มีคำเตือนที่หน้าแรก

Phase 1 ตามดีไซน์ (docs/DESIGN.md): Dashboard/Scan/Map + SQLite + i18n. REST API/MCP เป็นเฟสถัดไป.
"""
import argparse
import html
import io
import threading
import time
import urllib.parse
import contextlib
import http.cookies
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import i18n
from i18n import _, using
from core import VERSION, db, kb, netmap, report, scope
from core.finding import Result, SEVERITIES, grade, score

E = html.escape
MODULES = {"host": "เครื่องนี้ (Linux)", "lan": "เครือข่าย LAN", "web": "เว็บไซต์", "router": "เราเตอร์ / Wi-Fi", "wifi": "Wi-Fi", "tls": "TLS/SSL"}
JOBS = {}                      # job_id -> dict(status, log, scan_id, error, module, target)
SCAN_LOCK = threading.Lock()   # สแกนทีละงาน / one scan at a time
SESSIONS = set()
PIN = None

PAGE_CSS = report.CSS + """
.nav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 20px}
.nav a{padding:7px 14px;border-radius:10px;background:var(--card);border:1px solid var(--line);
color:var(--fg);text-decoration:none;font-weight:600;font-size:14px}
.nav a.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.warn{background:#f59e0b18;border:1px solid #f59e0b55;border-radius:12px;padding:12px 16px;margin-bottom:18px;font-size:13.5px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0}
@media(max-width:700px){.kpis{grid-template-columns:1fr 1fr}}
.kpi{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c,#243049);border-radius:14px;padding:12px 14px}
.kpi b{display:block;font-size:26px}.kpi span{font-size:12px;color:var(--mut)}
.btn{display:inline-block;cursor:pointer;border:1px solid var(--acc);background:var(--acc);color:#fff;
border-radius:10px;padding:9px 16px;font:600 14px inherit;text-decoration:none;margin:4px 6px 4px 0}
.btn.ghost{background:transparent;color:var(--acc)}
select,input{font:inherit;padding:8px 10px;border-radius:9px;border:1px solid var(--line);
background:var(--card);color:var(--fg)}
.mapbox{background:#0c1322;border:1px solid var(--line);border-radius:16px;padding:8px;overflow:hidden}
svg{width:100%;height:auto;display:block}.node{cursor:pointer}.node .emoji{font-size:30px}
.node .ipl{fill:#cdd6ea;font-size:13px;font-weight:700}.hub text{fill:#cdd6ea}.hub .t{font-size:13px;fill:#9fb0d0}
.maplayout{display:grid;grid-template-columns:1fr 300px;gap:16px}@media(max-width:860px){.maplayout{grid-template-columns:1fr}}
.cards{display:flex;flex-direction:column;gap:8px;max-height:720px;overflow:auto}
.card.hl{outline:2px solid var(--c)}.ch{display:flex;gap:9px;align-items:center}.ch .ico{font-size:22px}
.ch small{color:var(--mut);font-family:ui-monospace,monospace;font-size:12px}
.ports{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.port{font-family:ui-monospace,monospace;font-size:11.5px;background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:2px 7px}
.log{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:12px;white-space:pre-wrap;
font-family:ui-monospace,monospace;font-size:12.5px;max-height:320px;overflow:auto}
table.hist{width:100%;border-collapse:collapse}.hist td,.hist th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left}
"""


def layout(title, active, body_html, lang):
    nav = "".join(f'<a href="{href}?lang={lang}" class="{"on" if active == key else ""}">{E(_(label))}</a>'
                  for key, href, label in (
                      ("dash", "/", "Dashboard"), ("scan", "/scan", "สั่งสแกน"), ("map", "/map", "แผนที่"),
                      ("findings", "/findings", "ช่องโหว่"), ("learn", "/learn", "เรียนรู้"),
                      ("targets", "/targets", "เป้าหมาย"), ("history", "/history", "ประวัติ"),
                      ("settings", "/settings", "ตั้งค่า")))
    other = "en" if lang == "th" else "th"
    return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>sec-check · {E(_(title))}</title>
<style>{PAGE_CSS}</style></head><body><div class="wrap">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
<h1 style="margin:0">🛡️ sec-check</h1><a class="btn ghost" href="?lang={other}">{'EN' if lang == 'th' else 'ไทย'}</a></div>
<p class="mut" style="margin:4px 0 16px">{E(_('ตรวจหาช่องโหว่ระบบของตัวเอง แล้วอุดให้แน่น'))}</p>
<div class="nav">{nav}</div>{body_html}
<p class="mut" style="margin-top:40px;font-size:12px;text-align:center">sec-check {VERSION} · {E(_('ทดสอบเฉพาะระบบที่เป็นเจ้าของหรือได้รับอนุญาต'))}</p>
</div><script>
document.querySelectorAll('.node').forEach(n=>{{const ip=n.dataset.ip,c=document.querySelector('.card[data-ip="'+ip+'"]');
const on=()=>{{document.querySelectorAll('.card').forEach(x=>x.classList.remove('hl'));if(c){{c.classList.add('hl');c.scrollIntoView({{block:'nearest'}});}}}};
n.addEventListener('mouseenter',on);n.addEventListener('click',on);n.addEventListener('focus',on);}});
</script></body></html>"""


def dash(lang):
    last = db.latest()
    warn = f'<div class="warn">⚠️ {E(_("ใช้ตรวจเฉพาะระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตเท่านั้น — การสแกนระบบของผู้อื่นโดยไม่ได้รับอนุญาตผิดกฎหมาย"))}</div>'
    tgs = scope.load()
    allow = f'<p>{E(_("เป้าหมายที่อนุญาต"))}: <b>{len(tgs)}</b> · <a class="btn ghost" href="/targets?lang={lang}">{E(_("จัดการ"))}</a></p>'
    if not last:
        body = (warn + f'<div class="card"><h2 style="margin-top:0">{E(_("ยังไม่มีผลสแกน"))}</h2>'
                f'<p>{E(_("เริ่มจากตรวจเครื่องนี้ หรือสแกนวงแลนของคุณ"))}</p>'
                f'<a class="btn" href="/scan?lang={lang}">{E(_("สั่งสแกน"))}</a></div>' + allow)
        return body
    c = db.counts(last["id"])
    g = last["grade"]
    kpi = "".join(f'<div class="kpi" style="--c:{netmap.SEV_COLOR[s]}"><b>{c[s]}</b><span>{E(report.sev_label(s, lang))}</span></div>'
                  for s in SEVERITIES)
    body = (warn + f'''<div class="card" style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
<div class="grade g{g}" style="width:92px;height:92px;border-radius:50%;display:grid;place-items:center;font-size:40px;font-weight:800;color:#fff">{g}</div>
<div style="flex:1;min-width:200px"><h2 style="margin:0">{E(_("ผลล่าสุด"))}: {last['score']}/100</h2>
<p class="mut">{E(last['modules'])} · {E(last['target'][:80])}<br>{time.strftime('%Y-%m-%d %H:%M', time.localtime(last['started']))}</p></div>
<div><a class="btn" href="/scan?lang={lang}">{E(_("สแกนอีกครั้ง"))}</a>
<a class="btn ghost" href="/report/{last['id']}?lang={lang}">{E(_("ดูรายงานเต็ม"))}</a></div></div>
<div class="kpis">{kpi}</div>''' + allow)
    return body


def targets_page(lang, msg="", err=""):
    rows = "".join(f'''<tr><td class="mono">{E(e["target"])}</td><td>{E(e.get("kind",""))}</td>
<td>{E(e.get("note",""))}</td><td class="mut">{E(e.get("confirmed",""))}</td>
<td><form method="post" action="/targets?lang={lang}" style="margin:0"><input type="hidden" name="remove" value="{E(e["target"])}">
<button class="btn ghost" style="padding:4px 10px">{E(_("ลบ"))}</button></form></td></tr>'''
                   for e in scope.load())
    note = (f'<div class="warn" style="background:#22c55e18;border-color:#22c55e55">✅ {E(msg)}</div>' if msg else "") + \
           (f'<div class="warn">⛔ {E(err)}</div>' if err else "")
    return f'''{note}<div class="card"><h2 style="margin-top:0">{E(_("เป้าหมายที่อนุญาต (allow-list)"))}</h2>
<p class="mut">{E(_("127.0.0.0/8 · localhost — เครื่องนี้ อนุญาตเสมอ"))}</p>
<table class="hist"><tr><th>{E(_("เป้าหมาย"))}</th><th>kind</th><th>note</th><th>{E(_("ยืนยันเมื่อ"))}</th><th></th></tr>{rows}</table></div>
<div class="card"><h3 style="margin-top:0">{E(_("เพิ่มเป้าหมาย"))}</h3>
<form method="post" action="/targets?lang={lang}">
<p><input name="target" placeholder="192.168.1.0/24  |  https://example.com" style="width:320px;max-width:100%">
<input name="note" placeholder="{E(_('หมายเหตุ'))}" style="width:180px;max-width:100%"></p>
<p><label style="display:flex;gap:8px;align-items:flex-start;font-size:13.5px;color:var(--mut)">
<input type="checkbox" name="confirm" value="1" style="margin-top:3px">
{E(_("ข้าพเจ้ายืนยันว่าเป็นเจ้าของระบบนี้ หรือได้รับอนุญาตเป็นลายลักษณ์อักษรให้ทดสอบ — การสแกนระบบของผู้อื่นโดยไม่ได้รับอนุญาตผิดกฎหมาย"))}</label></p>
<button class="btn" type="submit">{E(_("เพิ่มเข้า allow-list"))}</button></form>
<p class="mut" style="font-size:12.5px">{E(_("ทำแบบเดียวกันใน CLI ได้: ./seccheck.py scope add <เป้าหมาย>"))}</p></div>'''


LEVEL_TITLE = {1: "🟢 Level 1 — พื้นฐาน (ของเปิดโล่ง)", 2: "🟡 Level 2 — โปรโตคอล/ตั้งค่าอ่อน",
               3: "🟠 Level 3 — เวอร์ชันเก่า / ข้อมูลรั่ว / hardening", 4: "🔴 Level 4 — ตั้งค่าพลาดเชิงลึก",
               5: "⚫ Level 5 — ขั้นสูง (lab / เครือข่ายตัวเอง)"}
CURRICULUM_URL = "https://github.com/6amdev/sec-check/blob/main/docs/CURRICULUM.md"


def learn_page(lang, focus=""):
    k = kb.load()
    by_level = {}
    for id, e in k.items():
        by_level.setdefault(e.get("level", 3), []).append((id, e))
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    sev_order["check"] = 9
    out = [f'''<div class="card"><h2 style="margin-top:0">🎓 {E(_("เรียนรู้: เจาะ → ป้องกัน"))}</h2>
<p>{E(_("บทเรียนจัดกลุ่มตามระดับความยาก 1–5 — เริ่มจากของเปิดโล่งที่เจอง่าย ไล่ไปจนถึงขั้นสูง แต่ละข้อบอก คืออะไร · ผู้โจมตีใช้ยังไง · วิธีแก้"))}</p>
<p class="mut">{E(_("หลักสูตรฉบับเต็ม (รวมเทคนิคขั้นสูงที่ยังไม่ตรวจอัตโนมัติ เช่น SQLi/XSS บนเป้าฝึก):"))}
<a href="{CURRICULUM_URL}" target="_blank" rel="noopener">docs/CURRICULUM.md ↗</a></p></div>''']
    for lvl in (1, 2, 3, 4, 5):
        items = sorted(by_level.get(lvl, []), key=lambda it: sev_order.get(it[1].get("severity"), 5))
        if not items:
            continue
        out.append(f'<h2 id="level-{lvl}">{E(_(LEVEL_TITLE[lvl]))} <span class="mut" style="font-size:14px">({len(items)})</span></h2>')
        for id, e in items:
            t = lambda f: fmt(kb.text(e, f, lang))
            sev = e.get("severity", "info")
            hl = ' style="outline:2px solid var(--acc)"' if id == focus else ""
            out.append(f'''<div class="card" id="lesson-{E(id)}"{hl}>
<div style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap">
<span class="pill {sev}">{E(report.sev_label(sev, lang))}</span>
<b style="flex:1;min-width:180px">{t("title")}</b>
<span class="mut" style="font-size:12px">{E(e.get("tag",""))} · <span class="mono">{E(id)}</span></span></div>
<div class="grid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:8px">
<div class="box"><b style="color:var(--mut);font-size:12px">{E(_("คืออะไร"))}</b><br>{t("what")}</div>
<div class="box"><b style="color:var(--mut);font-size:12px">{E(_("ผู้โจมตีใช้ยังไง"))}</b><br>{t("attack")}</div>
<div class="box"><b style="color:var(--mut);font-size:12px">{E(_("วิธีแก้"))}</b><br>{t("fix")}</div></div></div>''')
    return "<style>.grid{grid-template-columns:repeat(3,1fr)}@media(max-width:760px){.grid{grid-template-columns:1fr}}" \
           ".box{background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:13px}</style>" \
           + "\n".join(out)


def fmt(s):
    return report.fmt(s)


def settings_page(lang):
    return f'''<div class="card"><h2 style="margin-top:0">⚙️ {E(_("ตั้งค่า"))}</h2>
<table class="hist">
<tr><td>{E(_("ภาษา"))}</td><td><a class="btn ghost" href="?lang=th">ไทย</a> <a class="btn ghost" href="?lang=en">English</a></td></tr>
<tr><td>{E(_("ธีม"))}</td><td class="mut">{E(_("ตามระบบ (สว่าง/มืด) อัตโนมัติ"))}</td></tr>
<tr><td>PIN</td><td class="mut">{E(_("ตั้งตอนเปิดเซิร์ฟเวอร์") + ": ./web.sh --pin 1234")}  ·  {E(_("สถานะตอนนี้") + ": " + (_("ตั้งแล้ว") if PIN else _("ไม่ได้ตั้ง")))}</td></tr>
<tr><td>{E(_("เปิดให้วงแลนเข้าถึง"))}</td><td class="mut">./web.sh --host 0.0.0.0</td></tr>
<tr><td>{E(_("ลองรหัส default"))}</td><td class="mut">{E(_("เลือกตอนสั่งสแกน (ติ๊กในหน้า Scan) — อ่านอย่างเดียว จำกัดอัตรา"))}</td></tr>
</table>
<p class="mut" style="font-size:12.5px">{E(_("ระดับความยาก (1–5) และการเทียบ 🔴→🟢 ย้อนหลัง จะเพิ่มในเฟสถัดไป"))}</p></div>'''


def history_page(lang):
    out = []
    for r in db.recent(50):
        prev = db.previous_like(r["id"])
        cmp_link = (f'<a class="btn ghost" href="/compare/{prev}/{r["id"]}?lang={lang}">{E(_("เทียบก่อน/หลัง"))}</a>'
                    if prev else "")
        out.append(f'''<tr><td>{r['id']}</td><td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(r['started']))}</td>
<td>{E(r['modules'])}</td><td class="mono">{E(r['target'][:44])}</td><td><b>{r['score']}</b> ({E(r['grade'])})</td>
<td><a class="btn ghost" href="/report/{r['id']}?lang={lang}">{E(_("รายงาน"))}</a> {cmp_link}</td></tr>''')
    inner = "".join(out) or f'<tr><td colspan="6" class="mut">{E(_("ยังไม่มีประวัติ"))}</td></tr>'
    return (f'<div class="card"><h2 style="margin-top:0">{E(_("ประวัติการสแกน (เทียบก่อน/หลังแก้)"))}</h2>'
            f'<table class="hist"><tr><th>#</th><th>{E(_("เวลา"))}</th><th>module</th>'
            f'<th>{E(_("เป้าหมาย"))}</th><th>{E(_("คะแนน"))}</th><th></th></tr>{inner}</table></div>')


def compare_page(old_id, new_id, lang):
    old, new = db.get(old_id), db.get(new_id)
    if not old or not new:
        return f'<div class="card">{E(_("ไม่พบสแกนที่จะเทียบ"))}</div>'
    d = db.compare(old_id, new_id)

    def block(title, items, icon, color):
        if not items:
            return ""
        rows = "".join(f'<div class="find" style="border-left:4px solid {color};padding-left:10px;margin:6px 0">'
                       f'<b>{icon} {E(kb.text(kb.get(f["check_id"]), "title", lang))}</b> '
                       f'<span class="pill {f["severity"]}">{E(report.sev_label(f["severity"], lang))}</span>'
                       f'<br><span class="mono mut">{E(f["target"])}</span></div>' for f in items)
        return f'<div class="card"><h3 style="margin-top:0">{icon} {E(title)} ({len(items)})</h3>{rows}</div>'

    head = (f'<div class="card"><h2 style="margin-top:0">{E(_("เทียบก่อน/หลังแก้"))}</h2>'
            f'<p class="mut">#{old_id} ({old["score"]}/100, {time.strftime("%m-%d %H:%M", time.localtime(old["started"]))}) '
            f'→ #{new_id} ({new["score"]}/100, {time.strftime("%m-%d %H:%M", time.localtime(new["started"]))}) · '
            f'{E(new["target"][:70])}</p>'
            f'<p><b style="font-size:22px;color:{"#22c55e" if new["score"]>=old["score"] else "#ef4444"}">'
            f'{new["score"]-old["score"]:+d}</b> {E(_("คะแนน"))}</p></div>')
    return (head + block(_("แก้แล้ว (🔴→🟢)"), d["fixed"], "🟢", "#22c55e")
            + block(_("โผล่ใหม่"), d["new"], "🔴", "#ef4444")
            + block(_("ยังเจาะได้อยู่"), d["still"], "🔴", "#f59e0b")
            + (f'<div class="card mut">{E(_("ไม่มีการเปลี่ยนแปลงระหว่างสองครั้งนี้"))}</div>'
               if not (d["fixed"] or d["new"] or d["still"]) else ""))


def scan_form(lang):
    webtargets = "".join(f'<option value="web:{E(e["target"])}">{E(_("เว็บ"))}: {E(e["target"])}</option>'
                         for e in scope.load() if e["kind"] in ("url", "host") and not e["target"].startswith("*."))
    lantargets = "".join(f'<option value="lan:{E(e["target"])}">{E(_("วงแลน"))}: {E(e["target"])}</option>'
                         for e in scope.load() if e["kind"] == "net")
    tlstargets = "".join(f'<option value="tls:{E(e["target"])}">TLS: {E(e["target"])}</option>'
                         for e in scope.load() if e["kind"] in ("url", "host") and not e["target"].startswith("*."))
    running = next((j for j in JOBS.values() if j["status"] == "running"), None)
    note = f'<div class="warn">{E(_("มีการสแกนกำลังทำงานอยู่ — รอให้เสร็จก่อน"))}</div>' if running else ""
    return f'''{note}<div class="card"><h2 style="margin-top:0">{E(_("สั่งสแกน"))}</h2>
<form method="post" action="/scan?lang={lang}">
<p><label>{E(_("เลือกเป้าหมาย"))}:<br><select name="pick">
<option value="host">{E(_("เครื่องนี้ (Linux) — host audit"))}</option>
<option value="wifi">{E(_("Wi-Fi ที่ต่ออยู่ (passive)"))}</option>
<option value="lan:">{E(_("วงแลนของเครื่องนี้ (อัตโนมัติ)"))}</option>
{lantargets}{webtargets}{tlstargets}
</select></label></p>
<p><label>{E(_("ระดับความยาก"))}: <select name="level">
<option value="5">{E(_("ทั้งหมด (5)"))}</option>
<option value="1">1 — {E(_("ของเปิดโล่ง/เจอง่าย"))}</option>
<option value="2">2 — {E(_("โปรโตคอลอ่อน"))}</option>
<option value="3">3 — {E(_("hardening/ข้อมูลรั่ว"))}</option>
<option value="4">4 — {E(_("ตั้งค่าพลาดเชิงลึก"))}</option>
</select></label></p>
<p><label><input type="checkbox" name="creds" value="1"> {E(_("ลองรหัส default บนหน้า Basic auth (อ่านอย่างเดียว จำกัดอัตรา)"))}</label></p>
<button class="btn" type="submit">{E(_("เริ่มสแกน"))}</button></form>
<p class="mut">{E(_("สแกนได้เฉพาะเป้าหมายใน allow-list · แบบไม่ทำลาย"))}</p></div>'''


def run_job(job_id, pick, creds, level=5):
    job = JOBS[job_id]
    with SCAN_LOCK:
        job["status"] = "running"
        buf = io.StringIO()
        try:
            from checks import host, lan, tls, web, wifi
            opts = argparse.Namespace(delay=0.1, timeout=0.8, max_hosts=1024, default_creds=creds,
                                      passphrase=None, ssid=None)
            with contextlib.redirect_stdout(buf):
                if pick == "host":
                    results = [host.run(None, opts)]
                elif pick == "wifi":
                    results = [wifi.run(None, opts)]
                elif pick.startswith("lan:"):
                    results = [lan.run(pick[4:] or None, opts)]
                elif pick.startswith("web:"):
                    results = [web.run(pick[4:], opts)]
                elif pick.startswith("tls:"):
                    results = [tls.run(pick[4:], opts)]
                else:
                    raise ValueError("unknown target")
            kb.filter_level(results, level)
            job["scan_id"] = db.save(results, level=level)
            report.save(results, HERE / "reports", pick.replace(":", "_") or "scan")
            job["status"] = "done"
        except scope.OutOfScope as e:
            job["status"] = "error"
            job["error"] = str(e)
        except Exception as e:
            job["status"] = "error"
            job["error"] = f"{type(e).__name__}: {e}"
        finally:
            job["log"] = buf.getvalue()


def job_page(job_id, lang):
    job = JOBS.get(job_id)
    if not job:
        return f'<div class="card">{E(_("ไม่พบงานสแกนนี้"))}</div>'
    if job["status"] == "running":
        return (f'<div class="card"><h2 style="margin-top:0">⏳ {E(_("กำลังสแกน…"))}</h2>'
                f'<p class="mut">{E(job["target"])}</p><div class="log">{E(job.get("log","") or _("กำลังเริ่ม…"))}</div>'
                f'<meta http-equiv="refresh" content="2"></div>')
    if job["status"] == "error":
        return f'<div class="card"><h2 style="margin-top:0">⛔ {E(_("สแกนไม่สำเร็จ"))}</h2><div class="log">{E(job["error"])}</div></div>'
    sid = job["scan_id"]
    c = db.counts(sid)
    kpi = "".join(f'<div class="kpi"><b>{c[s]}</b><span>{E(report.sev_label(s, lang))}</span></div>' for s in SEVERITIES)
    return (f'<div class="card"><h2 style="margin-top:0">✅ {E(_("สแกนเสร็จแล้ว"))}</h2>'
            f'<div class="kpis">{kpi}</div>'
            f'<a class="btn" href="/report/{sid}?lang={lang}">{E(_("ดูรายงานเต็ม"))}</a>'
            f'<a class="btn ghost" href="/map?lang={lang}">{E(_("ดูแผนที่"))}</a></div>'
            f'<div class="card"><div class="log">{E(job.get("log",""))}</div></div>')


def map_page(lang):
    con = db.connect()
    try:
        row = con.execute("SELECT report_json FROM scans WHERE modules LIKE '%lan%' ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        con.close()
    if not row:
        return (f'<div class="card"><h2 style="margin-top:0">{E(_("แผนที่เครือข่าย"))}</h2>'
                f'<p>{E(_("ยังไม่มีข้อมูลแผนที่ — สแกน LAN ก่อน"))}</p>'
                f'<a class="btn" href="/scan?lang={lang}">{E(_("สั่งสแกน"))}</a></div>')
    import json
    data = json.loads(row["report_json"])
    res = next(Result.from_dict(r) for r in data["results"] if r["module"] == "lan")
    with using(lang):
        svg = netmap.svg(res, lang)
        cards = netmap.cards(res, lang)
    return (f'<div class="card"><h2 style="margin-top:0">🛰️ {E(_("แผนที่เครือข่ายในบ้าน"))}</h2>'
            f'<p class="mut">{E(res.target)} · {E(_("สแกนแบบไม่ทำลาย"))}</p>'
            f'<div class="maplayout"><div class="mapbox">{svg}</div><div class="cards">{cards}</div></div></div>')


def report_page(scan_id, lang):
    row = db.get(scan_id)
    if not row:
        return None
    import json
    data = json.loads(row["report_json"])
    results = [Result.from_dict(r) for r in data["results"]]
    return report.render(results)


class App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _lang(self, qs):
        return i18n.norm((qs.get("lang", [None])[0])) or "th"

    def _authed(self):
        if not PIN:
            return True
        ck = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "sc" in ck and ck["sc"].value in SESSIONS

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _page(self, title, active, body, lang):
        self._send(layout(title, active, body, lang))

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(u.query)
        lang = self._lang(qs)
        i18n.set_lang(lang)
        path = u.path
        if PIN and not self._authed() and path != "/login":
            return self._login(lang)
        with using(lang):
            if path == "/":
                self._page("Dashboard", "dash", dash(lang), lang)
            elif path == "/scan":
                self._page("Scan", "scan", scan_form(lang), lang)
            elif path.startswith("/scan/"):
                self._page("Scan", "scan", job_page(path.split("/")[-1], lang), lang)
            elif path == "/map":
                self._page("Map", "map", map_page(lang), lang)
            elif path == "/targets":
                self._page("Targets", "targets", targets_page(lang), lang)
            elif path == "/history":
                self._page("History", "history", history_page(lang), lang)
            elif path == "/settings":
                self._page("Settings", "settings", settings_page(lang), lang)
            elif path == "/learn":
                self._page("Learn", "learn", learn_page(lang, qs.get("focus", [""])[0]), lang)
            elif path.startswith("/compare/"):
                parts = path.split("/")
                try:
                    self._page("Compare", "history", compare_page(int(parts[2]), int(parts[3]), lang), lang)
                except (IndexError, ValueError):
                    self._send(layout("Compare", "history", '<div class="card">bad compare</div>', lang), 404)
            elif path == "/findings":
                last = db.latest()
                if last:
                    return self._send("", 303, headers={"Location": f"/report/{last['id']}?lang={lang}"})
                self._page("Findings", "findings",
                           f'<div class="card">{E(_("ยังไม่มีผลสแกน"))} · '
                           f'<a class="btn" href="/scan?lang={lang}">{E(_("สั่งสแกน"))}</a></div>', lang)
            elif path.startswith("/report/"):
                html_doc = report_page(path.split("/")[-1], lang)
                if html_doc:
                    self._send(html_doc)
                else:
                    self._send(layout("Report", "history", f'<div class="card">{E(_("ไม่พบรายงาน"))}</div>', lang), 404)
            elif path == "/login":
                self._login(lang)
            else:
                self._send(layout("404", "dash", '<div class="card">404</div>', lang), 404)

    def _login(self, lang, msg=""):
        body = (f'<div class="card" style="max-width:360px;margin:40px auto"><h2 style="margin-top:0">🔒 PIN</h2>'
                f'{"<p class=warn>"+E(msg)+"</p>" if msg else ""}'
                f'<form method="post" action="/login"><input name="pin" type="password" placeholder="PIN" autofocus> '
                f'<button class="btn" type="submit">{E(_("เข้าสู่ระบบ"))}</button></form></div>')
        self._send(layout("Login", "", body, lang))

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(u.query)
        lang = self._lang(qs)
        i18n.set_lang(lang)
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        if u.path == "/login":
            if PIN and form.get("pin", [""])[0] == PIN:
                tok = secrets.token_hex(16)
                SESSIONS.add(tok)
                return self._send("", 303, headers={"Location": f"/?lang={lang}",
                                                     "Set-Cookie": f"sc={tok}; HttpOnly; SameSite=Lax; Path=/"})
            return self._login(lang, _("PIN ไม่ถูกต้อง"))
        if PIN and not self._authed():
            return self._login(lang)
        if u.path == "/scan":
            if any(j["status"] == "running" for j in JOBS.values()):
                return self._send("", 303, headers={"Location": f"/scan?lang={lang}"})
            pick = form.get("pick", ["host"])[0]
            creds = form.get("creds", [""])[0] == "1"
            try:
                level = max(1, min(5, int(form.get("level", ["5"])[0])))
            except ValueError:
                level = 5
            job_id = secrets.token_hex(6)
            JOBS[job_id] = {"status": "queued", "log": "", "scan_id": None, "error": "",
                            "module": pick, "target": pick}
            threading.Thread(target=run_job, args=(job_id, pick, creds, level), daemon=True).start()
            time.sleep(0.2)
            return self._send("", 303, headers={"Location": f"/scan/{job_id}?lang={lang}"})
        if u.path == "/targets":
            if form.get("remove", [""])[0]:
                scope.remove(form["remove"][0])
                return self._page("Targets", "targets", targets_page(lang, msg=_("ลบแล้ว: {t}", t=form["remove"][0])), lang)
            target = form.get("target", [""])[0].strip()
            note = form.get("note", [""])[0].strip()
            if not target:
                return self._page("Targets", "targets", targets_page(lang, err=_("ต้องระบุเป้าหมาย")), lang)
            if form.get("confirm", [""])[0] != "1":
                return self._page("Targets", "targets",
                                  targets_page(lang, err=_("ต้องติ๊กยืนยันว่าเป็นเจ้าของ/ได้รับอนุญาตก่อน")), lang)
            try:
                scope.normalize(target)
            except Exception:
                return self._page("Targets", "targets", targets_page(lang, err=_("รูปแบบเป้าหมายไม่ถูกต้อง")), lang)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                scope.add(target, note, assume_yes=True)
            return self._page("Targets", "targets", targets_page(lang, msg=_("เพิ่มแล้ว: {t}", t=target)), lang)
        self._send("", 404)


def main(argv=None):
    global PIN
    p = argparse.ArgumentParser(description="sec-check web UI")
    p.add_argument("--host", default="127.0.0.1", help="ที่อยู่ที่ฟัง (0.0.0.0 = เปิดให้ทั้งวงแลน)")
    p.add_argument("--port", type=int, default=8770)
    p.add_argument("--pin", default=os.environ.get("SECCHECK_PIN"), help="ตั้ง PIN ก่อนเข้าเว็บ")
    p.add_argument("--lang", default="th")
    args = p.parse_args(argv)
    PIN = args.pin
    i18n.set_default(args.lang)
    kb.load()
    srv = ThreadingHTTPServer((args.host, args.port), App)
    where = f"http://{args.host}:{args.port}"
    print(f"sec-check web · {where}" + (f"  (PIN {'ตั้งแล้ว' if PIN else 'ไม่ได้ตั้ง'})"))
    if args.host == "0.0.0.0":
        print(_("เปิดให้ทั้งวงแลนเข้าถึง — แนะนำให้ตั้ง --pin"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
