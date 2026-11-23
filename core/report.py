"""
รายงาน HTML (ไทย/อังกฤษในไฟล์เดียว สลับได้) + JSON / HTML report (Thai/English toggle in one file) + JSON
"""
import html
import json
import re
import time
from pathlib import Path

from core import VERSION, kb
from core.finding import SEVERITIES, effective_severity, grade, score
from i18n import _, using

E = html.escape
SEV_TH = {"critical": "วิกฤต", "high": "สูง", "medium": "กลาง", "low": "ต่ำ", "info": "ข้อมูล", "check": "ตรวจเอง"}
MODULE_TH = {"web": "เว็บไซต์", "lan": "เครือข่าย LAN", "host": "เครื่องนี้ (Linux)", "router": "เราเตอร์ / Wi-Fi", "wifi": "Wi-Fi", "tls": "TLS/SSL", "windows": "Windows", "camera": "กล้อง/NVR"}

CSS = """
:root{--bg:#0b0f17;--card:#121826;--card2:#182033;--line:#243049;--fg:#e6ebf5;--mut:#8a97b1;
--crit:#ef4444;--high:#f97316;--med:#f59e0b;--low:#38bdf8;--info:#94a3b8;--ok:#22c55e;--acc:#7c5cff;--code:#0e1422}
@media (prefers-color-scheme: light){:root:not([data-theme=dark]){--bg:#f4f6fb;--card:#fff;--card2:#f1f4fa;
--line:#dfe4ee;--fg:#141a29;--mut:#5d6880;--code:#eef1f7}}
:root[data-theme=light]{--bg:#f4f6fb;--card:#fff;--card2:#f1f4fa;--line:#dfe4ee;--fg:#141a29;--mut:#5d6880;--code:#eef1f7}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 "Noto Sans Thai","Sarabun",system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 60px}
.hero{display:flex;flex-wrap:wrap;gap:22px;align-items:center;justify-content:space-between;padding:26px;
border-radius:20px;background:linear-gradient(135deg,#2a0f1f,#1c1640 45%,#0f2a44);color:#fff;border:1px solid #3a2b5c;
box-shadow:0 20px 60px -30px #ef444488}
.hero h1{margin:0;font-size:28px}.hero p{margin:4px 0 0;color:#c4c9dd}.hero .mono{color:#dfe4ff}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.chip{padding:5px 12px;border-radius:99px;
background:#ffffff14;border:1px solid #ffffff22;font-size:13px}.chip b{font-size:15px}
.grade{width:110px;height:110px;border-radius:50%;display:grid;place-items:center;flex:none;font-size:52px;
font-weight:800;color:#fff;position:relative}.grade small{position:absolute;bottom:-24px;font-size:13px;font-weight:600}
.gA,.gB{background:radial-gradient(circle at 30% 30%,#4ade80,#15803d)}.gC{background:radial-gradient(circle at 30% 30%,#fbbf24,#b45309)}
.gD,.gF{background:radial-gradient(circle at 30% 30%,#f87171,#b91c1c)}
.tools{display:flex;gap:8px}.btn{cursor:pointer;border:1px solid #ffffff33;background:#ffffff14;color:#fff;
border-radius:10px;padding:6px 12px;font:600 13px inherit}.btn.on{background:#fff;color:#1c1640}
h2{font-size:19px;margin:36px 0 12px;display:flex;align-items:center;gap:10px}
h2:before{content:"";width:6px;height:22px;border-radius:3px;background:var(--acc)}
h3{font-size:15px;margin:22px 0 10px;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;margin-bottom:14px}
.f{border-left:5px solid var(--info)}.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}.f.check{border-left-color:var(--acc)}
.fh{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.fh h4{margin:0;font-size:16.5px;flex:1;min-width:200px}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.critical{background:#ef444426;color:var(--crit)}.pill.high{background:#f9731626;color:var(--high)}
.pill.medium{background:#f59e0b26;color:var(--med)}.pill.low{background:#38bdf826;color:var(--low)}
.pill.info{background:#94a3b826;color:var(--info)}.pill.check{background:#7c5cff26;color:var(--acc)}
.tag{font-size:12px;color:var(--mut)}.mut{color:var(--mut)}
.mono,code,pre{font-family:ui-monospace,"JetBrains Mono",monospace;font-size:13px}
code{background:var(--code);border:1px solid var(--line);padding:1px 6px;border-radius:6px;word-break:break-word}
.tgt{color:var(--mut);margin:4px 0 8px;word-break:break-all}
.ev{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:8px 12px;margin:8px 0;
white-space:pre-wrap;word-break:break-word}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:10px}
@media(max-width:820px){.grid{grid-template-columns:1fr}.grade{width:84px;height:84px;font-size:40px}}
.box{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:10px 14px}
.box b{display:block;font-size:12.5px;color:var(--mut);margin-bottom:4px;letter-spacing:.3px}
.box.fix{border-color:#22c55e55}.box.atk{border-color:#ef444444}
.refs{margin-top:8px;font-size:12.5px}.refs a{color:var(--acc);margin-right:12px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:7px 9px;text-align:left;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600;font-size:12.5px}
.tw{overflow-x:auto}
.ok{display:flex;gap:10px;padding:6px 0;border-bottom:1px dashed var(--line)}.ok:last-child{border:0}
.ok:before{content:"✓";color:var(--ok);font-weight:800}
.note{padding:6px 0;border-bottom:1px dashed var(--line)}.note:last-child{border:0}
details>summary{cursor:pointer;color:var(--mut);font-weight:600;margin:6px 0}
label.chk{display:inline-flex;gap:8px;align-items:center;font-size:13px;color:var(--mut);margin-top:8px;cursor:pointer}
.learn{font-size:12.5px;color:var(--acc);text-decoration:none;margin-left:14px}.learn:hover{text-decoration:underline}
.foot{margin-top:40px;font-size:12.5px;color:var(--mut);text-align:center}
.L{display:none}html[lang=th] .L.th,html[lang=en] .L.en{display:block}
"""

JS = """
const root=document.documentElement;
function setLang(l){root.lang=l;document.querySelectorAll('.lb').forEach(b=>b.classList.toggle('on',b.dataset.l===l));
try{localStorage.setItem('sc-lang',l)}catch(e){}}
try{const l=localStorage.getItem('sc-lang');if(l)setLang(l)}catch(e){}
document.querySelectorAll('.lb').forEach(b=>b.onclick=()=>setLang(b.dataset.l));
setLang(root.lang);
document.querySelectorAll('input[data-k]').forEach(c=>{const k='sc-chk-'+c.dataset.k;
try{c.checked=localStorage.getItem(k)==='1'}catch(e){}
c.onchange=()=>{try{localStorage.setItem(k,c.checked?'1':'0')}catch(e){}}});
"""


def fmt(s):
    """escape แล้วแปลง `code` / escape, then `code`"""
    s = E(s or "")
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", s).replace("\n", "<br>")


def sev_label(sev, lang):
    return SEV_TH.get(sev, sev) if lang == "th" else sev.upper()


def finding_html(f, sev, lang, idx):
    e = kb.get(f.id)
    t = lambda k: fmt(kb.text(e, k, lang))
    refs = "".join(f'<a href="{E(u)}" target="_blank" rel="noopener">{E(u.split("//")[-1][:60])}</a>'
                   for u in e.get("refs", []))
    ev = f'<div class="ev">{E(str(f.evidence))}</div>' if str(f.evidence) else ""
    return f"""<div class="card f {sev}">
<div class="fh"><span class="pill {sev}">{E(sev_label(sev, lang))}</span><h4>{t('title')}</h4>
<span class="tag">{E(e.get('tag', ''))} · <span class="mono">{E(f.id)}</span></span></div>
<div class="tgt mono">{E(f.target)}</div>{ev}
<div class="grid"><div class="box"><b>{_('คืออะไร')}</b>{t('what')}</div>
<div class="box atk"><b>{_('ผู้โจมตีใช้ยังไง')}</b>{t('attack')}</div>
<div class="box fix"><b>{_('วิธีแก้')}</b>{t('fix')}</div></div>
{f'<div class="refs">📚 {refs}</div>' if refs else ''}
<label class="chk"><input type="checkbox" data-k="{E(f.id)}-{idx}"> {_('แก้แล้ว')}</label>
<a class="learn" href="/learn?focus={E(f.id)}#lesson-{E(f.id)}">{_('เรียนรู้เพิ่ม ↗')}</a></div>"""


def manual_html(mid, lang):
    e = kb.get(mid)
    t = lambda k: fmt(kb.text(e, k, lang))
    return f"""<div class="card f check"><div class="fh"><span class="pill check">{E(sev_label('check', lang))}</span>
<h4>{t('title')}</h4></div><div class="grid"><div class="box"><b>{_('คืออะไร')}</b>{t('what')}</div>
<div class="box atk"><b>{_('ทำไมต้องสนใจ')}</b>{t('attack')}</div><div class="box fix"><b>{_('ทำยังไง')}</b>{t('fix')}</div></div>
<label class="chk"><input type="checkbox" data-k="{E(mid)}"> {_('ตรวจแล้ว')}</label></div>"""


def body(results, lang):
    k = kb.load()
    with using(lang):
        pts = score(results, k)
        g = grade(pts)
        counts = {s: 0 for s in SEVERITIES}
        for r in results:
            for f in r.findings:
                counts[effective_severity(f, k)] += 1
        chips = "".join(f'<span class="chip">{E(sev_label(s, lang))} <b>{counts[s]}</b></span>' for s in SEVERITIES)
        mods = " · ".join(_(MODULE_TH[r.module]) + f" <span class='mono'>{E(r.target)}</span>" for r in results)
        out = [f"""<div class="hero"><div style="flex:1;min-width:260px"><h1>🛡️ sec-check</h1>
<p>{_('รายงานตรวจความปลอดภัยระบบของตัวเอง')}</p><p>{mods}</p>
<p class="mut">{time.strftime('%Y-%m-%d %H:%M', time.localtime(results[0].started))}</p>
<div class="chips">{chips}</div></div>
<div style="display:flex;flex-direction:column;align-items:center;gap:16px">
<div class="tools"><button class="btn lb" data-l="th">ไทย</button><button class="btn lb" data-l="en">EN</button></div>
<div class="grade g{g}">{g}<small>{pts}/100</small></div></div></div>"""]
        idx = 0
        for r in results:
            out.append(f"<h2>{_(MODULE_TH[r.module])} <span class='mono mut'>{E(r.target)}</span></h2>")
            fs = sorted(r.findings, key=lambda f: SEVERITIES.index(effective_severity(f, k)))
            main = [f for f in fs if effective_severity(f, k) != "info"]
            info = [f for f in fs if effective_severity(f, k) == "info"]
            if not fs:
                out.append(f"<div class='card'>✅ {_('ไม่พบปัญหาในการตรวจนี้')}</div>")
            for f in main:
                idx += 1
                out.append(finding_html(f, effective_severity(f, k), lang, idx))
            if info:
                out.append(f"<details open><summary>{_('ข้อมูลประกอบ ({n})', n=len(info))}</summary>")
                for f in info:
                    idx += 1
                    out.append(finding_html(f, "info", lang, idx))
                out.append("</details>")
            if r.manual:
                out.append(f"<h3>{_('สิ่งที่ต้องตรวจเองในหน้า admin (เครื่องมือตรวจจากภายนอกไม่ได้)')}</h3>")
                out.extend(manual_html(m, lang) for m in r.manual)
            for tb in r.tables:
                if not tb["rows"]:
                    continue
                head = "".join(f"<th>{E(_(c))}</th>" for c in tb["cols"])
                rows = "".join("<tr>" + "".join(f"<td class='mono'>{fmt(str(c))}</td>" for c in row) + "</tr>"
                               for row in tb["rows"])
                out.append(f"<h3>{E(_(tb['title']))}</h3><div class='card tw'><table><tr>{head}</tr>{rows}</table></div>")
            if r.passed:
                items = "".join(f"<div class='ok'><div>{E(_(p.label))} <span class='mono mut'>{E(p.target)}</span>"
                                f"{'<br><span class=mut>' + E(str(p.detail)) + '</span>' if str(p.detail) else ''}</div></div>"
                                for p in r.passed)
                out.append(f"<details><summary>{_('ตรวจแล้วผ่าน ({n})', n=len(r.passed))}</summary>"
                           f"<div class='card'>{items}</div></details>")
            if r.notes:
                items = "".join(f"<div class='note'>{E(_(n))} {f'<code>{E(d)}</code>' if d else ''}</div>"
                                for n, d in r.notes)
                out.append(f"<details><summary>{_('หมายเหตุ ({n})', n=len(r.notes))}</summary>"
                           f"<div class='card'>{items}</div></details>")
        out.append(f"""<div class="foot">sec-check {VERSION} · {_('ตรวจแบบไม่ทำลาย เฉพาะระบบที่เป็นเจ้าของหรือได้รับอนุญาต')}<br>
{_('รายงานนี้มีข้อมูลระบบของคุณ — อย่าเผยแพร่สาธารณะ')}</div>""")
    return "\n".join(out)


def render(results):
    with using("th"):
        th = body(results, "th")
    with using("en"):
        en = body(results, "en")
    return f"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>sec-check report</title>
<style>{CSS}</style></head><body><div class="wrap"><div class="L th">{th}</div><div class="L en">{en}</div></div>
<script>{JS}</script></body></html>"""


def save(results, outdir, name):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:60]
    base = str(outdir / f"{stamp}_{safe}")
    k = kb.load()
    data = {"tool": "sec-check", "version": VERSION, "score": score(results, k), "grade": grade(score(results, k)),
            "results": [r.to_dict() for r in results]}
    for r in data["results"]:
        for f in r["findings"]:
            f["severity"] = f["severity"] or k.get(f["id"], {}).get("severity", "info")
    Path(base + ".json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(base + ".html").write_text(render(results), encoding="utf-8")
    return Path(base + ".html")
