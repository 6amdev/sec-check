"""
แผนที่เครือข่าย / Network map — turn a lan scan Result into an SVG home map (adapted from docs/map-prototype.py)

ใช้ข้อมูลจริงจากการสแกน (ไม่ใช่ข้อมูลตายตัว) — ความเสี่ยงของแต่ละอุปกรณ์มาจาก finding ที่เจอบน IP นั้น
Real scan data, not hardcoded: each device's risk comes from the findings on that IP.
"""
import html
import math
import re

from core import kb
from core.finding import SEVERITIES, effective_severity
from i18n import _

E = html.escape
ICON = {"router": "📶", "windows": "🖥️", "camera": "📷", "nvr": "🎞️", "printer": "🖨️",
        "mac": "💻", "linux": "🐧", "tv": "📺", "device": "🔌", "unknown": "❓"}
SEV_COLOR = {"critical": "#dc2626", "high": "#ef4444", "medium": "#f59e0b", "low": "#eab308",
             "info": "#38bdf8", "ok": "#22c55e"}


def _kind(guess):
    g = (guess or "").lower()
    for key, kind in (("camera", "camera"), ("กล้อง", "camera"), ("nvr", "nvr"), ("router", "router"),
                      ("เราเตอร์", "router"), ("windows", "windows"), ("printer", "printer"),
                      ("เครื่องพิมพ์", "printer"), ("mac", "mac"), ("nas", "mac"), ("linux", "linux"),
                      ("เซิร์ฟเวอร์", "linux"), ("tv", "tv"), ("chromecast", "tv")):
        if key in g:
            return kind
    return "device" if guess else "unknown"


def hosts_from(result):
    """ดึงรายการอุปกรณ์จากตาราง 'เครื่องที่พบ' + ความรุนแรงจาก findings / build host list from the lan Result"""
    k = kb.load()
    worst = {}   # ip -> severity index
    for f in result.findings:
        ip = f.target.split("/")[0].split(":")[0].replace("http", "").strip()
        m = re.search(r"\d+\.\d+\.\d+\.\d+", f.target)
        if not m:
            continue
        ip = m.group(0)
        sev = effective_severity(f, k)
        idx = SEVERITIES.index(sev)
        if ip not in worst or idx < worst[ip]:
            worst[ip] = idx
    table = next((t for t in result.tables if "เครื่อง" in t["title"] or "Hosts" in t["title"]), None)
    hosts = []
    for row in (table["rows"] if table else []):
        ip, name, guess, mac, ports = (list(row) + ["", "", "", "", ""])[:5]
        portnums = [int(x) for x in re.findall(r"\b(\d{1,5})/", str(ports))] or \
                   [int(x) for x in re.findall(r"\b(\d{1,5})\b", str(ports))]
        sev = SEVERITIES[worst[ip]] if ip in worst else "ok"
        hosts.append({"ip": ip, "name": name or guess or ip, "kind": _kind(guess),
                      "ports": portnums[:8], "sev": sev, "mac": mac})
    return hosts


def svg(result, lang="th"):
    hosts = hosts_from(result)
    if not hosts:
        return f'<p class="mut">{E(_("ยังไม่มีข้อมูลแผนที่ — สแกน LAN ก่อน"))}</p>'
    cx, cy, R = 430, 400, 300
    n = len(hosts)
    lines, nodes = [], []
    for i, h in enumerate(hosts):
        ang = -math.pi / 2 + 2 * math.pi * i / max(n, 1)
        x, y = cx + R * math.cos(ang), cy + R * math.sin(ang)
        col = SEV_COLOR.get(h["sev"], "#22c55e")
        lines.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.0f}" y2="{y:.0f}" stroke="{col}" '
                     f'stroke-width="2" stroke-opacity="0.35"/>')
        tip = f'{h["ip"]} · {h["name"]} · ' + _("พอร์ต") + f' {",".join(map(str, h["ports"])) or "-"}'
        nodes.append(f'''<g class="node" tabindex="0" transform="translate({x:.0f},{y:.0f})" data-ip="{E(h['ip'])}">
<title>{E(tip)}</title><circle r="34" fill="#0f1628" stroke="{col}" stroke-width="3"/>
<circle r="34" fill="{col}" fill-opacity="0.12"/><text class="emoji" y="6" text-anchor="middle">{ICON[h['kind']]}</text>
<text class="ipl" y="52" text-anchor="middle">{E(h['ip'].split('.')[-1])}</text></g>''')
    return f'''<svg viewBox="0 0 860 800">{''.join(lines)}
<line x1="{cx}" y1="{cy}" x2="{cx}" y2="120" stroke="#7c5cff" stroke-width="2" stroke-opacity="0.4"/>
<g class="hub" transform="translate({cx},120)"><circle r="30" fill="#0f1628" stroke="#7c5cff" stroke-width="3"/>
<text y="6" text-anchor="middle" font-size="26">🌐</text>
<text class="t" y="50" text-anchor="middle">{E(_("อินเทอร์เน็ต"))}</text></g>
<g class="hub" transform="translate({cx},{cy})"><circle r="44" fill="#0f1628" stroke="#7c5cff" stroke-width="4"/>
<circle r="44" fill="#7c5cff" fill-opacity="0.12"/><text y="8" text-anchor="middle" font-size="34">📶</text>
<text class="t" y="64" text-anchor="middle">{E(_("เราเตอร์/วงแลน"))}</text></g>
{''.join(nodes)}</svg>'''


def cards(result, lang="th"):
    hosts = hosts_from(result)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    order["ok"] = len(SEVERITIES)
    out = []
    for h in sorted(hosts, key=lambda d: (order.get(d["sev"], 9), d["ip"])):
        col = SEV_COLOR.get(h["sev"], "#22c55e")
        ports = " ".join(f'<span class="port">{p}</span>' for p in h["ports"]) or "-"
        out.append(f'''<div class="card" style="--c:{col}" data-ip="{E(h['ip'])}">
<div class="ch"><span class="ico">{ICON[h['kind']]}</span><div><b>{E(h['name'])}</b><small>{E(h['ip'])}</small></div></div>
<div class="ports">{ports}</div></div>''')
    return "\n".join(out)
