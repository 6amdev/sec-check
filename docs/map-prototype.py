#!/usr/bin/env python3
"""สร้างแผนที่เครือข่ายในบ้านเป็นหน้า HTML (ต้นแบบหน้า Network Map ของ sec-check)
Standalone demo of the Network Map page. The real web UI builds this from an actual scan (core/netmap.py).
ข้อมูลด้านล่างเป็น "ตัวอย่าง" ใช้ช่วง IP สำหรับเอกสาร (RFC 5737) — ไม่ใช่เครือข่ายจริงของใคร
The hosts below are EXAMPLE data using the documentation range (RFC 5737), not anyone's real network."""
import json, math, html

HOSTS = [
    {"ip": "192.0.2.1",   "type": "router",  "name": "เราเตอร์ / Router", "ports": [53, 80, 445],           "sev": "high",   "note": "เว็บ admin เก่า + SMB เปิดบน router / old admin web + SMB on router"},
    {"ip": "192.0.2.201", "type": "windows", "name": "Windows PC",        "ports": [139, 445, 3389, 5900],  "sev": "high",   "note": "เปิด VNC + RDP + SMB พร้อมกัน / VNC + RDP + SMB all exposed"},
    {"ip": "192.0.2.51",  "type": "nvr",     "name": "NVR / กล้อง",       "ports": [443, 554, 8443],        "sev": "high",   "note": "RTSP ไม่ถามรหัส อาจดูภาพได้ / RTSP with no auth challenge"},
    {"ip": "192.0.2.24",  "type": "camera",  "name": "กล้อง IP / Camera", "ports": [80, 554],               "sev": "medium", "note": "หน้าเว็บอาจเข้าได้ไม่ล็อกอิน / web UI may be open"},
    {"ip": "192.0.2.31",  "type": "device",  "name": "อุปกรณ์ / Device",  "ports": [80],                    "sev": "medium", "note": "Basic auth ผ่าน http / Basic auth over plain http"},
    {"ip": "192.0.2.27",  "type": "unknown", "name": "ไม่ทราบชนิด / ?",   "ports": [80, 443],               "sev": "medium", "note": "เข้าเว็บได้ สถานะล็อกอินไม่ชัด / web reachable, auth unclear"},
    {"ip": "192.0.2.57",  "type": "camera",  "name": "กล้อง IP / Camera", "ports": [80, 554],               "sev": "low",    "note": "RTSP มี digest auth / RTSP has digest auth — check default creds"},
    {"ip": "192.0.2.59",  "type": "camera",  "name": "กล้อง IP / Camera", "ports": [80, 554],               "sev": "low",    "note": "RTSP มี digest auth / RTSP has digest auth — check default creds"},
    {"ip": "192.0.2.25",  "type": "unknown", "name": "อุปกรณ์ UPnP / UPnP","ports": [49152],                "sev": "low",    "note": "UPnP เปิด / UPnP enabled — check WAN port-opening"},
    {"ip": "192.0.2.78",  "type": "server",  "name": "เครื่องนี้ / This box","ports": [22, 8080],            "sev": "ok",     "note": "Linux server (example)"},
]
ICON = {"router": "📶", "windows": "🖥️", "nvr": "🎞️", "camera": "📷", "device": "🔌",
        "unknown": "❓", "server": "🐧"}
SEV = {"high": ("#ef4444", "เสี่ยงสูง"), "medium": ("#f59e0b", "เสี่ยงกลาง"),
       "low": ("#eab308", "ควรตรวจ"), "ok": ("#22c55e", "ปกติ")}
E = html.escape

devices = [h for h in HOSTS if h["type"] != "server"] + [h for h in HOSTS if h["type"] == "server"]
cx, cy, R = 430, 400, 300
nodes, lines, n = [], [], len(devices)
for i, h in enumerate(devices):
    ang = -math.pi / 2 + 2 * math.pi * i / n
    x, y = cx + R * math.cos(ang), cy + R * math.sin(ang)
    h["_xy"] = (x, y)
    col = SEV[h["sev"]][0]
    lines.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.0f}" y2="{y:.0f}" stroke="{col}" '
                 f'stroke-width="2" stroke-opacity="0.35"/>')
    tip = f'{h["ip"]} · {h["name"]} · พอร์ต {",".join(map(str,h["ports"]))} — {h["note"]}'
    nodes.append(f'''<g class="node" tabindex="0" transform="translate({x:.0f},{y:.0f})" data-ip="{E(h['ip'])}">
      <title>{E(tip)}</title>
      <circle r="34" fill="#0f1628" stroke="{col}" stroke-width="3"/>
      <circle r="34" fill="{col}" fill-opacity="0.12"/>
      <text class="emoji" y="6" text-anchor="middle">{ICON[h['type']]}</text>
      <text class="ipl" y="52" text-anchor="middle">{E(h['ip'].split('.')[-1])}</text>
    </g>''')

cards = ""
order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
for h in sorted(devices, key=lambda d: (order[d["sev"]], d["ip"])):
    col, lbl = SEV[h["sev"]]
    ports = " ".join(f'<span class="port">{p}</span>' for p in h["ports"])
    cards += f'''<div class="card" style="--c:{col}" data-ip="{E(h['ip'])}">
      <div class="ch"><span class="ico">{ICON[h['type']]}</span>
        <div><b>{E(h['name'])}</b><small>{E(h['ip'])}</small></div>
        <span class="sev" style="background:{col}">{E(lbl)}</span></div>
      <div class="ports">{ports}</div><p>{E(h['note'])}</p></div>'''

counts = {k: sum(1 for h in devices if h["sev"] == k) for k in SEV}
kpi = "".join(f'<div class="kpi" style="--c:{SEV[k][0]}"><b>{counts[k]}</b><span>{SEV[k][1]}</span></div>'
              for k in ("high", "medium", "low", "ok"))

HTML = f'''<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>แผนที่เครือข่ายในบ้าน</title><style>
*{{box-sizing:border-box}}
body{{margin:0;font-family:system-ui,"Noto Sans Thai",sans-serif;background:
radial-gradient(1200px 800px at 70% -10%,#13203a,#0a0e18 60%);color:#e6ebf5;min-height:100vh}}
.wrap{{max-width:1100px;margin:0 auto;padding:22px 18px 60px}}
.hero h1{{margin:0;font-size:26px}} .hero p{{color:#8a97b1;margin:6px 0 0}}
.badge{{display:inline-block;margin-top:10px;padding:5px 12px;border-radius:99px;background:#7c5cff22;
border:1px solid #7c5cff55;color:#b9a9ff;font-size:12.5px}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}}
.kpi{{background:#121826;border:1px solid #243049;border-left:4px solid var(--c);border-radius:14px;padding:12px 14px}}
.kpi b{{display:block;font-size:26px}} .kpi span{{font-size:12px;color:#8a97b1}}
.layout{{display:grid;grid-template-columns:860px 1fr;gap:18px;align-items:start}}
@media(max-width:1000px){{.layout{{grid-template-columns:1fr}} svg{{max-width:100%}}}}
@media(max-width:560px){{.kpis{{grid-template-columns:1fr 1fr}}}}
.mapbox{{background:#0c1322;border:1px solid #243049;border-radius:18px;padding:8px;overflow:hidden}}
svg{{width:100%;height:auto;display:block}}
.node{{cursor:pointer}} .node .emoji{{font-size:30px}}
.node .ipl{{fill:#cdd6ea;font-size:13px;font-weight:700}}
.node:hover circle:first-of-type,.node:focus circle:first-of-type{{fill:#1a2742}}
.hub text{{fill:#fff}} .hub .t{{font-size:13px;fill:#9fb0d0}}
.cards{{display:flex;flex-direction:column;gap:10px;max-height:760px;overflow:auto}}
.card{{background:#121826;border:1px solid #243049;border-left:4px solid var(--c);border-radius:14px;padding:12px 14px}}
.card.hl{{outline:2px solid var(--c);background:#16203a}}
.ch{{display:flex;align-items:center;gap:10px}} .ch .ico{{font-size:24px}}
.ch b{{display:block}} .ch small{{color:#8a97b1;font-family:ui-monospace,monospace;font-size:12px}}
.sev{{margin-left:auto;color:#07101f;font-weight:800;font-size:11.5px;padding:3px 9px;border-radius:99px}}
.ports{{display:flex;flex-wrap:wrap;gap:5px;margin:9px 0 6px}}
.port{{font-family:ui-monospace,monospace;font-size:11.5px;background:#1b2740;border:1px solid #2c3b5c;
border-radius:7px;padding:2px 7px;color:#aeb9d4}}
.card p{{margin:4px 0 0;font-size:13px;color:#c3cbe0;line-height:1.5}}
.note{{margin-top:22px;color:#8a97b1;font-size:12.5px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hero"><h1>🛰️ แผนที่เครือข่ายในบ้าน</h1>
<p>{E("ตัวอย่าง (ช่วง IP เอกสาร) / Example (documentation IP range)")} · {len(devices)} {E("อุปกรณ์")}</p>
<span class="badge">sec-check Network Map · demo</span></div>
<div class="kpis">{kpi}</div>
<div class="layout">
<div class="mapbox"><svg viewBox="0 0 860 800">
{''.join(lines)}
<line x1="{cx}" y1="{cy}" x2="{cx}" y2="120" stroke="#7c5cff" stroke-width="2" stroke-opacity="0.4"/>
<g class="hub" transform="translate({cx},120)"><circle r="30" fill="#0f1628" stroke="#7c5cff" stroke-width="3"/>
<text y="6" text-anchor="middle" font-size="26">🌐</text><text class="t" y="50" text-anchor="middle">อินเทอร์เน็ต</text></g>
<g class="hub" transform="translate({cx},{cy})"><circle r="44" fill="#0f1628" stroke="#7c5cff" stroke-width="4"/>
<circle r="44" fill="#7c5cff" fill-opacity="0.12"/><text y="8" text-anchor="middle" font-size="34">📶</text>
<text class="t" y="64" text-anchor="middle">เราเตอร์ .1</text></g>
{''.join(nodes)}
</svg></div>
<div class="cards">{cards}</div>
</div>
<p class="note">🔴 เสี่ยงสูง = ควรแก้ก่อน · แตะอุปกรณ์บนแผนที่เพื่อไฮไลต์ · ทุกการทดสอบเป็นแบบอ่านอย่างเดียว ไม่ทำให้อุปกรณ์เสียหาย</p>
</div>
<script>
document.querySelectorAll('.node').forEach(n=>{{
  const ip=n.dataset.ip, card=document.querySelector('.card[data-ip="'+ip+'"]');
  const on=()=>{{document.querySelectorAll('.card').forEach(c=>c.classList.remove('hl'));
    if(card){{card.classList.add('hl');card.scrollIntoView({{block:'nearest',behavior:'smooth'}});}}}};
  n.addEventListener('mouseenter',on);n.addEventListener('focus',on);n.addEventListener('click',on);
}});
</script></body></html>'''

with open("home_map.html", "w", encoding="utf-8") as f:
    f.write(HTML)
print("wrote home_map.html", len(HTML), "bytes")
