"""
โมดูล tools — ห่อเครื่องมือภายนอกที่ติดตั้งไว้ (nmap, nuclei, testssl.sh, lynis) แล้วแปลงผลเป็น Finding
Module tools — wrap installed external tools and fold their output into sec-check Findings

ถ้ามีเครื่องมือก็รันกับเป้าหมายใน allow-list แล้ว parse ผล · ถ้าไม่มีก็บอกวิธีติดตั้ง (ทำงานต่อได้ไม่ต้องมี)
If a tool is installed it runs against an allow-listed target and its output is parsed; if not, it prints
an install hint and carries on. nmap -sV / testssl / nuclei are standard non-destructive scans; lynis
audits THIS machine locally. Everything stays gated by the allow-list.
"""
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from core import cvedb, scope
from core.finding import Result, T
from i18n import _

INSTALL = {
    "nmap": "sudo apt install nmap",
    "nuclei": "https://github.com/projectdiscovery/nuclei (go install / binary release)",
    "testssl.sh": "sudo apt install testssl.sh  (หรือ git clone drwetter/testssl.sh)",
    "lynis": "sudo apt install lynis",
}
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
           "informational": "info", "warning": "medium", "unknown": "info", "ok": "info"}


def which(name):
    return shutil.which(name)


def run_cmd(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


# ---- parsers (แยกออกมาเพื่อทดสอบได้โดยไม่ต้องมีเครื่องมือจริง) -----------------------------------
def parse_nmap_xml(xml_text):
    """คืน [(port, proto, service, product, version)] จาก nmap -oX -"""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for host in root.findall(".//host"):
        for port in host.findall(".//port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            out.append((port.get("portid"), port.get("protocol"),
                        (svc.get("name") if svc is not None else "") or "",
                        (svc.get("product") if svc is not None else "") or "",
                        (svc.get("version") if svc is not None else "") or ""))
    return out


def parse_nuclei_jsonl(text):
    """คืน [(severity, name, matched)] จาก nuclei -jsonl"""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info", {})
        out.append((info.get("severity", "info"), info.get("name", j.get("template-id", "?")),
                    j.get("matched-at", j.get("host", ""))))
    return out


def parse_testssl_json(text):
    """คืน [(severity, id, finding)] จาก testssl --jsonfile (array)"""
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    items = data if isinstance(data, list) else data.get("scanResult", [])
    for it in items:
        sev = (it.get("severity") or "").lower()
        if sev in ("ok", "info", "") or not it.get("finding"):
            continue
        out.append((sev, it.get("id", "?"), it.get("finding", "")[:160]))
    return out


def parse_lynis_report(text):
    """คืน [(type, detail)] warnings/suggestions จาก /var/log/lynis-report.dat"""
    out = []
    for line in text.splitlines():
        if line.startswith("warning[]="):
            out.append(("warning", line.split("=", 1)[1].split("|")[0]))
        elif line.startswith("suggestion[]="):
            out.append(("suggestion", line.split("=", 1)[1].split("|")[0]))
    return out


# ---- runners ----------------------------------------------------------------------------------
def run_nmap(target, res):
    rc, out, err = run_cmd(["nmap", "-sV", "-Pn", "-T4", "--version-light", "-oX", "-", target], timeout=300)
    if rc != 0 and not out:
        res.note("nmap รันไม่สำเร็จ", err[:120])
        return
    rows = parse_nmap_xml(out)
    res.table("nmap -sV (พอร์ต/บริการ/เวอร์ชัน)", ["port", "service", "product", "version"],
              [[f"{p}/{proto}", svc, prod, ver] for p, proto, svc, prod, ver in rows] or [["-", "-", "-", "-"]])
    for p, proto, svc, prod, ver in rows:
        for e in cvedb.match(prod or svc, ver):
            from checks.cve import Desc
            res.add("cve.known_vuln", f"{target}:{p}", Desc(f"{prod or svc} {ver}", e.get("cve", "?"),
                                                            e["th"], e["en"]), e["sev"])
    res.note("nmap พบพอร์ตเปิด", str(len(rows)))


def run_nuclei(target, res):
    url = target if "://" in target else f"http://{target}"
    rc, out, err = run_cmd(["nuclei", "-u", url, "-silent", "-jsonl", "-rl", "50", "-timeout", "8"], timeout=420)
    for sev, name, matched in parse_nuclei_jsonl(out):
        res.add("tools.external", matched or url, T("nuclei [{s}] {n}", s=sev, n=name), SEV_MAP.get(sev, "info"))


def run_testssl(target, res):
    rc, out, err = run_cmd(["testssl.sh", "--quiet", "--color", "0", "--jsonfile", "/dev/stdout", target], timeout=420)
    for sev, fid, finding in parse_testssl_json(out):
        res.add("tools.external", target, T("testssl [{s}] {i}: {f}", s=sev, i=fid, f=finding),
                SEV_MAP.get(sev, "info"))


def run_lynis(res):
    run_cmd(["lynis", "audit", "system", "--quick", "--no-colors"], timeout=600)
    report = Path("/var/log/lynis-report.dat")
    try:
        text = report.read_text(errors="replace")
    except OSError:
        res.note("lynis รันแล้วแต่อ่านรายงานไม่ได้ (ต้องใช้ root): ", "sudo lynis audit system")
        return
    items = parse_lynis_report(text)
    warns = [d for t, d in items if t == "warning"]
    for d in warns[:25]:
        res.add("tools.external", "lynis", T("lynis warning: {d}", d=d), "medium")
    sugg = [d for t, d in items if t == "suggestion"]
    res.note("lynis suggestions", str(len(sugg)))
    if not warns:
        res.ok("lynis ไม่พบ warning", "localhost")


def run(target, opts):
    res = Result("tools", target or "localhost")
    present = {t: which(t) for t in ("nmap", "nuclei", "testssl.sh", "lynis")}

    if target:
        scope.check(target if "://" in target else f"https://{target}")
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        if present["nmap"]:
            run_nmap(host, res)
        if present["nuclei"]:
            run_nuclei(target, res)
        if present["testssl.sh"]:
            run_testssl(host, res)
    if present["lynis"]:
        run_lynis(res)

    missing = [t for t, path in present.items() if not path]
    if missing:
        for t in missing:
            res.note("ยังไม่ได้ติดตั้งเครื่องมือนี้ — ติดตั้งเพื่อตรวจลึกขึ้น", f"{t}: {INSTALL[t]}")
    if not any(present.values()):
        res.note("ยังไม่มีเครื่องมือภายนอกที่รองรับเลย — sec-check ยังทำงานได้ด้วยตัวเอง", ", ".join(present))
    res.note("โมดูลนี้ห่อเครื่องมือภายนอก รันเฉพาะเป้าหมายใน allow-list · การสแกนเป็นแบบไม่ทำลาย")
    return res.done()
