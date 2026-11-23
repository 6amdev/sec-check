#!/usr/bin/env python3
"""
MCP server ของ sec-check / sec-check MCP server (stdio, JSON-RPC 2.0)

ให้ผู้ช่วย AI (เช่น Claude) สั่งสแกนและอ่านผลได้โดยไม่ต้องกดเอง — แต่ยังไม่ข้าม allow-list และไม่ทำลาย
Lets an AI assistant drive scans and read results — still gated by the allow-list and non-destructive.

  ./seccheck.py mcp          (หรือ python3 mcpserver.py)  — พูดคุยผ่าน stdin/stdout

tool ที่มี: list_targets · scan · get_findings · explain_finding · get_report · compare_scans
เขียนด้วย stdlib ล้วน ไม่ต้องลง MCP SDK · newline-delimited JSON-RPC
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import i18n  # noqa: E402
from core import VERSION, db, kb, report, scope  # noqa: E402
from core.finding import SEVERITIES, effective_severity, grade, score  # noqa: E402

PROTOCOL = "2024-11-05"
TOOLS = [
    {"name": "list_targets", "description": "List the allow-listed targets sec-check may scan (plus loopback, always allowed).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "scan",
     "description": "Run a non-destructive scan of an allow-listed target and return a summary. "
                    "target is one of: 'host', 'wifi', 'router', 'lan:<cidr>', 'web:<url>', 'tls:<host:port>', "
                    "'windows:<ip>', 'camera:<ip>', 'mac:<ip>', 'iot:<ip>', 'dns:<domain>', 'cve:<host>'. "
                    "Refuses anything not in the allow-list.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string"}, "level": {"type": "integer", "minimum": 1, "maximum": 5, "default": 5},
         "default_creds": {"type": "boolean", "default": False}}, "required": ["target"]}},
    {"name": "get_findings",
     "description": "Get the vulnerable findings from a scan (defaults to the latest). Optional severity filter.",
     "inputSchema": {"type": "object", "properties": {
         "scan_id": {"type": "integer"}, "severity": {"type": "string",
                                                      "enum": ["critical", "high", "medium", "low", "info"]}}}},
    {"name": "explain_finding", "description": "Explain a finding/lesson by its id (what it is, how attackers use it, how to fix), bilingual.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    {"name": "get_report", "description": "Get the full machine-readable report JSON for a scan id.",
     "inputSchema": {"type": "object", "properties": {"scan_id": {"type": "integer"}}, "required": ["scan_id"]}},
    {"name": "compare_scans", "description": "Compare two scans (before/after hardening): fixed / new / still-open findings.",
     "inputSchema": {"type": "object", "properties": {"old_id": {"type": "integer"}, "new_id": {"type": "integer"}},
                     "required": ["old_id", "new_id"]}},
]


def run_module(pick, level, creds):
    import argparse
    from checks import camera, cve, dns, host, iot, lan, mac, router, tls, web, webapp, wifi, windows
    opts = argparse.Namespace(delay=0.1, timeout=0.8, max_hosts=1024, default_creds=creds,
                              passphrase=None, ssid=None)
    simple = {"host": host, "wifi": wifi, "router": router}
    pref = {"lan": lan, "web": web, "tls": tls, "windows": windows, "camera": camera, "mac": mac,
            "iot": iot, "dns": dns, "email": dns, "cve": cve, "webapp": webapp}
    if pick in simple:
        return [simple[pick].run(None, opts)]
    mod, _, arg = pick.partition(":")
    if mod in pref:
        return [pref[mod].run(arg or None, opts)]
    raise ValueError(f"unknown target '{pick}' (see the tool description)")


def tool_scan(args):
    pick = args["target"]
    level = max(1, min(5, int(args.get("level", 5))))
    results = run_module(pick, level, bool(args.get("default_creds")))
    kb.filter_level(results, level)
    k = kb.load()
    sid = db.save(results, level=level)
    pts = score(results, k)
    counts = {s: 0 for s in SEVERITIES}
    tops = []
    for r in results:
        for f in r.findings:
            sev = effective_severity(f, k)
            counts[sev] += 1
            if sev in ("critical", "high"):
                tops.append({"id": f.id, "severity": sev, "target": f.target,
                             "title": kb.text(kb.get(f.id), "title", "en")})
    return {"scan_id": sid, "score": pts, "grade": grade(pts), "counts": counts,
            "top_findings": tops[:20], "modules": [r.module for r in results]}


def tool_call(name, args):
    if name == "list_targets":
        return {"always_allowed": ["127.0.0.0/8", "::1", "localhost"], "targets": scope.load()}
    if name == "scan":
        return tool_scan(args)
    if name == "get_findings":
        sid = args.get("scan_id") or (db.latest() or {}).get("id")
        rows = db.findings(sid, "VULNERABLE") if sid else []
        if args.get("severity"):
            rows = [r for r in rows if r["severity"] == args["severity"]]
        return {"scan_id": sid, "findings": rows}
    if name == "explain_finding":
        e = kb.get(args["id"])
        return {"id": args["id"], "severity": e.get("severity"), "level": e.get("level", 3),
                "tag": e.get("tag", ""), "title": e.get("title", {}), "what": e.get("what", {}),
                "attack": e.get("attack", {}), "fix": e.get("fix", {}), "refs": e.get("refs", [])}
    if name == "get_report":
        row = db.get(int(args["scan_id"]))
        if not row:
            raise ValueError("scan not found")
        return json.loads(row["report_json"])
    if name == "compare_scans":
        return db.compare(int(args["old_id"]), int(args["new_id"]))
    raise ValueError(f"unknown tool '{name}'")


def dispatch(msg):
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
            "serverInfo": {"name": "sec-check", "version": VERSION}}}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            result = tool_call(name, args)
            text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}}
        except scope.OutOfScope as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"refused: {e}"}], "isError": True}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}], "isError": True}}
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def main():
    i18n.set_default("en")
    kb.load()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        resp = dispatch(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
