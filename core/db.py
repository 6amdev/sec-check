"""
เก็บผลสแกนลง SQLite / Store scan results in SQLite (data/seccheck.db)

เก็บไว้ดูประวัติและเทียบก่อน/หลังแก้ (🔴 → 🟢) · ไฟล์นี้ไม่ขึ้น git
Keeps history so you can compare before/after hardening. The DB file is git-ignored.

allow-list ตัวจริงอยู่ที่ scope.json (เป็นด่านความปลอดภัย) — DB นี้เก็บแค่ผล ไม่ใช่ตัวตัดสินสิทธิ์
The real allow-list lives in scope.json (the safety gate); this DB only stores results.
"""
import json
import sqlite3
import time
from pathlib import Path

from core import VERSION
from core.finding import SEVERITIES, effective_severity, grade, score
from core import kb

HERE = Path(__file__).resolve().parent.parent
DB_PATH = HERE / "data" / "seccheck.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started REAL, finished REAL, modules TEXT, target TEXT,
  level INTEGER, score INTEGER, grade TEXT, report_json TEXT);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER, module TEXT, target TEXT, check_id TEXT,
  state TEXT, severity TEXT, evidence TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE INDEX IF NOT EXISTS ix_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_find_target ON findings(target);
"""


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def save(results, level=1):
    """บันทึก 1 การสแกน (หลาย module ได้) คืน scan_id / save one scan, return scan_id"""
    k = kb.load()
    pts = score(results, k)
    con = connect()
    try:
        cur = con.execute(
            "INSERT INTO scans(started, finished, modules, target, level, score, grade, report_json)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (results[0].started, max(r.finished for r in results),
             ",".join(r.module for r in results), ", ".join(r.target for r in results),
             level, pts, grade(pts),
             json.dumps({"tool": "sec-check", "version": VERSION,
                         "results": [r.to_dict() for r in results]}, ensure_ascii=False)))
        sid = cur.lastrowid
        rows = []
        for r in results:
            for f in r.findings:
                sev = effective_severity(f, k)
                rows.append((sid, r.module, f.target, f.id,
                             "INFO" if sev == "info" else "VULNERABLE", sev, str(f.evidence)))
            for p in r.passed:                       # 🟢 ผ่าน / secure
                rows.append((sid, r.module, p.target or r.target, p.label, "SECURE", "info", str(p.detail)))
        con.executemany("INSERT INTO findings(scan_id, module, target, check_id, state, severity, evidence)"
                        " VALUES(?,?,?,?,?,?,?)", rows)
        con.commit()
        return sid
    finally:
        con.close()


def recent(limit=20):
    con = connect()
    try:
        return [dict(r) for r in con.execute(
            "SELECT id, started, finished, modules, target, level, score, grade"
            " FROM scans ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        con.close()


def get(scan_id):
    con = connect()
    try:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def latest():
    r = recent(1)
    return r[0] if r else None


def findings(scan_id, state=None):
    con = connect()
    try:
        q = "SELECT * FROM findings WHERE scan_id=?"
        args = [scan_id]
        if state:
            q += " AND state=?"
            args.append(state)
        return [dict(r) for r in con.execute(q + " ORDER BY severity", args)]
    finally:
        con.close()


def counts(scan_id):
    con = connect()
    try:
        out = {s: 0 for s in SEVERITIES}
        for r in con.execute("SELECT severity, COUNT(*) c FROM findings WHERE scan_id=? AND state='VULNERABLE'"
                             " GROUP BY severity", (scan_id,)):
            out[r["severity"]] = r["c"]
        return out
    finally:
        con.close()


def trend(target, check_id):
    """ประวัติสถานะของเช็กเดียวกันบนเป้าเดียวกัน (ดู 🔴→🟢) / state history for one check on one target"""
    con = connect()
    try:
        return [dict(r) for r in con.execute(
            "SELECT s.id, s.started, f.state FROM findings f JOIN scans s ON s.id=f.scan_id"
            " WHERE f.target=? AND f.check_id=? ORDER BY s.id", (target, check_id))]
    finally:
        con.close()
