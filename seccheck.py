#!/usr/bin/env python3
"""
sec-check — ตรวจหาช่องโหว่ในระบบของตัวเอง เพื่อเรียนรู้และป้องกัน
sec-check — find weaknesses in systems you own, learn how attacks work, and fix them

  ./seccheck.py scope add 6amdev.com          เพิ่มเป้าหมาย (ต้องยืนยันว่าเป็นเจ้าของ) / add a target you own
  ./seccheck.py web https://6amdev.com        ตรวจเว็บ / check a website
  ./seccheck.py lan [192.168.1.0/24]          หาเครื่อง+บริการในวงแลน / scan your LAN
  ./seccheck.py host                          ตรวจเครื่อง Linux นี้ / audit this Linux machine
  ./seccheck.py router [192.168.1.1]          ตรวจเราเตอร์/Wi-Fi / check router & Wi-Fi
  ./seccheck.py all                           host + router + lan + web ทุกเป้าหมายใน scope
  ./seccheck.py explain web.git_exposed       อ่านคำอธิบายช่องโหว่ / read a lesson
  ./seccheck.py lessons                       รายการช่องโหว่ทั้งหมดที่ตรวจได้ / list all checks

ทุกการตรวจเป็นแบบไม่ทำลาย (อ่านอย่างเดียว) และทำได้เฉพาะเป้าหมายใน scope.json
Every check is non-destructive (read-only) and only runs against targets in scope.json.
"""
import argparse
import os
import sys
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import i18n  # noqa: E402
from i18n import _  # noqa: E402
from core import VERSION, kb, report, scope  # noqa: E402
from core.finding import SEVERITIES, effective_severity, grade, score  # noqa: E402

COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m",
         "info": "\033[90m", "check": "\033[35m"}
RESET = "\033[0m"


def c(sev, text):
    return f"{COLOR.get(sev, '')}{text}{RESET}" if sys.stdout.isatty() else text


def lang():
    return i18n.get_lang()


def summary(results):
    k = kb.load()
    for r in results:
        print(f"\n== {_(report.MODULE_TH[r.module])} · {r.target} ==")
        fs = sorted(r.findings, key=lambda f: SEVERITIES.index(effective_severity(f, k)))
        for f in fs:
            sev = effective_severity(f, k)
            title = kb.text(kb.get(f.id), "title", lang())
            print(f"  {c(sev, f'[{report.sev_label(sev, lang()):^8}]')} {title}  ·  {f.target}")
        if not fs:
            print("  ✅ " + _("ไม่พบปัญหาในการตรวจนี้"))
        print("  " + _("ผ่าน {n} ข้อ", n=len(r.passed)) + (f" · {_('ต้องตรวจเอง {n} ข้อ', n=len(r.manual))}"
                                                           if r.manual else ""))
    pts = score(results, k)
    print("\n" + _("คะแนน: {p}/100  เกรด {g}", p=pts, g=grade(pts)))


def finish(results, args, name):
    lvl = getattr(args, "level", 5)
    kb.filter_level(results, lvl)
    if lvl < 5:
        print(_("(กรองที่ระดับความยาก ≤ {l})", l=lvl))
    summary(results)
    want_pdf = getattr(args, "pdf", False)
    report.save.last_pdf = None
    path = report.save(results, args.out, name, org=getattr(args, "org", "") or "", pdf=want_pdf)
    print(_("📄 รายงาน: {p}", p=path))
    if want_pdf:
        pdf = getattr(report.save, "last_pdf", None)
        if pdf:
            print(_("📑 PDF: {p}", p=pdf))
        else:
            print(_("⚠️  ออก PDF ไม่ได้ — ติดตั้ง chromium/google-chrome หรือ wkhtmltopdf ก่อน"))
    if args.open:
        webbrowser.open(path.as_uri())


def run_module(mod, target, args):
    from checks import camera, cve, dns, host, iot, lan, mac, router, tls, tools, web, webapp, wifi, windows
    m = {"web": web, "lan": lan, "host": host, "router": router, "wifi": wifi, "tls": tls, "windows": windows, "camera": camera, "mac": mac, "webapp": webapp, "iot": iot, "dns": dns, "email": dns, "cve": cve, "tools": tools}[mod]
    print(_("▶ กำลังตรวจ {m} {t}", m=_(report.MODULE_TH[mod]), t=target or ""), flush=True)
    return m.run(target, args)


def cmd_all(args):
    from checks import lan, router
    results = [run_module("host", None, args)]
    for mod, tgt in [("router", router.gateway())] + [("lan", n) for _i, n in lan.local_networks()]:
        if not tgt:
            continue
        try:
            scope.check(tgt)
        except scope.OutOfScope:
            print(_("⏭  ข้าม {m} {t} — ยังไม่อยู่ใน scope (เพิ่มด้วย ./seccheck.py scope add {t})",
                    m=mod, t=tgt))
            continue
        results.append(run_module(mod, tgt, args))
    for e in scope.load():
        if e["kind"] == "url" or (e["kind"] == "host" and not e["target"].startswith("*.")):
            results.append(run_module("web", e["target"], args))
    finish(results, args, "all")


def cmd_explain(args):
    e = kb.load().get(args.id)
    if not e:
        print(_("ไม่รู้จัก id นี้ — ดูรายการด้วย ./seccheck.py lessons"))
        return 1
    L = lang()
    print(c(e["severity"], f"[{report.sev_label(e['severity'], L)}]") + f" {kb.text(e, 'title', L)}  ({e.get('tag', '')})")
    for field, label in (("what", "คืออะไร"), ("attack", "ผู้โจมตีใช้ยังไง"), ("fix", "วิธีแก้")):
        print(f"\n{_(label)}:\n  {kb.text(e, field, L)}")
    for u in e.get("refs", []):
        print("  📚 " + u)
    return 0


def cmd_lessons(_args):
    L = lang()
    for id, e in kb.load().items():
        print(f"  {c(e['severity'], f'{report.sev_label(e['severity'], L):<8}')} {id:<34} {kb.text(e, 'title', L)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="seccheck.py", description=_("ตรวจหาช่องโหว่ในระบบของตัวเอง (ไม่ทำลาย)"))
    p.add_argument("--lang", choices=["th", "en"], default=os.environ.get("SECCHECK_LANG", "th"))
    p.add_argument("--out", default=str(HERE / "reports"), help=_("โฟลเดอร์เก็บรายงาน"))
    p.add_argument("--open", action="store_true", help=_("เปิดรายงานในเบราว์เซอร์เมื่อเสร็จ"))
    p.add_argument("--pdf", action="store_true", help=_("ออกรายงานเป็น PDF ด้วย (ถ้ามี chromium/wkhtmltopdf)"))
    p.add_argument("--org", default="", help=_("ใส่ชื่อองค์กร/ร้านบนหัวรายงาน"))
    p.add_argument("--version", action="version", version=f"sec-check {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope", help=_("จัดการเป้าหมายที่อนุญาต"))
    sp.add_argument("action", choices=["list", "add", "remove"])
    sp.add_argument("target", nargs="?")
    sp.add_argument("--note", default="")
    sp.add_argument("--yes", action="store_true", help=_("ยืนยันว่าเป็นเจ้าของ (ไม่ถาม)"))

    lvl = dict(type=int, default=5, choices=[1, 2, 3, 4, 5],
               help=_("ระดับความยาก 1–5 (1 = เฉพาะของเปิดโล่ง/เจอง่าย, 5 = ทั้งหมด)"))

    w = sub.add_parser("web", help=_("ตรวจเว็บไซต์"))
    w.add_argument("target")
    w.add_argument("--delay", type=float, default=0.15, help=_("หน่วงระหว่าง request (วินาที)"))
    w.add_argument("--level", **lvl)

    ln = sub.add_parser("lan", help=_("หาเครื่องและบริการในวงแลน"))
    ln.add_argument("target", nargs="?")
    ln.add_argument("--timeout", type=float, default=0.8)
    ln.add_argument("--max-hosts", type=int, default=1024)
    ln.add_argument("--default-creds", action="store_true",
                    help=_("ลองรหัส default บนหน้า Basic auth (อ่านอย่างเดียว จำกัดอัตรา)"))
    ln.add_argument("--level", **lvl)

    h = sub.add_parser("host", help=_("ตรวจเครื่อง Linux นี้"))
    h.add_argument("--level", **lvl)
    wf = sub.add_parser("wifi", help=_("ตรวจความปลอดภัย Wi-Fi ของตัวเอง (passive)"))
    wf.add_argument("target", nargs="?")
    wf.add_argument("--ssid", help=_("ระบุชื่อ Wi-Fi ที่จะตรวจ (ค่าเริ่มต้น = ที่ต่ออยู่)"))
    wf.add_argument("--passphrase", help=_("ตรวจความแข็งแรงของรหัส Wi-Fi ในเครื่อง (ไม่เก็บ ไม่ส่งออก)"))
    wf.add_argument("--level", **lvl)
    tp = sub.add_parser("tls", help=_("ตรวจ TLS/SSL ของบริการ (host:port หรือ URL)"))
    tp.add_argument("target")
    tp.add_argument("--level", **lvl)
    wn = sub.add_parser("windows", help=_("ตรวจเครื่อง Windows ในวง (SMB/RDP)"))
    wn.add_argument("target")
    wn.add_argument("--level", **lvl)
    cm = sub.add_parser("camera", help=_("ตรวจกล้อง IP / NVR ในวง (ONVIF/RTSP)"))
    cm.add_argument("target")
    cm.add_argument("--level", **lvl)
    mc = sub.add_parser("mac", help=_("ตรวจเครื่อง Mac ในวง (Screen Sharing/AFP/SMB)"))
    mc.add_argument("target")
    mc.add_argument("--level", **lvl)
    wa = sub.add_parser("webapp", help=_("ตรวจช่องโหว่เว็บแอป SQLi/XSS/CSRF (เป้าฝึก/เว็บตัวเอง)"))
    wa.add_argument("target")
    wa.add_argument("--delay", type=float, default=0.2)
    wa.add_argument("--level", **lvl)
    io = sub.add_parser("iot", help=_("ตรวจอุปกรณ์ IoT/ทีวี/สมาร์ตโฮม ในวง (passive)"))
    io.add_argument("target")
    io.add_argument("--level", **lvl)
    dn = sub.add_parser("dns", help=_("ตรวจ DNS/อีเมลของโดเมน (SPF/DKIM/DMARC/DNSSEC)"))
    dn.add_argument("target")
    dn.add_argument("--level", **lvl)
    em = sub.add_parser("email", help=_("ตรวจความปลอดภัยอีเมลของโดเมน (SPF/DKIM/DMARC)"))
    em.add_argument("target")
    em.add_argument("--level", **lvl)
    cv = sub.add_parser("cve", help=_("จับคู่เวอร์ชันบริการกับช่องโหว่ที่รู้จัก (CVE, ออฟไลน์)"))
    cv.add_argument("target")
    cv.add_argument("--level", **lvl)
    tl = sub.add_parser("tools", help=_("ห่อเครื่องมือภายนอก nmap/nuclei/testssl/lynis (ถ้าติดตั้งไว้)"))
    tl.add_argument("target", nargs="?")
    tl.add_argument("--level", **lvl)
    r = sub.add_parser("router", help=_("ตรวจเราเตอร์และ Wi-Fi"))
    r.add_argument("target", nargs="?")
    r.add_argument("--timeout", type=float, default=1.5)
    r.add_argument("--level", **lvl)
    a = sub.add_parser("all", help=_("ตรวจทุกอย่างที่อยู่ใน scope"))
    a.add_argument("--delay", type=float, default=0.15)
    a.add_argument("--timeout", type=float, default=0.8)
    a.add_argument("--max-hosts", type=int, default=1024)
    a.add_argument("--default-creds", action="store_true")
    a.add_argument("--level", **lvl)
    e = sub.add_parser("explain", help=_("อ่านคำอธิบายช่องโหว่"))
    e.add_argument("id")
    sub.add_parser("lessons", help=_("รายการช่องโหว่ทั้งหมดที่ตรวจได้"))
    sv = sub.add_parser("serve", help=_("เปิดหน้าเว็บ (Dashboard/Scan/Map)"))
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8770)
    sv.add_argument("--pin", default=os.environ.get("SECCHECK_PIN"))

    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default=os.environ.get("SECCHECK_LANG", "th"))
    i18n.set_default(pre.parse_known_args(argv)[0].lang)
    args = p.parse_args(argv)
    i18n.set_default(args.lang)

    try:
        if args.cmd == "scope":
            if args.action == "list":
                scope.show()
            elif not args.target:
                p.error(_("ต้องระบุเป้าหมาย"))
            elif args.action == "add":
                scope.add(args.target, args.note, args.yes)
            else:
                scope.remove(args.target)
        elif args.cmd == "explain":
            return cmd_explain(args)
        elif args.cmd == "lessons":
            cmd_lessons(args)
        elif args.cmd == "serve":
            import webapp
            webapp.main(["--host", args.host, "--port", str(args.port), "--lang", args.lang]
                        + (["--pin", args.pin] if args.pin else []))
        elif args.cmd == "all":
            cmd_all(args)
        else:
            res = run_module(args.cmd, getattr(args, "target", None), args)
            name = f"{args.cmd}_{res.target.split('://')[-1]}"
            finish([res], args, name)
    except scope.OutOfScope as ex:
        print("⛔ " + str(ex))
        return 2
    except KeyboardInterrupt:
        print("\n" + _("ยกเลิก"))
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
