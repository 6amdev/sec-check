"""
โมดูล dns — ตรวจความปลอดภัย DNS และอีเมลของโดเมนตัวเอง / DNS & email security for your own domain

ตรวจ SPF, DKIM, DMARC (กันอีเมลปลอม), DNSSEC, CAA — ด้วยการค้น DNS แบบอ่านอย่างเดียว (เหมือน dig)
ไม่ได้แตะเซิร์ฟเวอร์ของเป้าหมาย เป็นการอ่านข้อมูลสาธารณะ
Checks SPF, DKIM, DMARC (anti-spoofing), DNSSEC and CAA via read-only DNS lookups (like `dig`).
It doesn't touch the target's servers — DNS records are public data.

  ./seccheck.py dns 6amdev.com       (หรือ ./seccheck.py email 6amdev.com)
"""
from core import dnsq
from core.finding import Result, T
from i18n import _

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
                  "s1", "s2", "zoho", "mandrill", "mxvault", "sig1", "scph0120"]


def run(target, opts):
    domain = (target or "").strip().lower().strip(".")
    if not domain or "." not in domain:
        raise SystemExit(_("ระบุชื่อโดเมน เช่น ./seccheck.py dns example.com"))
    if "://" in domain:
        domain = domain.split("://")[1].split("/")[0]
    res = Result("dns", domain)

    a = dnsq.query(domain, dnsq.A)
    if a is None:
        res.note("ค้น DNS ไม่ได้ (เครือข่าย/รีโซลเวอร์มีปัญหา?)", domain)
        return res.done()
    mx = dnsq.query(domain, dnsq.MX) or []
    res.note("ข้อมูลโดเมน", f"A: {', '.join(a) or '-'} · MX: {', '.join(mx) or '-'}")

    # --- SPF ---
    spf = [t for t in dnsq.txt(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        res.add("dns.no_spf", domain)
    else:
        rec = spf[0]
        res.ok("มี SPF", domain, rec[:120])
        tail = rec.split()[-1].lower() if rec.split() else ""
        if tail in ("+all", "?all") or " +all" in rec.lower():
            res.add("dns.spf_weak", domain, rec[:120])

    # --- DMARC ---
    dmarc = [t for t in dnsq.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        res.add("dns.no_dmarc", domain)
    else:
        rec = dmarc[0]
        res.ok("มี DMARC", f"_dmarc.{domain}", rec[:140])
        pol = ""
        for part in rec.split(";"):
            if part.strip().lower().startswith("p="):
                pol = part.strip()[2:].strip().lower()
        if pol == "none":
            res.add("dns.dmarc_weak", f"_dmarc.{domain}", rec[:140])
        elif pol in ("quarantine", "reject"):
            res.ok("DMARC บังคับจริง", f"_dmarc.{domain}", f"p={pol}")

    # --- DKIM (ลอง selector ยอดนิยม) ---
    found = []
    for sel in DKIM_SELECTORS:
        recs = dnsq.txt(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower() and len(r) > 40 for r in recs):
            found.append(sel)
    if found:
        res.ok("พบ DKIM", domain, "selector: " + ", ".join(found))
    elif mx:
        res.add("dns.no_dkim", domain, T("ลอง {n} selector ยอดนิยมแล้วไม่พบ", n=len(DKIM_SELECTORS)))

    # --- DNSSEC ---
    if dnsq.query(domain, dnsq.DNSKEY):
        res.ok("เปิด DNSSEC (มี DNSKEY)", domain)
    else:
        res.add("dns.no_dnssec", domain)

    # --- CAA ---
    if dnsq.query(domain, dnsq.CAA):
        res.ok("มี CAA (จำกัด CA ที่ออกใบรับรองได้)", domain)
    else:
        res.add("dns.no_caa", domain)

    res.note("ตรวจจากการค้น DNS สาธารณะอย่างเดียว ไม่ได้แตะเซิร์ฟเวอร์ของโดเมน · DKIM ลองเฉพาะ selector ยอดนิยม")
    return res.done()
