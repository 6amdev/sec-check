"""
ตัวค้น DNS แบบ stdlib ล้วน / minimal stdlib DNS resolver (UDP) — no external deps

ใช้สอบถามเรคคอร์ด TXT/MX/A/NS/SOA/DNSKEY/CAA เพื่อตรวจ SPF/DKIM/DMARC/DNSSEC ของโดเมนตัวเอง
การค้น DNS เป็นการอ่านข้อมูลสาธารณะ (เหมือน `dig`) ไม่ได้โจมตีหรือแตะระบบของเป้าหมาย
DNS lookups read public data (like `dig`); they don't attack or touch the target's systems.
"""
import random
import socket
import struct

A, NS, CNAME, SOA, MX, TXT, AAAA, DNSKEY, CAA = 1, 2, 5, 6, 15, 16, 28, 48, 257


def resolvers():
    servers = []
    try:
        for line in open("/etc/resolv.conf", encoding="utf-8"):
            if line.strip().startswith("nameserver"):
                servers.append(line.split()[1])
    except OSError:
        pass
    # ตัวค้นระบบก่อน (ได้ผลครบกว่า) แล้วค่อย public fallback
    for pub in ("1.1.1.1", "8.8.8.8"):
        if pub not in servers:
            servers.append(pub)
    return servers


def _encode(name):
    return b"".join(bytes([len(l)]) + l.encode("idna" if any(ord(c) > 127 for c in l) else "ascii")
                    for l in name.rstrip(".").split(".") if l) + b"\x00"


def _read_name(data, off):
    labels, jumped, nxt = [], False, off
    for _ in range(128):
        if off >= len(data):
            break
        length = data[off]
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                nxt = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        if length == 0:
            break
        labels.append(data[off:off + length].decode("latin-1"))
        off += length
    return ".".join(labels), (nxt if jumped else off)


def _rdata(rtype, data, off, rdlen):
    raw = data[off:off + rdlen]
    if rtype == TXT:
        out, i = [], 0
        while i < len(raw):
            n = raw[i]
            out.append(raw[i + 1:i + 1 + n].decode("latin-1"))
            i += 1 + n
        return "".join(out)
    if rtype in (NS, CNAME):
        return _read_name(data, off)[0]
    if rtype == MX:
        pref = struct.unpack(">H", raw[:2])[0]
        return f"{pref} {_read_name(data, off + 2)[0]}"
    if rtype == A:
        return socket.inet_ntoa(raw) if len(raw) == 4 else ""
    if rtype == SOA:
        mname, o = _read_name(data, off)
        return mname
    if rtype == CAA:
        if len(raw) >= 2:
            tl = raw[1]
            return f"{raw[2:2 + tl].decode('latin-1')} {raw[2 + tl:].decode('latin-1')}"
        return ""
    if rtype == DNSKEY:
        return "present"
    return raw.hex()


def query(name, qtype, timeout=4):
    """คืนลิสต์ค่า rdata ที่ parse แล้ว หรือ None ถ้าค้นไม่ได้ / list of parsed rdata, or None on failure"""
    # EDNS0 OPT: โฆษณา UDP buffer 4096 ไบต์ กันคำตอบโดนตัด (truncation)
    edns = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    pkt = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 1) + \
        _encode(name) + struct.pack(">HH", qtype, 1) + edns
    for srv in resolvers():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (srv, 53))
            data, _ = s.recvfrom(8192)
            s.close()
        except OSError:
            continue
        if len(data) < 12:
            continue
        _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        if flags & 0x000F not in (0, 3):      # 0=OK, 3=NXDOMAIN (ตอบได้ว่าไม่มี)
            continue
        off = 12
        for _ in range(qd):
            _n, off = _read_name(data, off)
            off += 4
        out = []
        for _ in range(an):
            _n, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            out.append((rtype, _rdata(rtype, data, off, rdlen)))
            off += rdlen
        return [v for t, v in out if t == qtype or (qtype == TXT and t == TXT)]
    return None


def txt(name):
    return query(name, TXT) or []
