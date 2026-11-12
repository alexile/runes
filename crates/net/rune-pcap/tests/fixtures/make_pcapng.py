# Independent pcapng writer (not using rune-pcap) for test fixtures.
import struct, sys
out = sys.argv[1]
SYN = bytes.fromhex("0200000000020200000000018100602a08004500003f1c46400040063237c0000201c63364079c4001bb0102030400000000a002faf0badc0000020405b40402080a123456780000000001030307474554")
V6UDP = bytes.fromhex("02000000000202000000000186dd620123450012114020010db800000000000000000000000120010db800000000000000000000000214e900350012c65368656c6c6f2c20756470")
ICMP = bytes.fromhex("0200000000020200000000010800450000240007400040014e96c0000201c633640708005435123400016162636465666768")
ARP = bytes.fromhex("ffffffffffff02000000000108060001080006040001020000000001c0000201000000000000c00002fe000000000000000000000000000000000000")

def build(e, nanos, second_section):
    def u16(v): return struct.pack(e+"H", v)
    def u32(v): return struct.pack(e+"I", v)
    def u64(v): return struct.pack(e+"Q", v)
    def pad(b): return b + b"\0" * (-len(b) % 4)
    def opt(code, val): return u16(code) + u16(len(val)) + pad(val)
    def opts(*o): return b"".join(o) + (u32(0) if o else b"")
    def block(t, body):
        body = pad(body)
        n = len(body) + 12
        return u32(t) + u32(n) + body + u32(n)
    res = 9 if nanos else 6
    def epb(ifid, secs, frac, data, orig=None, o=b""):
        t = secs * 10**res + frac
        return block(6, u32(ifid) + u32(t >> 32) + u32(t & 0xffffffff) + u32(len(data)) + u32(orig or len(data)) + pad(data) + o)
    def section(tag):
        shb = block(0x0A0D0D0A, u32(0x1A2B3C4D) + u16(1) + u16(0) + u64(2**64 - 1) +
                    opts(opt(2, b"x86_64"), opt(3, b"Linux 6.1"), opt(4, b"rune-pcap fixture generator"), opt(1, b"section " + tag)))
        idb_opts = [opt(2, b"eth0"), opt(3, b"test interface"), opt(12, b"Linux 6.1")]
        if nanos:
            idb_opts.append(opt(9, bytes([9])))
        idb = block(1, u16(1) + u16(0) + u32(262144) + opts(*idb_opts))
        nrb = block(4, u16(1) + u16(4 + 15) + pad(bytes([192, 0, 2, 1]) + b"client.example\0") + u16(0) + u16(0) + opts(opt(1, b"names")))
        f = lambda us: us * 1000 if nanos else us
        pk = [
            epb(0, 1700000000, f(123456) + (789 if nanos else 0), SYN, o=opts(opt(1, b"tcp syn"), opt(2, u32(1)))),
            epb(0, 1700000001, f(1), V6UDP),
            epb(0, 1700000002, f(500000), ICMP[:40], orig=len(ICMP)),
            epb(0, 1700000003, 0, ARP, o=opts(opt(4, u64(7)))),
        ]
        isb = block(5, u32(0) + u32(0) + u32(0) + opts(opt(4, u64(4)), opt(5, u64(0))))
        dsb = block(0x0A, u32(0x544c534b) + u32(28) + pad(b"CLIENT_RANDOM 00 11 22 33 4\n"))
        custom = block(0xBAD, u32(32473) + b"rune")
        return shb + idb + nrb + pk[0] + dsb + pk[1] + custom + pk[2] + pk[3] + isb
    data = section(b"one")
    if second_section:
        data += section(b"two")
    return data

e = "<" if "le" in out else ">"
open(out, "wb").write(build(e, "nanos" in out, "two" in out))
