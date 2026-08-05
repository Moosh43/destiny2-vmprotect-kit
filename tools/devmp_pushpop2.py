#!/usr/bin/env python3
"""Second de-mutation pass: recover the sites backward convergence declined.

devmp_pushpop.py rewrote 554,487 idioms but SKIPPED 74,071 where its backward-convergence check
(23 local probes) could not confirm an instruction boundary. 67,430 mutation sites remain.

DIFFERENT ORACLE THIS TIME
    Backward convergence only ever sees ~24 bytes of context, which is exactly why it fails in
    dense mutated regions. A global resync linear sweep carries alignment from potentially
    thousands of correctly-decoded bytes away, and it is CALIBRATED: it independently confirmed
    99.988% of pass 1's rewrites (422,288/422,340), and every unconfirmed site inspected turned
    out to be a sweep false negative, not a bad rewrite.

    The sweep runs on the CURRENT image, which is strictly better than sweeping the original:
    pass 1 already replaced ~554k ambiguous idioms with single-byte push/pop + unambiguous nop
    runs, so the decoder resynchronises faster and drifts less.

    ITERATED: each rewrite makes the next sweep cleaner, so sites unconfirmable in round 1 can
    become confirmable in round 2. Loops until no further progress.

Same rewrite rules and the same equivalence argument as devmp_pushpop.py -- see that file. Every
replacement preserves length and nop-pads, so nothing moves.

ANALYSIS ONLY.
  usage: devmp_pushpop2.py [in.bin] [out.bin] [rounds]
"""
import sys, re, struct, collections
import capstone
import psweep

SRC = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp2_pe.bin"
DST = sys.argv[2] if len(sys.argv) > 2 else "destiny2_devmp3_pe.bin"
ROUNDS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
B = 0x140000000

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
d = bytearray(open(SRC, "rb").read())

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
SECS = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = bytes(d[o:o + 8]).rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
    ch = struct.unpack_from("<I", d, o + 36)[0]
    if ch & 0x20000000:
        SECS.append((name, va, vs, ra))


def nop_pad(ins, n):
    return ins + b"\x90" * (n - len(ins))


RULES = []
for i in range(16):
    rex = 0x4C if i >= 8 else 0x48
    r = i & 7
    push_i = (b"\x41" if i >= 8 else b"") + bytes([0x50 + r])
    pop_i = (b"\x41" if i >= 8 else b"") + bytes([0x58 + r])
    # push A: mov [rsp-8],reg ; lea rsp,[rsp-8]   (reg==rsp is safe: stores the OLD rsp)
    pat = bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8")
    RULES.append((pat, nop_pad(push_i, len(pat)), "push"))
    if i != 4:
        # push B: lea rsp,[rsp-8] ; mov [rsp],reg
        pat = bytes.fromhex("488d6424f8") + bytes([rex, 0x89, 0x04 | (r << 3), 0x24])
        RULES.append((pat, nop_pad(push_i, len(pat)), "push"))
        # pop A: mov reg,[rsp] ; lea rsp,[rsp+8]
        pat = bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408")
        RULES.append((pat, nop_pad(pop_i, len(pat)), "pop"))
        # pop B: lea rsp,[rsp+8] ; mov reg,[rsp-8]
        pat = bytes.fromhex("488d642408") + bytes([rex, 0x8B, 0x44 | (r << 3), 0x24, 0xF8])
        RULES.append((pat, nop_pad(pop_i, len(pat)), "pop"))
for hexpat in ("488d6424f8488d642408", "488d642408488d6424f8"):
    pat = bytes.fromhex(hexpat)
    RULES.append((pat, b"\x90" * len(pat), "junk"))
RULES.append((bytes.fromhex("488d642408ff6424f8"), b"\xc3" + b"\x90" * 8, "ret"))


def sweep(blob, base):
    """Resync linear sweep -> set of instruction start offsets. Parallel, byte-identical."""
    return psweep.sweep_boundaries(blob, base)


total = collections.Counter()
for rnd in range(1, ROUNDS + 1):
    round_done = 0
    for name, va, vs, ra in SECS:
        lo, hi = ra, ra + vs
        blob = d[lo:hi]
        remaining = sum(len(re.findall(re.escape(p), bytes(blob))) for p, _, _ in RULES)
        if not remaining:
            continue
        print(f"[round {rnd}] {name} RVA {va:#x}: {remaining:,} idiom sites present; sweeping...",
              flush=True)
        starts = sweep(blob, B + va)
        print(f"           {len(starts):,} boundaries recovered", flush=True)
        n = 0
        claimed = bytearray(hi - lo)
        for pat, rep, label in RULES:
            for m in re.finditer(re.escape(pat), bytes(blob)):
                off = m.start()
                if off not in starts:
                    continue
                if any(claimed[off:off + len(pat)]):
                    continue
                d[lo + off:lo + off + len(pat)] = rep
                claimed[off:off + len(pat)] = b"\x01" * len(pat)
                total[label] += 1
                n += 1
        print(f"           rewrote {n:,} this round", flush=True)
        round_done += n
    print(f"[round {rnd}] total {round_done:,}\n", flush=True)
    if round_done == 0:
        break

open(DST, "wb").write(bytes(d))
print("rewritten this pass:", dict(total), "=", sum(total.values()))
print(f"wrote {DST}")
