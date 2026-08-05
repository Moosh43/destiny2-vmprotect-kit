#!/usr/bin/env python3
"""Third de-mutation pass, gated on RELOCATION-ANCHORED boundaries (ground truth).

ORACLE PROGRESSION
    pass 1  backward convergence   -- ~24 bytes of context. 554,487 rewritten, 67,430 left.
    pass 2  global linear sweep    -- resyncs, but can drift through data.  57,996, 9,495 left.
    pass 3  RELOCATION ANCHORS     -- this file. Not a heuristic at all.

WHY THIS IS GROUND TRUTH
    The BASERELOC *data directory* (RVA 0x8955230 -- NOT the decoy `.reloc` section, which has
    zero code entries) yields 324,064 relocations inside executable code. 309,148 of them have a
    `movabs reg,imm64` starting at reloc-2, and the loader MUST patch exactly there or the image
    does not run. Those are certain instruction starts.

    Decoding FORWARD from a certain start keeps yielding certain starts, until the decoder hits
    an undecodable byte. So 309,148 anchors expand into a large trusted boundary set that no
    heuristic can match. Anchors are processed in address order and already-trusted addresses are
    skipped, so the expansion is linear rather than 309,148 redundant walks.

    Reported per-oracle so the anchors' marginal contribution over the sweep is visible instead
    of assumed.

ANALYSIS ONLY.
  usage: devmp_pushpop3.py [in.bin] [out.bin]
"""
import sys, re, json, struct, collections
import capstone
import psweep

SRC = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp3_pe.bin"
DST = sys.argv[2] if len(sys.argv) > 2 else "destiny2_devmp4_pe.bin"
B = 0x140000000
FWD = 512                      # bytes to decode forward from each anchor

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
    RULES.append((bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8"),
                  None, "push", push_i))
    if i != 4:
        RULES.append((bytes.fromhex("488d6424f8") + bytes([rex, 0x89, 0x04 | (r << 3), 0x24]),
                      None, "push", push_i))
        RULES.append((bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408"),
                      None, "pop", pop_i))
        RULES.append((bytes.fromhex("488d642408") + bytes([rex, 0x8B, 0x44 | (r << 3), 0x24, 0xF8]),
                      None, "pop", pop_i))
RULES = [(p, nop_pad(ins, len(p)), lab) for p, _, lab, ins in RULES]
for hexpat in ("488d6424f8488d642408", "488d642408488d6424f8"):
    p = bytes.fromhex(hexpat)
    RULES.append((p, b"\x90" * len(p), "junk"))
RULES.append((bytes.fromhex("488d642408ff6424f8"), b"\xc3" + b"\x90" * 8, "ret"))

# --- trusted boundaries, expanded from the relocation anchors --------------------------------
anchors = json.load(open("reloc_boundaries.json"))["movabs_boundaries"]
print(f"[*] {len(anchors):,} relocation anchors (certain instruction starts)", flush=True)

trusted = set()
raw = bytes(d)
for A in anchors:                       # already sorted ascending
    if A in trusted:
        continue
    off = A - B
    stop = off + FWD
    pos = off
    while pos < stop:
        got = False
        for addr, size, _, _ in md.disasm_lite(raw[pos:min(stop, pos + 256)], B + pos):
            if addr in trusted:         # merged into an already-expanded run
                pos = stop
                got = True
                break
            trusted.add(addr)
            got = True
            pos = addr - B + size
        if not got:
            break                       # undecodable -> certainty ends here
print(f"[*] expanded to {len(trusted):,} trusted boundaries", flush=True)


def sweep(blob, base):
    # Returns ABSOLUTE addresses to preserve this pass's original convention. The sweep is
    # DIAGNOSTIC ONLY here: the rewrite gate uses the relocation ANCHORS (in_tr); `off in sw`
    # compares a relative offset against absolute addrs and never fires (verified: 0 sweep-only).
    # Parallel, and byte-identical to the original.
    return {base + o for o in psweep.sweep_boundaries(blob, base)}


total = collections.Counter()
by_oracle = collections.Counter()
for name, va, vs, ra in SECS:
    lo, hi = ra, ra + vs
    blob = bytes(d[lo:hi])
    present = sum(len(re.findall(re.escape(p), blob)) for p, _, _ in RULES)
    print(f"\n=== {name} RVA {va:#x}: {present:,} idiom sites still present ===", flush=True)
    if not present:
        continue
    sw = sweep(blob, B + va)
    print(f"    sweep boundaries {len(sw):,}", flush=True)
    claimed = bytearray(hi - lo)
    n = 0
    for pat, rep, label in RULES:
        for m in re.finditer(re.escape(pat), blob):
            off = m.start()
            addr = B + va + off
            in_tr = addr in trusted
            in_sw = off in sw
            if not (in_tr or in_sw):
                by_oracle["neither (declined)"] += 1
                continue
            if any(claimed[off:off + len(pat)]):
                continue
            by_oracle["anchor-only (NEW this pass)" if in_tr and not in_sw else
                      "sweep-only" if in_sw and not in_tr else "both"] += 1
            d[lo + off:lo + off + len(pat)] = rep
            claimed[off:off + len(pat)] = b"\x01" * len(pat)
            total[label] += 1
            n += 1
    print(f"    rewrote {n:,}", flush=True)

print("\nconfirming oracle:")
for k, v in by_oracle.most_common():
    print(f"  {v:>8,}  {k}")
open(DST, "wb").write(bytes(d))
print(f"\nrewritten this pass: {dict(total)} = {sum(total.values()):,}")
print(f"wrote {DST}")
