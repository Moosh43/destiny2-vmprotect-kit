#!/usr/bin/env python3
"""Rewrite VMProtect's push/pop MUTATION back to real `push`/`pop` in the ANALYSIS COPY.

Census (devmp_census.py) over destiny2_devmp_pe.bin found what is left after the `ret` pass:
    191,498  push : mov [rsp-8],reg ; lea rsp,[rsp-8]      <- dominant
    117,721  pop  : mov reg,[rsp]  ; lea rsp,[rsp+8]       <- dominant
      6,897  junk : lea rsp,[rsp-/+8] ; lea rsp,[rsp+/-8]  (cancelling pair)
      7,058  ret  : sites the previous pass judged unaligned
These are why Ghidra's stack-depth model breaks: it sees raw stores below rsp plus manual rsp
arithmetic instead of push/pop, so locals and parameters are mis-attributed and callers
decompile truncated.

EQUIVALENCE (why each rewrite is safe in ANY context)
  push reg                    == mov [rsp-8],reg ; lea rsp,[rsp-8]
      Both end with [new rsp] = reg and rsp 8 lower. Neither touches flags. `push rsp` pushes
      the OLD rsp, and the mutated form stores rsp BEFORE the lea, so even reg==rsp matches.
  pop reg                     == mov reg,[rsp] ; lea rsp,[rsp+8]
      Both end with reg = [old rsp] and rsp 8 higher. EXCEPT reg == rsp: `pop rsp` yields
      [rsp], while the mutated form yields [rsp]+8. NOT equivalent -- reg 4 is EXCLUDED for pop.
  lea rsp,[rsp-8] ; lea rsp,[rsp+8]  == nothing (cancels; no flags touched)
The only observable difference is the transient window where the mutated form has written below
rsp before adjusting it, which nothing but an async interrupt could see. Irrelevant statically.

Replacements keep the ORIGINAL LENGTH and pad with `nop`, so nothing moves and no offset,
relocation, .pdata entry or vtable slot needs fixing.

Every site is verified instruction-aligned by BACKWARD CONVERGENCE (decode from 23 earlier
offsets; a strong majority must land exactly on the site). This is the same check that validated
the `ret` pass, whose output loads in Ghidra and decompiles gate 1 correctly.

ANALYSIS ONLY. The client runs the ORIGINAL binary. Never ship this image.
  usage: devmp_pushpop.py [in.bin] [out.bin]
"""
import sys, re, struct, collections
import capstone
import psweep

SRC = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp_pe.bin"
DST = sys.argv[2] if len(sys.argv) > 2 else "destiny2_devmp2_pe.bin"
B = 0x140000000

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

d = bytearray(open(SRC, "rb").read())
raw = bytes(d)

pe = struct.unpack_from("<I", raw, 0x3C)[0]
nsec = struct.unpack_from("<H", raw, pe + 6)[0]
opt = struct.unpack_from("<H", raw, pe + 20)[0]
SECS = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = raw[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", raw, o + 8)
    ch = struct.unpack_from("<I", raw, o + 36)[0]
    if ch & 0x20000000:
        SECS.append((name, va, vs, ra))


def aligned(off, plen, back=24):
    """True if `off` is a real instruction boundary: decode from each of the previous `back`
    bytes and require a majority of runs to land exactly on it."""
    yes = no = 0
    for b in range(1, back):
        st = off - b
        if st < 0:
            continue
        hit = False
        for i in md.disasm(raw[st:off + plen], B + st):
            if i.address == B + off:
                hit = True
                break
            if i.address > B + off:
                break
        yes += hit
        no += (not hit)
    return yes > no * 1.5 and yes >= 6


# --- build the pattern table ------------------------------------------------------------------
# (pattern bytes, replacement bytes, label)  -- replacement is nop-padded to len(pattern)
def nop_pad(ins, n):
    return ins + b"\x90" * (n - len(ins))


RULES = []
for i in range(16):
    rex = 0x4C if i >= 8 else 0x48
    r = i & 7
    push_i = (b"\x41" if i >= 8 else b"") + bytes([0x50 + r])
    pop_i = (b"\x41" if i >= 8 else b"") + bytes([0x58 + r])

    # push A: mov [rsp-8],reg ; lea rsp,[rsp-8]
    # reg==rsp is FINE here: the store happens before the lea, so it saves the OLD rsp,
    # which is exactly what `push rsp` does.
    pat = bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8")
    RULES.append((pat, nop_pad(push_i, len(pat)), "push"))

    # push B: lea rsp,[rsp-8] ; mov [rsp],reg      (same idiom, opposite order)
    # reg==rsp differs: the store would save the ALREADY-DECREMENTED rsp.
    if i != 4:
        pat = bytes.fromhex("488d6424f8") + bytes([rex, 0x89, 0x04 | (r << 3), 0x24])
        RULES.append((pat, nop_pad(push_i, len(pat)), "push"))

    # pop A: mov reg,[rsp] ; lea rsp,[rsp+8]
    # reg==rsp differs: yields [rsp]+8 instead of [rsp].
    if i != 4:
        pat = bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408")
        RULES.append((pat, nop_pad(pop_i, len(pat)), "pop"))

    # pop B: lea rsp,[rsp+8] ; mov reg,[rsp-8]
    # reg==rsp would actually be equivalent here, but it is excluded for uniformity --
    # the site count is negligible and a uniform rule is easier to trust.
    if i != 4:
        pat = bytes.fromhex("488d642408") + bytes([rex, 0x8B, 0x44 | (r << 3), 0x24, 0xF8])
        RULES.append((pat, nop_pad(pop_i, len(pat)), "pop"))

for hexpat in ("488d6424f8488d642408", "488d642408488d6424f8"):
    pat = bytes.fromhex(hexpat)
    RULES.append((pat, b"\x90" * len(pat), "junk"))

# the obfuscated ret, for the sites the previous pass skipped
RULES.append((bytes.fromhex("488d642408ff6424f8"), b"\xc3" + b"\x90" * 8, "ret"))

print(f"src {SRC}\n{len(RULES)} rewrite rules\n")

done = collections.Counter()
skip = collections.Counter()
claimed = bytearray(len(raw))     # guard: never rewrite bytes another rule already took

# 1. collect every regex candidate in the exact serial order (regex is cheap; alignment is the cost)
cand = []
for name, va, vs, ra in SECS:
    lo, hi = ra, ra + vs
    for pat, rep, label in RULES:
        for m in re.finditer(re.escape(pat), raw[lo:hi]):
            cand.append((lo + m.start(), len(pat)))

# 2. backward-convergence verdict is a pure function of `raw` -> evaluate all candidates in
# parallel across every core. Identical result to calling aligned() serially.
print(f"  aligning {len(cand):,} candidates across cores...", flush=True)
verdict = psweep.batch_aligned(raw, B, set(cand), back=24, step=1, strong=1.5, min_yes=6)

# 3. apply serially in the ORIGINAL order (the `claimed` guard is order-dependent)
for name, va, vs, ra in SECS:
    lo, hi = ra, ra + vs
    print(f"=== {name}  RVA {va:#x}  ({vs:,} bytes) ===", flush=True)
    for pat, rep, label in RULES:
        n = 0
        for m in re.finditer(re.escape(pat), raw[lo:hi]):
            off = lo + m.start()
            if any(claimed[off:off + len(pat)]):
                skip[label + " (overlap)"] += 1
                continue
            if not verdict[(off, len(pat))]:
                skip[label] += 1
                continue
            d[off:off + len(pat)] = rep
            claimed[off:off + len(pat)] = b"\x01" * len(pat)
            n += 1
        done[label] += n
    for k in sorted(set(list(done) + list(skip))):
        print(f"    {done[k]:>9,} rewritten   {skip[k]:>7,} skipped   {k}", flush=True)

open(DST, "wb").write(bytes(d))
print(f"\ntotal rewritten: {sum(done.values()):,}   skipped: {sum(skip.values()):,}")
print(f"wrote {DST}")
