#!/usr/bin/env python3
"""How much VMProtect is left? Classify every instruction in both executable sections.

Counts sites AND bytes, so "how much is left" has a real denominator instead of a vibe.

BUCKETS
  padding     nop / 0f1f            -- our nop-padding plus VMProtect's own alignment
  threading   xchg [rsp],reg | movabs reg,<code addr> | lea reg,[rip+x] into code | cmov | ret
              -- the flattening machinery: a block plants its successor on the stack and `ret`s
  stackop     push / pop            -- register saves, now native (were mutated idioms)
  mutation    the push/pop/ret idioms still in mutated form (the aligner declined these)
  work        everything else       -- actual program semantics
"""
import sys, struct, re, collections
import capstone

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp2_pe.bin"
B = 0x140000000
d = open(IMG, "rb").read()

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
SECS = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = d[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
    ch = struct.unpack_from("<I", d, o + 36)[0]
    SECS.append((name, va, vs, ra, bool(ch & 0x20000000)))

import peinfo   # was hardcoded to 87221
_er = peinfo.exec_ranges(d)
CLO, CHI = _er[0][0], _er[-1][1]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# still-mutated idiom byte patterns (any remaining site the aligner declined)
MUT = [bytes.fromhex("488d642408ff6424f8")]
for i in range(16):
    rex = 0x4C if i >= 8 else 0x48
    r = i & 7
    MUT += [bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8"),
            bytes.fromhex("488d6424f8") + bytes([rex, 0x89, 0x04 | (r << 3), 0x24]),
            bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408"),
            bytes.fromhex("488d642408") + bytes([rex, 0x8B, 0x44 | (r << 3), 0x24, 0xF8])]

print(f"image {IMG}\n")
grand = collections.Counter()
grand_b = collections.Counter()

for name, va, vs, ra, ex in SECS:
    if not ex:
        continue
    blob = d[ra:ra + vs]
    mut_bytes = sum(len(p) * len(re.findall(re.escape(p), blob)) for p in MUT)

    cnt = collections.Counter()
    byt = collections.Counter()
    pos, n = 0, len(blob)
    while pos < n:
        got = False
        for ins in md.disasm(blob[pos:min(n, pos + 8192)], B + va + pos):
            got = True
            m, ops = ins.mnemonic, ins.op_str
            if m == "nop":
                k = "padding"
            elif m == "xchg" and "[rsp]" in ops:
                k = "threading"
            elif m == "movabs" and re.search(r"0x1[45678][0-9a-f]{7}\b", ops):
                k = "threading"
            elif m == "lea" and "rip" in ops:
                k = "threading"
            elif m.startswith("cmov") or m == "ret" or m.startswith("j"):
                k = "threading"
            elif m in ("push", "pop"):
                k = "stackop"
            else:
                k = "work"
            cnt[k] += 1
            byt[k] += ins.size
            pos = ins.address - B - va + ins.size
            if pos >= n:
                break
        if not got:
            cnt["undecodable"] += 1
            byt["undecodable"] += 1
            pos += 1

    tot = sum(cnt.values())
    totb = sum(byt.values())
    print(f"=== {name} RVA {va:#x}  ({vs:,} bytes, {tot:,} instructions) ===")
    for k in ("work", "threading", "padding", "stackop", "undecodable"):
        if cnt[k]:
            print(f"  {cnt[k]:>12,} insns  {byt[k]:>12,} B  {100*byt[k]/totb:>5.1f}%  {k}")
    print(f"  {'':>12}  {mut_bytes:>12,} B  {100*mut_bytes/totb:>5.1f}%  "
          f"mutation still un-rewritten (subset of the above)")
    print()
    grand.update(cnt)
    grand_b.update(byt)

tb = sum(grand_b.values())
print("=== BOTH EXECUTABLE SECTIONS ===")
for k in ("work", "threading", "padding", "stackop", "undecodable"):
    if grand[k]:
        print(f"  {grand[k]:>12,} insns  {grand_b[k]:>12,} B  {100*grand_b[k]/tb:>5.1f}%  {k}")
