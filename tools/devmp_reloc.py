#!/usr/bin/env python3
"""Use .reloc as a THIRD, authoritative oracle -- and as an audit of the de-mutation passes.

.pdata covers ZERO of the 81 MB VMProtect .text, which is why every rewrite there rested on
heuristics (backward convergence, then linear sweep). But .reloc was sitting right there:

  * Each IMAGE_REL_BASED_DIR64 entry marks an embedded 64-bit ABSOLUTE address. In
    `movabs reg, imm64` (REX + B8+r + imm64) the immediate starts at instr+2, so a reloc at R
    implies a real instruction boundary at R-2 whenever bytes[R-2] is REX and bytes[R-1] is B8..BF.
    That is ground truth, not a heuristic -- the loader must patch exactly there or the image
    breaks.
  * Those relocated immediates that point back into the code sections ARE the flattening
    successor targets, i.e. the block-entry address set, obtained with no emulation.
  * AUDIT: no rewrite may overlap a relocated field. If one does, we nop'd over an absolute
    address -- meaning that range was DATA and the rewrite was wrong. Zero overlaps is strong
    independent evidence the passes were sound.

  usage: devmp_reloc.py [orig.bin] [patched.bin]
"""
import sys, struct, collections, bisect

ORIG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_full_image.bin"
NEW = sys.argv[2] if len(sys.argv) > 2 else "destiny2_devmp3_pe.bin"
B = 0x140000000

a = open(ORIG, "rb").read()
b = open(NEW, "rb").read()

# section table from the memory-aligned image (ra == va there)
pe = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe + 6)[0]
opt = struct.unpack_from("<H", b, pe + 20)[0]
SECS, EXEC = [], []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = b[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", b, o + 8)
    ch = struct.unpack_from("<I", b, o + 36)[0]
    SECS.append((name, va, vs, ra, ch))
    if ch & 0x20000000:
        EXEC.append((name, va, vs, ra))

# DO NOT USE THE `.reloc` SECTION. VMProtect left the original there (116,914 DIR64, ALL of
# them in .rdata/.data, ZERO in code) and moved the REAL table into its own .text section. Only
# the BASERELOC data directory points at the one the loader actually uses: 441,006 DIR64, of
# which 324,064 are inside executable code.
_rva, _sz = struct.unpack_from("<II", b, pe + 24 + 112 + 5 * 8)
reloc = (".reloc(dir)", _rva, _sz, _rva, 0)
_leftover = next((s for s in SECS if s[0] == ".reloc"), None)
print(f"BASERELOC directory  RVA {_rva:#x}  size {_sz:,} bytes   <- the real one")
print(f"'.reloc' section     RVA {_leftover[1]:#x}  size {_leftover[2]:,} bytes   "
      f"<- VMProtect leftover, .rdata/.data only\n")

# --- parse the base relocation blocks -------------------------------------------------------
TYPES = {0: "ABSOLUTE(pad)", 3: "HIGHLOW(32)", 10: "DIR64"}
kinds = collections.Counter()
dir64 = []
off, end = reloc[1], reloc[1] + reloc[2]
while off + 8 <= end:
    page, size = struct.unpack_from("<II", a, off)
    if size < 8 or off + size > end:
        break
    for k in range(off + 8, off + size, 2):
        (w,) = struct.unpack_from("<H", a, k)
        t, o2 = w >> 12, w & 0xFFF
        kinds[TYPES.get(t, f"type{t}")] += 1
        if t == 10:
            dir64.append(B + page + o2)
    off += size

print("relocation entries by type:")
for k, v in kinds.most_common():
    print(f"  {v:>10,}  {k}")

dir64.sort()
print(f"\nDIR64 entries: {len(dir64):,}")


def sec_of(addr):
    for name, va, vs, ra in EXEC:
        if B + va <= addr < B + va + vs:
            return name, va, ra
    return None


in_exec = [x for x in dir64 if sec_of(x)]
print(f"  inside executable sections: {len(in_exec):,}")

# --- 1. authoritative instruction boundaries -------------------------------------------------
movabs = 0
targets = []
for r in in_exec:
    s = sec_of(r)
    if not s:
        continue
    i = r - B
    if i >= 2 and 0x48 <= a[i - 2] <= 0x4F and 0xB8 <= a[i - 1] <= 0xBF:
        movabs += 1
        (v,) = struct.unpack_from("<Q", a, i)
        targets.append(v)
print(f"  of those, a `movabs reg,imm64` starts at reloc-2: {movabs:,} "
      f"({100*movabs/max(1,len(in_exec)):.1f}%)  <- authoritative boundaries")

import peinfo   # was hardcoded to 87221
_er = peinfo.exec_ranges(b)
_inx = lambda x: any(lo <= x < hi for lo, hi in _er)
code_t = [t for t in targets if _inx(t)]
print(f"  relocated immediates pointing INTO code: {len(code_t):,} "
      f"({len(set(code_t)):,} distinct) <- block-entry / successor set")

# --- 2. AUDIT: did any rewrite touch a relocated field? --------------------------------------
patched = []
for name, va, vs, ra in EXEC:
    i, hi = ra, ra + vs
    while i < hi:
        if a[i] != b[i]:
            j = i
            while j < hi and a[j] != b[j]:
                j += 1
            patched.append((B + i, B + j))
            i = j
        else:
            i += 1
print(f"\nAUDIT: {len(patched):,} rewritten ranges vs {len(in_exec):,} relocated fields in code")
starts = [p[0] for p in patched]
hits = []
for r in in_exec:
    for f in range(8):                      # the relocated field is 8 bytes wide
        k = bisect.bisect_right(starts, r + f) - 1
        if k >= 0 and patched[k][0] <= r + f < patched[k][1]:
            hits.append(r)
            break
print(f"  rewrites overlapping a relocated address: {len(hits):,}")
for h in hits[:20]:
    print(f"    {h:#x}   orig {a[h-B:h-B+8].hex()}  new {b[h-B:h-B+8].hex()}")
if not hits:
    print("  -> CLEAN: no rewrite ever overwrote an absolute address the loader must patch.")
