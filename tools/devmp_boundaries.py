#!/usr/bin/env python3
"""Emit reloc_boundaries.json + reloc_seeds.txt - the ground-truth anchors everything else needs.

This step was missing from the first cut of the kit. `devmp_pushpop3.py` and `ThreadCFG.java`
both consume `reloc_boundaries.json`, and nothing produced it; `devmp_reloc.py` only prints
statistics and audits. Run this before either of them.

WHAT IT PRODUCES
  movabs_boundaries -- AUTHORITATIVE instruction starts. A DIR64 relocation marks an embedded
      absolute address; in `movabs reg,imm64` (REX + B8+r + imm64) the immediate begins at
      instr+2, so a relocation at R implies a real instruction start at R-2 whenever bytes[R-2]
      is REX and bytes[R-1] is B8..BF. The loader must patch exactly there or the image does not
      run -- this is ground truth, not a heuristic. On build 87221: 309,148 of 324,064 code
      relocations qualify (95.4%).
  code_targets     -- the relocated immediates that point back into code: the flattening
      block-entry / successor set, free of emulation. 245,572 distinct on 87221.

Relocations come from the BASERELOC *data directory*, never the `.reloc` SECTION -- VMProtect
leaves a decoy there with zero code entries. See peinfo.baserelocs().

Read the relocation ENTRIES from the ORIGINAL dump, not a patched image: our own rewrites never
touch relocated fields (audited: 0 of 557,628), but reading the table from the source keeps this
independent of that claim rather than assuming it.

  usage: devmp_boundaries.py <memaligned.bin> [source_dump.bin] [out.json] [out_seeds.txt]
"""
import sys, json, struct, collections
import peinfo

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp4_pe.bin"
SRC = sys.argv[2] if len(sys.argv) > 2 else IMG
OUT = sys.argv[3] if len(sys.argv) > 3 else "reloc_boundaries.json"
SEEDS = sys.argv[4] if len(sys.argv) > 4 else "reloc_seeds.txt"

d = open(IMG, "rb").read()
src = open(SRC, "rb").read() if SRC != IMG else d
B = peinfo.image_base(d)
EX = peinfo.exec_ranges(d)
inc = lambda x: any(lo <= x < hi for lo, hi in EX)

relocs = peinfo.baserelocs(d, src)
in_exec = [r for r in relocs if inc(r)]
print(f"image base {B:#x}   exec ranges {[(hex(a), hex(b)) for a, b in EX]}")
print(f"DIR64 relocations: {len(relocs):,}   inside executable code: {len(in_exec):,}")

bounds, targets = [], collections.Counter()
for r in sorted(in_exec):
    i = r - B
    if i < 2 or i + 8 > len(src):
        continue
    if 0x48 <= src[i - 2] <= 0x4F and 0xB8 <= src[i - 1] <= 0xBF:
        bounds.append(r - 2)
        (v,) = struct.unpack_from("<Q", src, i)
        if inc(v):
            targets[v] += 1

pct = 100.0 * len(bounds) / max(1, len(in_exec))
print(f"  `movabs reg,imm64` at reloc-2 : {len(bounds):,}  ({pct:.1f}%)  <- authoritative starts")
print(f"  distinct code targets         : {len(targets):,}  <- block-entry / successor set")
print(f"  targets referenced >1x        : {sum(1 for v in targets.values() if v > 1):,}")
if pct < 50:
    print("  LOW RATIO -- this build may encode threading differently. Verify before trusting"
          " the anchors; the whole boundary oracle rests on this pattern.")

json.dump({"movabs_boundaries": bounds, "code_targets": sorted(targets)}, open(OUT, "w"))
open(SEEDS, "w").write("".join("%x\n" % x for x in bounds))
print(f"wrote {OUT} and {SEEDS}")
