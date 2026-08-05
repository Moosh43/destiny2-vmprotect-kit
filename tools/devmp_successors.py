#!/usr/bin/env python3
"""Build the flattening SUCCESSOR MAP: block-terminating `ret` -> successor address(es).

This is the artifact BOTH de-threading routes need:
  A. Ghidra CFG repair -- apply as flow overrides + references so each `ret` becomes a branch
     to a known target and the CFG reconnects. Zero byte risk.
  B. Relocating re-emitter -- needs the same edges to lay out clean function bodies.

STRUCTURE BEING RESOLVED
    A flattened block plants its successor on the stack and returns to it:
        <load target into reg>      movabs reg, T   |   lea reg, [rip+d]
        xchg [rsp], reg             [rsp] = T, reg = old [rsp]
        <body>
        ret                         -> jumps to T
    Conditional blocks load a second candidate and `cmov` between them, so a block can have TWO
    successors.

TWO LOADING FORMS, AND THE ANCHORS ONLY COVER ONE
    `movabs reg,imm64` embeds an ABSOLUTE address, so it carries a relocation -- those are the
    309,148 ground-truth anchors. But `lea reg,[rip+disp32]` is RIP-RELATIVE and needs NO
    relocation, so it is completely absent from the reloc table. Scanning only relocations would
    silently miss every lea-form block. Both are scanned here, and reported separately so the
    split is visible rather than assumed.

Emits successors.json: {ret_addr: [targets]} plus per-form coverage stats.
"""
import sys, re, json, struct, collections
import capstone

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp4_pe.bin"
OUT = sys.argv[2] if len(sys.argv) > 2 else "successors.json"
B = 0x140000000
WINDOW = 320                      # max bytes from target-load to the block's ret

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
d = open(IMG, "rb").read()

# was hardcoded to build 87221 -- derive from the PE header so this works on other builds
import peinfo
EXEC = tuple(peinfo.exec_ranges(d))
B = peinfo.image_base(d)
incode = lambda x: any(lo <= x < hi for lo, hi in EXEC)

# ---- collect target-load sites -------------------------------------------------------------
# form 1: movabs reg, imm64  (relocation-anchored = ground truth)
anchors = json.load(open("reloc_boundaries.json"))["movabs_boundaries"]
sites = []
for A in anchors:
    i = A - B
    reg = (d[i + 1] - 0xB8) | ((d[i] & 1) << 3)
    (t,) = struct.unpack_from("<Q", d, i + 2)
    if incode(t):
        sites.append((A, 10, reg, t, "movabs"))

# form 2: lea reg, [rip+disp32] -- NO relocation exists for these
for lo, hi in EXEC:
    blob = d[lo - B + (B - B):hi - B] if False else d[lo - B:hi - B]
    for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", blob):
        a = B + lo - B + m.start()
        i = a - B
        if i + 7 > len(d):
            continue
        (disp,) = struct.unpack_from("<i", d, i + 3)
        t = a + 7 + disp
        if incode(t):
            reg = ((d[i + 2] >> 3) & 7) | ((d[i] & 4) << 1)
            sites.append((a, 7, reg, t, "lea"))

sites.sort()
print(f"target-load sites: {len(sites):,} "
      f"({sum(1 for s in sites if s[4]=='movabs'):,} movabs / "
      f"{sum(1 for s in sites if s[4]=='lea'):,} lea)", flush=True)

# ---- walk each site to its xchg and then to the block's ret --------------------------------
XCHG = {}      # (rex,modrm) -> reg  for `xchg [rsp],reg`
for r in range(16):
    XCHG[bytes([0x4C if r >= 8 else 0x48, 0x87, 0x04 | ((r & 7) << 3), 0x24])] = r

succ = collections.defaultdict(set)
stat = collections.Counter()

for addr, ln, reg, tgt, form in sites:
    i = addr - B + ln
    # the xchg must follow within a few instructions (other movabs/cmov may intervene)
    j, found = i, False
    for _ in range(6):
        if d[j:j + 4] in XCHG:
            if XCHG[d[j:j + 4]] == reg:
                found = True
            break
        ins = next(md.disasm(d[j:j + 16], B + j), None)
        if ins is None:
            break
        j += ins.size
    if not found:
        stat[f"{form}: no matching xchg"] += 1
        continue
    j += 4
    # forward to the terminating ret
    end = j + WINDOW
    ret = None
    while j < end:
        ins = next(md.disasm(d[j:j + 16], B + j), None)
        if ins is None:
            break
        if ins.mnemonic == "ret":
            ret = ins.address
            break
        if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
            break                       # left the block by a direct branch
        j += ins.size
    if ret is None:
        stat[f"{form}: no ret in window"] += 1
        continue
    succ[ret].add(tgt)
    stat[f"{form}: resolved"] += 1

print("\nresolution:")
for k, v in sorted(stat.items()):
    print(f"  {v:>9,}  {k}")

deg = collections.Counter(len(v) for v in succ.values())
print(f"\nblocks with a resolved successor: {len(succ):,}")
for k in sorted(deg):
    print(f"  {deg[k]:>9,}  blocks with {k} successor(s)")

json.dump({hex(k): [hex(x) for x in sorted(v)] for k, v in succ.items()}, open(OUT, "w"))
# the Ghidra scripts read the TEXT form ("<ret> <target> [target2 ...]" per line), not JSON --
# parsing JSON in a Ghidra script without dependencies is needless friction. Emit both here so
# the pipeline has no manual conversion step.
TXT = OUT.rsplit(".", 1)[0] + ".txt"
with open(TXT, "w") as f:
    for k in sorted(succ):
        f.write("%x %s\n" % (k, " ".join("%x" % x for x in sorted(succ[k]))))
print(f"\nwrote {OUT} and {TXT}")
