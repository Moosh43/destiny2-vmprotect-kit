#!/usr/bin/env python3
"""Is in-place de-threading feasible? Measure the space available at each block tail.

A flattened block is:
    movabs reg, T        10 B    plant the successor address
    xchg  [rsp], reg      4 B    [rsp] = T, reg = old [rsp]
    <body>
    ret                   1 B    consumes it -> jumps to T
Net effect of the pair + ret == `pop reg` (at the head) + `jmp T` (at the tail).

The head is easy: 14 bytes available, `pop reg` needs 1-2.
The TAIL is the blocker: `jmp rel32` needs 5 bytes and `ret` is 1. In-place rewriting is only
possible where >= 4 spare bytes sit immediately BEFORE the ret -- which is now sometimes true,
because devmp_pushpop.py left 8 nops behind at every rewritten push/pop.

So: for each movabs+xchg site, walk forward to its `ret` and count the nop run before it.
    >= 5 usable bytes -> in-place `jmp rel32` fits
    < 5              -> needs relocation to new space (cannot be done in place)

Also splits conditional (cmov-selected successor) from unconditional threading, because a
conditional tail needs `jcc rel32` (6 B) plus a fallthrough `jmp` (5 B) = 11 B, far more room.
"""
import sys, re, struct, collections
import capstone

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp2_pe.bin"
B = 0x140000000
d = open(IMG, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

import peinfo   # was hardcoded to 87221: pick the LARGEST exec section (VMProtect's)
_secs = [s for s in peinfo.sections(d) if s[4] & 0x20000000]
_big = max(_secs, key=lambda s: s[2])
LO, HI = _big[1], _big[1] + _big[2]
blob = d[LO:HI]
base = B + LO

# movabs reg,imm64 ; xchg [rsp],reg
pat = re.compile(rb"\x48(?P<op>[\xb8-\xbf])(?P<imm>.{8})\x48\x87(?P<mr>[\x04\x0c\x14\x1c\x24\x2c\x34\x3c])\x24", re.S)

room = collections.Counter()
cond = collections.Counter()
dist = []
n = 0
no_ret = 0

for m in pat.finditer(blob):
    n += 1
    imm = struct.unpack("<Q", m.group("imm"))[0]
    if not any(lo <= imm < hi for lo, hi in peinfo.exec_ranges(d)):
        room["target not in code"] += 1
        continue
    e = m.end()
    j = blob.find(b"\xc3", e, e + 256)      # the block's terminating ret
    if j < 0:
        no_ret += 1
        continue
    dist.append(j - e)
    # count nop bytes immediately before the ret
    k = j
    while k > e and blob[k - 1] == 0x90:
        k -= 1
    spare = (j - k) + 1                     # nops + the ret byte itself
    room[">=5 (jmp rel32 fits)" if spare >= 5 else f"{spare} bytes"] += 1
    # is the successor conditional? look for a cmov in the block body
    body = blob[e:j]
    cond["conditional (cmov in block)" if re.search(rb"\x48\x0f[\x40-\x4f]", body)
         else "unconditional"] += 1

print(f"image {IMG}   VMProtect .text {HI-LO:,} bytes")
print(f"movabs+xchg[rsp] blocks: {n:,}   (no ret within 256 B: {no_ret:,})\n")
print("TAIL SPACE (bytes available where `jmp rel32` must go):")
for k, v in room.most_common():
    print(f"  {v:>9,}  {100*v/max(1,n):>5.1f}%  {k}")
print("\nSUCCESSOR KIND:")
for k, v in cond.most_common():
    print(f"  {v:>9,}  {100*v/max(1,sum(cond.values())):>5.1f}%  {k}")
if dist:
    dist.sort()
    print(f"\nblock body size: median {dist[len(dist)//2]} B, "
          f"p90 {dist[int(len(dist)*0.9)]} B, max {dist[-1]} B")
