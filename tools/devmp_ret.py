#!/usr/bin/env python3
"""Rewrite VMProtect obfuscated returns to real `ret` in an ANALYSIS COPY of the image.

    lea rsp,[rsp+8] ; jmp qword [rsp-8]   (9 bytes)  ==  ret
Both pop the top of stack into rip and leave rsp 8 higher, so the equivalence holds in ANY
context. Rewritten to `C3` + 8x `nop` -- same length, so nothing moves.

Why: Ghidra models `jmp [rsp-8]` as an indirect jump, which (a) marks the function
"does not return" and (b) breaks its stack-depth model, so callers decompile truncated.
That cost a 389-instruction hand-lift of FUN_140FCB2B0 this session.

Each site is verified instruction-aligned by BACKWARD CONVERGENCE (decode from several earlier
offsets; majority must land exactly on the site). Unverified sites are skipped.

ANALYSIS ONLY. Not runnable. Never ship this to the client.
  usage: devmp_ret.py [dump.bin] [out.bin]
"""
import re,sys,capstone
import psweep
# input is a parameter: the dump filename is the user's choice, not ours
SRC=sys.argv[1] if len(sys.argv)>1 else "destiny2_full_image.bin"
DST=sys.argv[2] if len(sys.argv)>2 else "destiny2_devmp.bin"
B=0x140000000
d=bytearray(open(SRC,"rb").read())
PAT=bytes.fromhex("488d642408ff6424f8"); REP=b"\xc3"+b"\x90"*8
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
raw=bytes(d)
def aligned(off,back=24):
    yes=no=0
    for b in range(4,back,4):
        st=off-b
        if st<0: continue
        hit=False
        for i in md.disasm(raw[st:off+9], B+st):
            if i.address==B+off: hit=True; break
            if i.address>B+off: break
        yes+=hit; no+=(not hit)
    return yes>no
hits=[m.start() for m in re.finditer(re.escape(PAT), raw)]
print(f"  pattern sites: {len(hits)}")
# backward-convergence verdict is pure over `raw` -> evaluate all sites in parallel (step 4, yes>no)
verdict=psweep.batch_aligned(raw, B, [(h,9) for h in hits], back=24, step=4, strong=1.0, min_yes=0)
n=skip=0
for h in hits:
    if verdict[(h,9)]: d[h:h+9]=REP; n+=1
    else: skip+=1
open(DST,"wb").write(bytes(d))
print(f"  rewritten to `ret`: {n}      skipped (unaligned): {skip}")
print(f"  wrote {DST}")
