#!/usr/bin/env python3
"""Census the VMProtect MUTATION idioms still present in the analysis image.

Measure before transforming. devmp_ret.py already converted the obfuscated `ret`
(191,616 of 198,674 sites); this counts what is LEFT, so the next transforms are chosen by
frequency instead of by guesswork.

Runs on destiny2_devmp_pe.bin, where every section has ra == va, so file offset == RVA and a
match's address is just B + offset. Both executable sections are scanned separately: the
original .text (RVA 0x1000) and the 81 MB VMProtect-added .text (RVA 0x3cc3000).

Pure byte-pattern counting -- no alignment check yet. Counts here are an UPPER BOUND; some
matches will be data or mid-instruction coincidences. That is fine for choosing targets.

  usage: devmp_census.py [image]
"""
import sys, re, struct, collections

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp_pe.bin"
B = 0x140000000
d = open(IMG, "rb").read()

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
secs = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = d[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
    ch = struct.unpack_from("<I", d, o + 36)[0]
    if ch & 0x20000000:
        secs.append((name, va, vs, ra))

# --- the idioms ------------------------------------------------------------------------------
# Registers in modrm reg-field order, and which REX prefix selects them.
REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def rex_and_reg(i):
    """-> (rex_byte, modrm_reg_field) for register index i using a [rsp+disp] SIB memory operand."""
    return (0x4C if i >= 8 else 0x48), (i & 7)


pats = collections.OrderedDict()

# obfuscated ret -- what devmp_ret.py rewrites. Any left = sites it judged unaligned.
pats["ret  : lea rsp,[rsp+8] ; jmp [rsp-8]"] = [bytes.fromhex("488d642408ff6424f8")]

# obfuscated push: mov [rsp-8],reg ; lea rsp,[rsp-8]
p = []
for i in range(16):
    rex, r = rex_and_reg(i)
    p.append(bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8"))
pats["push : mov [rsp-8],reg ; lea rsp,[rsp-8]"] = p

# obfuscated pop: mov reg,[rsp] ; lea rsp,[rsp+8]
p = []
for i in range(16):
    rex, r = rex_and_reg(i)
    p.append(bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408"))
pats["pop  : mov reg,[rsp] ; lea rsp,[rsp+8]"] = p

# obfuscated jmp: push imm32 ; ret     (68 imm32 C3)
pats["jmp  : push imm32 ; ret"] = None   # handled by regex below

# stack adjust pairs that cancel: lea rsp,[rsp-8] ; lea rsp,[rsp+8]
pats["junk : lea rsp,[rsp-8] ; lea rsp,[rsp+8]"] = [bytes.fromhex("488d6424f8488d642408")]
pats["junk : lea rsp,[rsp+8] ; lea rsp,[rsp-8]"] = [bytes.fromhex("488d642408488d6424f8")]

# already-converted rets, to confirm the previous pass landed
pats["done : ret + 8x nop (already converted)"] = [b"\xc3" + b"\x90" * 8]

print(f"image {IMG}  ({len(d):,} bytes)\n")
for name, va, vs, ra in secs:
    blob = d[ra:ra + vs]
    print(f"=== {name}  RVA {va:#x}-{va+vs:#x}  ({vs:,} bytes) ===")
    for label, plist in pats.items():
        if plist is None:
            n = len(re.findall(rb"\x68....\xc3", blob, re.S))
        else:
            n = sum(len(re.findall(re.escape(x), blob)) for x in plist)
        if n:
            print(f"  {n:>9,}  {label}")
    print()
