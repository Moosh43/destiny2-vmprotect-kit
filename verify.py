#!/usr/bin/env python3
"""Confirm your dump is the build this kit's address metadata was derived from.

WHY NOT SHA-256 OF THE CODE SECTIONS (the obvious approach, and wrong)
   Two dumps of the SAME build are not byte-identical. Measured across two captures:
   287 bytes differ in .text#1 and 1,234 in .text#2 -- 0.001%, in 127 short runs -- because a
   dump freezes runtime state (IAT binding, installed hooks, self-modified stubs). An exact hash
   would therefore reject every legitimate dump, including a correct one. This checks STRUCTURAL
   invariants instead: things identical across captures but different across builds.

Passing means the shipped addresses in data/ apply to your dump. Failing means regenerate data/
from your own image -- using 87221 addresses on another build gives plausible, silently wrong
results.

  usage: verify.py [dump.bin]
"""
import sys, re, struct

IMG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_full_image.bin"

EXPECT_SIZE = 145_010_688
EXPECT_BASE = 0x140000000
EXPECT_VERSION = b"87221.20.09.10.1506"
EXPECT_SECTIONS = [
    (".text", 0x1000, 0x1B8AC00), (".rdata", 0x1B8C000, 0x37E600),
    (".data", 0x1F0B000, 0x16BE9B0), (".pdata", 0x35CA000, 0x14D800),
    (".vmp0", 0x3718000, 0x484000), (".tls", 0x3B9C000, 0x9AC00),
    ("_RDATA", 0x3C37000, 0xE00), (".rsrc", 0x3C38000, 0x4A400),
    (".reloc", 0x3C83000, 0x3A800), (".idata", 0x3CBE000, 0x4400),
    (".text", 0x3CC3000, 0x4D87200),
]
EXPECT_DIR64 = 441_006
EXPECT_IDIOMS = 813_162          # mutation sites in an UNTOUCHED dump (measured identical across 2 captures)
TOL = 0.01                       # 1% -- absorbs the ~1.5k bytes of run-to-run variation

d = open(IMG, "rb").read()
print(f"{IMG}: {len(d):,} bytes\n")
fails = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{'  ' + detail if detail else ''}")
    if not ok:
        fails.append(name)


check("file size", len(d) == EXPECT_SIZE, f"expected {EXPECT_SIZE:,}")
if len(d) < 0x1000:
    sys.exit("file far too small to be an image")

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
check("image base", base == EXPECT_BASE, f"got {base:#x}, expected {EXPECT_BASE:#x}")

got = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    nm = d[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
    got.append((nm, va, vs))
check("section layout", got == EXPECT_SECTIONS,
      "" if got == EXPECT_SECTIONS else f"{len(got)} sections, layout differs")

check("version string", EXPECT_VERSION in d, EXPECT_VERSION.decode())

# relocation count, from the BASERELOC DIRECTORY (not the decoy .reloc section)
rva, sz = struct.unpack_from("<II", d, pe + 24 + 112 + 5 * 8)
n = 0
off, end = rva, rva + sz
while off + 8 <= end:
    page, size = struct.unpack_from("<II", d, off)
    if size < 8 or off + size > end:
        break
    for k in range(off + 8, off + size, 2):
        (w,) = struct.unpack_from("<H", d, k)
        if w >> 12 == 10:
            n += 1
    off += size
check("DIR64 relocations", abs(n - EXPECT_DIR64) <= EXPECT_DIR64 * TOL,
      f"{n:,} (expected ~{EXPECT_DIR64:,})")

# mutation idiom census -- confirms this is an UNTOUCHED dump of this build
mut = [bytes.fromhex("488d642408ff6424f8")]
for i in range(16):
    rex, r = (0x4C if i >= 8 else 0x48), (i & 7)
    mut += [bytes([rex, 0x89, 0x44 | (r << 3), 0x24, 0xF8]) + bytes.fromhex("488d6424f8"),
            bytes.fromhex("488d6424f8") + bytes([rex, 0x89, 0x04 | (r << 3), 0x24]),
            bytes([rex, 0x8B, 0x04 | (r << 3), 0x24]) + bytes.fromhex("488d642408"),
            bytes.fromhex("488d642408") + bytes([rex, 0x8B, 0x44 | (r << 3), 0x24, 0xF8])]
tot = 0
for lo, hi in ((0x1000, 0x1B8BC00), (0x3CC3000, 0x8A4A200)):
    b = d[lo:hi]
    tot += sum(len(re.findall(re.escape(p), b)) for p in mut)
check("mutation idioms present", abs(tot - EXPECT_IDIOMS) <= EXPECT_IDIOMS * TOL,
      f"{tot:,} (expected ~{EXPECT_IDIOMS:,}; near 0 means already de-mutated)")

print()
if fails:
    print("FAILED: " + ", ".join(fails))
    print("   The shipped data/ does NOT apply. Regenerate it from your own image:")
    print("     tools/devmp_boundaries.py <memaligned.bin> <dump.bin>")
    print("     tools/devmp_successors.py <memaligned.bin>")
    sys.exit(1)
print("build 87221 confirmed - the shipped address metadata applies to this dump.")
