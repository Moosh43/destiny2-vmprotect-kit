#!/usr/bin/env python3
"""Independent alignment check on every site devmp_pushpop.py rewrote.

WHY THIS IS NEEDED
    `.pdata` covers ZERO of the 81 MB VMProtect .text (measured: 0 of 58,043 ranges fall inside
    it), so there are no authoritative function starts there. Every rewrite in that section
    rested on backward convergence -- the same heuristic that chose the sites in the first place.
    Checking a heuristic with itself proves nothing, so this uses a different method.

METHOD
    Resync linear sweep of the ORIGINAL image across each executable section: decode forward,
    and on an undecodable byte advance one byte and continue (capstone's disasm STOPS at the
    first bad byte -- that lesson is already recorded in this project). x86 is self-
    synchronising: a sweep started anywhere re-joins the true instruction stream within a few
    instructions, so over an 81 MB run the recovered boundary set is overwhelmingly correct.

    Then: what fraction of rewritten sites coincide with a swept boundary?
    Agreement = independent evidence the site was a real instruction start.
    Disagreement flags exactly the sites worth distrusting, by address.

    The sweep runs on the ORIGINAL bytes, because that is where the question lives -- was the
    pattern a real instruction pair before we touched it.

  usage: devmp_verify_sweep.py [orig.bin] [patched.bin]
"""
import sys, struct
import capstone
import psweep

ORIG = sys.argv[1] if len(sys.argv) > 1 else "destiny2_devmp_pe.bin"
NEW = sys.argv[2] if len(sys.argv) > 2 else "destiny2_devmp2_pe.bin"
B = 0x140000000

a = open(ORIG, "rb").read()
b = open(NEW, "rb").read()
assert len(a) == len(b), "images differ in length"

pe = struct.unpack_from("<I", a, 0x3C)[0]
nsec = struct.unpack_from("<H", a, pe + 6)[0]
opt = struct.unpack_from("<H", a, pe + 20)[0]
SECS = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    name = a[o:o + 8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ra = struct.unpack_from("<IIII", a, o + 8)
    ch = struct.unpack_from("<I", a, o + 36)[0]
    if ch & 0x20000000:
        SECS.append((name, va, vs, ra))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def sweep_boundaries(blob, base):
    """Resync linear sweep -> instruction-start offsets (relative to blob). Parallel, identical."""
    return psweep.sweep_boundaries(blob, base)


total_sites = total_ok = 0
bad_addrs = []

for name, va, vs, ra in SECS:
    # index content by VA (== RVA == file offset on a VA-ordered dump/image), NOT by the header
    # RA. On the raw extracted dump the RA fields are STALE (inherited from the on-disk exe) and
    # point nowhere near the bytes; only VA is valid before pe_memalign. Line below uses B+va as
    # the disasm base, so lo must be va for the content and the addresses to agree.
    lo, hi = va, va + vs
    # sites = starts of maximal differing runs
    sites = []
    i = lo
    while i < hi:
        if a[i] != b[i]:
            sites.append(i)
            j = i
            while j < hi and a[j] != b[j]:
                j += 1
            i = j
        else:
            i += 1
    print(f"=== {name} RVA {va:#x} ({vs:,} bytes): {len(sites):,} rewritten sites ===", flush=True)
    print("    sweeping original bytes...", flush=True)
    starts = sweep_boundaries(a[lo:hi], B + va)
    ok = sum(1 for s in sites if (s - lo) in starts)
    total_sites += len(sites)
    total_ok += ok
    miss = [B + va + (s - lo) for s in sites if (s - lo) not in starts]
    bad_addrs += miss[:200]
    pct = 100.0 * ok / max(1, len(sites))
    print(f"    boundaries recovered: {len(starts):,}")
    print(f"    sites confirmed by sweep: {ok:,}/{len(sites):,}  ({pct:.3f}%)")
    print(f"    NOT confirmed: {len(miss):,}", flush=True)

print(f"\nTOTAL confirmed {total_ok:,}/{total_sites:,} "
      f"({100.0*total_ok/max(1,total_sites):.3f}%)")
if bad_addrs:
    print("sample unconfirmed addresses:")
    for x in bad_addrs[:20]:
        print(f"  {x:#x}")
