#!/usr/bin/env python3
"""Derive image base and executable section ranges from the PE header.

PORTING NOTE. Several tools originally hardcoded build 87221's layout:
    B    = 0x140000000
    EXEC = ((0x140001000, 0x141b8bc00), (0x143cc3000, 0x148a4a200))
Those literals are that ONE build's section table. On any other build they are wrong, and wrong
in the worst way -- the scan silently covers the wrong byte ranges and reports plausible numbers.
Import from here instead so the layout comes from the file being analysed.

Assumes the memory-aligned image produced by pe_memalign.py, where ra == va and therefore
file offset == RVA. Run pe_memalign.py first.
"""
import struct


def _hdr(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    return pe, nsec, opt


def image_base(d):
    pe, _, _ = _hdr(d)
    return struct.unpack_from("<Q", d, pe + 24 + 24)[0]


def sections(d):
    """-> [(name, va, vsize, raw_off, characteristics)] with va as an RVA."""
    pe, nsec, opt = _hdr(d)
    out = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode(errors="replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        ch = struct.unpack_from("<I", d, o + 36)[0]
        out.append((name, va, vs, ra, ch))
    return out


def exec_ranges(d, absolute=True):
    """-> [(lo, hi)] for executable sections. absolute=True adds the image base."""
    B = image_base(d) if absolute else 0
    return [(B + va, B + va + vs) for _, va, vs, _, ch in sections(d) if ch & 0x20000000]


def data_directory(d, index):
    pe, _, _ = _hdr(d)
    return struct.unpack_from("<II", d, pe + 24 + 112 + index * 8)


def baserelocs(d, src=None):
    """DIR64 relocation addresses from the BASERELOC *data directory*.

    NOT from the `.reloc` section -- VMProtect leaves a decoy there with zero code entries and
    moves the real table into its own .text. Only the directory finds the one the loader uses.
    `src` lets you read entries out of a different (e.g. pre-patch) image.
    """
    if src is None:
        src = d
    B = image_base(d)
    rva, sz = data_directory(d, 5)
    out, off, end = [], rva, rva + sz
    while off + 8 <= end:
        page, size = struct.unpack_from("<II", src, off)
        if size < 8 or off + size > end:
            break
        for k in range(off + 8, off + size, 2):
            (w,) = struct.unpack_from("<H", src, k)
            if w >> 12 == 10:
                out.append(B + page + (w & 0xFFF))
        off += size
    return out


if __name__ == "__main__":
    import sys
    d = open(sys.argv[1], "rb").read()
    print(f"image base {image_base(d):#x}")
    for nm, va, vs, ra, ch in sections(d):
        print(f"  {nm:10} va={va:#010x} vs={vs:#010x} ra={ra:#010x} "
              f"{'EXEC' if ch & 0x20000000 else ''}")
    print("exec ranges:", [(hex(a), hex(b)) for a, b in exec_ranges(d)])
    print(f"BASERELOC DIR64 entries: {len(baserelocs(d)):,}")
