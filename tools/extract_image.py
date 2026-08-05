#!/usr/bin/env python3
"""Extract the loaded destiny2.exe image from a process dump - step 0 of the pipeline.

The on-disk exe is encrypted (0.58% / 9.43% identical to runtime), so every tool here needs a
RUNTIME image. This reassembles it - flat, **file offset == RVA**, from the module base - out of
whatever dump you made where the game was running:

  * Windows minidump (.dmp)  -- Task Manager "Create dump file", or `procdump -ma destiny2.exe`
  * Linux/Proton ELF core    -- `gcore <pid>`

The format is auto-detected. IMPORTANT for cross-environment use: DUMP where the process runs
(native Windows, or Proton on Linux), then run this + the rest of the kit ANYWHERE - WSL, another
Linux box - since analysis is just Python. WSL cannot dump a native-Windows process, so you must
make the .dmp on Windows first.

For a minidump the module base+size are read from the dump's module list (so ASLR is handled
automatically); for an ELF core you pass them (default 0x140000000 / 145,010,688). if the base
is not 0x140000000, the shipped data/ (pinned to that base) must be regenerated.

Gaps (unmapped/unreadable regions) are zero-filled and reported: a gap inside .text means the dump
is incomplete and downstream results would be wrong - re-dump with the game fully loaded.

  usage: extract_image.py <dump> [out.bin] [base_hex] [size]
"""
import sys, struct

DUMP = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else "destiny2_full_image.bin"
ARG_BASE = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
ARG_SIZE = int(sys.argv[4]) if len(sys.argv) > 4 else None
DEF_BASE, DEF_SIZE = 0x140000000, 145_010_688


def write_image(ranges_reader, base, size):
    """ranges_reader yields (vaddr, nbytes, read_fn); read_fn()->bytes. Reassemble RVA-ordered."""
    img = bytearray(size)
    covered = 0
    for vaddr, nbytes, read in ranges_reader:
        lo = max(vaddr, base)
        hi = min(vaddr + nbytes, base + size)
        if lo >= hi:
            continue
        img[lo - base:hi - base] = read(lo - vaddr, hi - lo)
        covered += hi - lo
    open(OUT, "wb").write(bytes(img))
    pct = 100.0 * covered / size
    print(f"wrote {OUT}  ({size:,} bytes, {covered:,} covered = {pct:.3f}%)")
    if pct < 99.9:
        print("INCOMPLETE - unmapped regions were zero-filled. If gaps land in .text the "
              "downstream results will be wrong. Re-dump with the game fully loaded at the menu.")
    else:
        print("run verify.py on it next")


# ---------------------------------------------------------------- ELF core (gcore) ----------
def do_elf(f):
    base = ARG_BASE or DEF_BASE
    size = ARG_SIZE or DEF_SIZE
    f.seek(0)
    hdr = f.read(64)
    if hdr[4] != 2:
        sys.exit("expected a 64-bit ELF core")
    e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
    e_phnum = struct.unpack_from("<H", hdr, 56)[0]
    if e_phnum == 0xFFFF:
        sys.exit("extended program header count not handled")
    f.seek(e_phoff)
    ph = f.read(e_phentsize * e_phnum)
    segs = []
    for i in range(e_phnum):
        o = i * e_phentsize
        if struct.unpack_from("<I", ph, o)[0] != 1:        # PT_LOAD
            continue
        p_off = struct.unpack_from("<Q", ph, o + 8)[0]
        p_va = struct.unpack_from("<Q", ph, o + 16)[0]
        p_fsz = struct.unpack_from("<Q", ph, o + 32)[0]
        if p_fsz and p_va + p_fsz > base and p_va < base + size:
            segs.append((p_va, p_off, p_fsz))
    if not segs:
        sys.exit(f"no PT_LOAD segment covers {base:#x}..{base+size:#x} - wrong base, or the core "
                 f"does not contain the module")
    segs.sort()
    print(f"ELF core: {len(segs)} segments overlap the module range")

    def gen():
        for va, off, fsz in segs:
            yield va, fsz, (lambda o0, n, off=off, va=va: (f.seek(off + o0), f.read(n))[1])
    write_image(gen(), base, size)


# ---------------------------------------------------------------- Windows minidump ----------
def do_minidump(f):
    f.seek(0)
    data = f.read(0x1000000) if False else None   # streams are small; read on demand via seek
    f.seek(0)
    head = f.read(32)
    nstreams = struct.unpack_from("<I", head, 8)[0]
    dir_rva = struct.unpack_from("<I", head, 12)[0]
    f.seek(dir_rva)
    dirs = f.read(12 * nstreams)
    streams = {}
    for i in range(nstreams):
        st, dsz, rva = struct.unpack_from("<III", dirs, i * 12)
        streams[st] = (dsz, rva)

    # module list (type 4): find destiny2.exe -> base, size (unless overridden)
    base, size = ARG_BASE, ARG_SIZE
    if 4 in streams and (base is None or size is None):
        _, mrva = streams[4]
        f.seek(mrva)
        nmod = struct.unpack_from("<I", f.read(4), 0)[0]
        mods = f.read(108 * nmod)
        for i in range(nmod):
            b, sz = struct.unpack_from("<QI", mods, i * 108)
            name_rva = struct.unpack_from("<I", mods, i * 108 + 20)[0]
            f.seek(name_rva)
            slen = struct.unpack_from("<I", f.read(4), 0)[0]
            name = f.read(slen).decode("utf-16-le", "replace")
            if name.lower().replace("\\", "/").endswith("destiny2.exe"):
                if base is None:
                    base = b
                if size is None:
                    size = sz
                print(f"minidump module: {name.split('/')[-1]}  base={b:#x}  size={sz:,}")
                break
    if base is None:
        base = DEF_BASE
    if size is None:
        size = DEF_SIZE
    if base != DEF_BASE:
        print(f"module base is {base:#x}, not {DEF_BASE:#x} - the shipped data/ (pinned to "
              f"{DEF_BASE:#x}) will NOT apply; regenerate it, or the addresses will be off.")

    # memory ranges: Memory64List (9, full dumps) or MemoryList (5)
    if 9 in streams:
        _, rva = streams[9]
        f.seek(rva)
        nranges, base_rva = struct.unpack_from("<QQ", f.read(16))
        descs = f.read(16 * nranges)
        rr = []
        off = base_rva
        for i in range(nranges):
            sva, dsz = struct.unpack_from("<QQ", descs, i * 16)
            rr.append((sva, dsz, off))
            off += dsz
        print(f"minidump (Memory64List): {nranges} ranges")

        def gen():
            for sva, dsz, foff in rr:
                if sva + dsz > base and sva < base + size:
                    yield sva, dsz, (lambda o0, n, foff=foff: (f.seek(foff + o0), f.read(n))[1])
        write_image(gen(), base, size)
    elif 5 in streams:
        _, rva = streams[5]
        f.seek(rva)
        nranges = struct.unpack_from("<I", f.read(4), 0)[0]
        descs = f.read(16 * nranges)
        rr = [struct.unpack_from("<QII", descs, i * 16) for i in range(nranges)]  # (sva,dsz,rva)
        print(f"minidump (MemoryList): {nranges} ranges")

        def gen():
            for sva, dsz, drva in rr:
                if sva + dsz > base and sva < base + size:
                    yield sva, dsz, (lambda o0, n, drva=drva: (f.seek(drva + o0), f.read(n))[1])
        write_image(gen(), base, size)
    else:
        sys.exit("minidump has no memory stream - make a FULL dump (Task Manager 'Create dump "
                 "file', or `procdump -ma`), not a minimal one")


f = open(DUMP, "rb")
magic = f.read(4)
if magic == b"\x7fELF":
    do_elf(f)
elif magic == b"MDMP":
    do_minidump(f)
else:
    sys.exit(f"unrecognised dump format (magic {magic!r}) - expected an ELF core (gcore) or a "
             f"Windows minidump (MDMP). If this is already an extracted image, skip this step.")
