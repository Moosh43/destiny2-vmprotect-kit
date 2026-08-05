#!/usr/bin/env python3
"""Parallel primitives for the de-mutation passes - byte-identical to the serial versions.

The dominant cost is the resync linear sweep (millions of capstone decodes) and the per-site
backward-convergence check, both single-threaded. Both are embarrassingly parallel across
independent byte ranges. The hard requirement is that the OUTPUT is bit-for-bit identical to the
serial code, because the pipeline is validated byte-for-byte - so the parallelism is arranged to
produce exactly the same boundary set / alignment verdicts, never an approximation.

HOW IDENTITY IS PRESERVED
  * Sweep: each worker sweeps [chunk_start - OVERLAP, chunk_end) but keeps only boundaries in
    [chunk_start, chunk_end). x86 is self-synchronising - a sweep started anywhere rejoins the true
    instruction stream within a few dozen bytes - so with a 64 KB runway every worker is aligned
    with the serial stream long before its kept region begins. Union of the parts == serial set.
  * Alignment: the backward-convergence verdict for an offset is a pure function of the (unchanged)
    original bytes, so it can be computed for every candidate in parallel and applied serially in
    the original order.

Linux fork is used, so the big blob is shared copy-on-write via a module global rather than pickled
to each worker (pickling 110 MB per task would erase the win).
"""
import os
import multiprocessing as mp
import capstone

# Python 3.14 defaults to forkserver on Linux; force fork so workers inherit the big blob via
# copy-on-write instead of re-importing (which loses the module globals and re-runs __main__).
_CTX = mp.get_context("fork")

READ = 1 << 16              # decode-window step
OVERLAP = 1 << 16           # 64 KB resync runway before each chunk's kept region

_BLOB = None                # set in the parent before Pool(); inherited by fork


def _workers(w):
    if w is not None:
        return max(1, w)
    return max(1, (os.cpu_count() or 2) - 1)


# ---------------------------------------------------------------- linear sweep
def _serial_sweep(blob, base):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    starts = set()
    n = len(blob)
    pos = 0
    while pos < n:
        got = False
        for addr, size, _, _ in md.disasm_lite(bytes(blob[pos:min(n, pos + READ)]), base + pos):
            starts.add(addr - base)
            got = True
            pos = addr - base + size
            if pos >= n:
                break
        if not got:
            pos += 1
    return starts


def _sweep_range(args):
    c0, c1, base = args
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    blob = _BLOB
    n = len(blob)
    start = max(0, c0 - OVERLAP)
    end_read = min(n, c1 + 64)     # let a boundary-straddling instruction decode fully
    out = []
    pos = start
    while pos < c1:
        got = False
        for addr, size, _, _ in md.disasm_lite(bytes(blob[pos:min(end_read, pos + READ)]), base + pos):
            off = addr - base
            if off >= c1:
                got = True
                pos = c1
                break
            if off >= c0:
                out.append(off)
            got = True
            pos = off + size
        if not got:
            pos += 1
    return out


def sweep_boundaries(blob, base, workers=None):
    """Set of instruction-start offsets (relative to blob). Identical to the serial sweep."""
    global _BLOB
    n = len(blob)
    w = _workers(workers)
    if w <= 1 or n < (4 << 20):
        return _serial_sweep(blob, base)
    _BLOB = blob
    step = (n + w - 1) // w
    tasks = [(i * step, min(n, (i + 1) * step), base) for i in range(w) if i * step < n]
    with _CTX.Pool(len(tasks)) as pool:
        parts = pool.map(_sweep_range, tasks)
    s = set()
    for p in parts:
        s.update(p)
    return s


# ---------------------------------------------------------- backward-convergence alignment
# Batch-evaluate the backward-convergence check for many (off, plen) pairs. Verdict is a pure
# function of the original bytes, so results are order-independent; the caller applies rewrites
# serially in its own order.
_CFG = None


def _align_init(blob, base, back, step, strong, min_yes):
    global _BLOB, _CFG
    _BLOB = blob
    _CFG = (base, back, step, strong, min_yes,
            capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64))


def _align_one(item):
    off, plen = item
    base, back, step, strong, min_yes, md = _CFG
    blob = _BLOB
    yes = no = 0
    for b in range(step, back, step):
        st = off - b
        if st < 0:
            continue
        hit = False
        for ins in md.disasm(bytes(blob[st:off + plen]), base + st):
            if ins.address == base + off:
                hit = True
                break
            if ins.address > base + off:
                break
        yes += hit
        no += (not hit)
    return (off, plen), (yes > no * strong and yes >= min_yes)


def batch_aligned(blob, base, items, back=24, step=1, strong=1.5, min_yes=6, workers=None):
    """{(off,plen): bool} for each candidate. step/strong/min_yes match the caller's serial rule:
       pushpop -> step 1, strong 1.5, min_yes 6 ;  ret -> step 4, strong 1.0, min_yes 0."""
    items = list(items)
    w = _workers(workers)
    if w <= 1 or len(items) < 4000:
        _align_init(blob, base, back, step, strong, min_yes)
        return dict(_align_one(it) for it in items)
    with _CTX.Pool(w, initializer=_align_init,
                 initargs=(blob, base, back, step, strong, min_yes)) as pool:
        return dict(pool.map(_align_one, items, chunksize=2000))
