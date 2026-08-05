#!/usr/bin/env python3
"""ONE command: a destiny2 dump -> de-mutated, de-threaded binary that any decompiler traces.

Give it a **dump** (Windows `.dmp` minidump OR Linux `gcore` core) or an already-extracted
**image** - it auto-detects, extracts, verifies, de-mutates, de-threads, and produces
`dethread_pe.bin`. Each stage is a standalone tool from tools/ (subprocess); this only sequences
them, checks exit codes, and cleans up.

DUMPING IS A SEPARATE, OS-SPECIFIC STEP - this script does NOT dump. Make the dump where the game
RUNS, then hand it here (analysis is pure Python and runs anywhere, incl. WSL):

    native Windows :  Task Manager -> right-click destiny2.exe -> "Create dump file"
                      or:  procdump -ma destiny2.exe d2.dmp
    Proton / Linux :  sudo gcore <pid>            (pid from `pgrep -x destiny2.exe`)

WSL cannot dump a native-Windows process - make the .dmp on the Windows side first.

  usage: demutate.py <dump.dmp | core | image.bin> [--base HEX] [--keep] [--no-verify] [--no-dethread]

  demutate.py d2.dmp            # Windows minidump (base auto-detected from it)
  demutate.py core.1234         # Linux gcore core
  demutate.py image.bin         # already extracted

Produces:  dethread_pe.bin (load THIS) / devmp4_pe.bin (de-mutated only) / successors.txt/.json -
           reloc_seeds.txt.   Intermediates deleted unless --keep.
ORDER IS LOAD-BEARING: devmp_boundaries runs before devmp_pushpop3 (pass 3 consumes the anchors).
"""
import sys, os, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "tools")
PY = sys.executable

args = [a for a in sys.argv[1:] if not a.startswith("-")]
if not args:
    sys.exit(__doc__)
INP = args[0]
KEEP = "--keep" in sys.argv
VERIFY = "--no-verify" not in sys.argv
HAS_BASE = "--base" in sys.argv
BASE = sys.argv[sys.argv.index("--base") + 1].removeprefix("0x") if HAS_BASE else "140000000"
SIZE = "145010688"


def run(tool, *a, label=None):
    cmd = [PY, os.path.join(TOOLS, tool), *map(str, a)]
    print(f"\n\033[1m> {label or tool}\033[0m  ({' '.join(os.path.basename(x) for x in cmd[1:])})",
          flush=True)
    t = time.time()
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(f"x {tool} failed (exit {r.returncode}) - stopping")
    print(f"  OK {time.time()-t:.0f}s", flush=True)


t0 = time.time()


def prepare_image(inp):
    """-> path to a 145 MB RVA-ordered image, extracting from a dump if needed. Does NOT dump."""
    if not os.path.exists(inp):
        sys.exit(f"input not found: {inp}  (this script does not dump - make the dump first; see "
                 f"--help for the per-OS command)")
    magic = open(inp, "rb").read(4)
    # ELF core (gcore) or Windows minidump (MDMP) -> extract; extract_image auto-detects the format
    # and, for a minidump, reads the base from the module list (handles ASLR).
    if magic in (b"\x7fELF", b"MDMP"):
        extra = [BASE, SIZE] if HAS_BASE else []
        run("extract_image.py", inp, "image.bin", *extra, label="extract module from dump")
        return "image.bin"
    if magic[:2] == b"MZ":
        return inp                                   # already an extracted PE image
    sys.exit(f"unrecognised input (magic {magic!r}) - expected a dump (ELF core / MDMP minidump) "
             f"or an extracted image (PE). This script does not dump; see --help.")


DUMP = prepare_image(INP)
print(f"\nde-mutating {DUMP}")

# --- precondition: right build/base --------------------------------------------------------
run("../verify.py", DUMP, label="verify build")

# --- byte pipeline -------------------------------------------------------------------------
run("devmp_ret.py",       DUMP,            "devmp.bin",      label="pass 0: obfuscated ret -> ret")
run("pe_memalign.py",     "devmp.bin",     "devmp_pe.bin",   label="memory-align section table")
run("devmp_pushpop.py",   "devmp_pe.bin",  "devmp2_pe.bin",  label="pass 1: push/pop (backward convergence)")
run("devmp_pushpop2.py",  "devmp2_pe.bin", "devmp3_pe.bin",  label="pass 2: push/pop (linear sweep)")
run("devmp_boundaries.py", "devmp3_pe.bin", DUMP,            label="relocation anchors (before pass 3)")
run("devmp_pushpop3.py",  "devmp3_pe.bin", "devmp4_pe.bin",  label="pass 3: push/pop (reloc anchors) -> FINAL")

# --- metadata against the FINAL image ------------------------------------------------------
run("devmp_boundaries.py", "devmp4_pe.bin", DUMP,            label="anchors (regen vs final)")
run("devmp_successors.py", "devmp4_pe.bin", "successors.json", label="CFG successor map")

# --- de-thread: replace ret-dispatch with native jmp/jcc/call (skip with --no-dethread) -----
DETHREAD = "--no-dethread" not in sys.argv
if DETHREAD:
    run("dethread.py", "devmp4_pe.bin", "dethread_pe.bin",
        label="de-thread control flow -> native jumps (readable in ANY decompiler)")

# --- verification (self-contained; skip with --no-verify) ----------------------------------
if VERIFY:
    run("devmp_reloc.py",       DUMP, "devmp4_pe.bin", label="audit: rewrites vs relocations (expect 0)")
    run("devmp_verify_sweep.py", DUMP, "devmp4_pe.bin", label="alignment sweep (expect ~99.97%)")

# --- cleanup -------------------------------------------------------------------------------
if not KEEP:
    for f in ("devmp.bin", "devmp_pe.bin", "devmp2_pe.bin", "devmp3_pe.bin"):
        if os.path.exists(f):
            os.remove(f)
    print("\ncleaned intermediates (devmp.bin, devmp_pe.bin, devmp2_pe.bin, devmp3_pe.bin) - use --keep to retain")

print(f"\n\033[1mOK done in {time.time()-t0:.0f}s\033[0m")
if DETHREAD:
    print("  \033[1mdethread_pe.bin\033[0m  <- LOAD THIS in Ghidra / IDA / Binary Ninja / objdump.")
    print("                     Mutation removed + control flow native - traces with zero setup.")
    print("  devmp4_pe.bin    <- de-mutated only, control flow still threaded")
else:
    print("  devmp4_pe.bin    <- de-mutated (control flow still threaded; drop --no-dethread for native)")
