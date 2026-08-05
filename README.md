# destiny2 build 87221 - VMProtect de-mutation kit

Reproduces a **de-mutated, de-threaded analysis image** of `destiny2.exe` build 87221
(content 84840, version `87221.20.09.10.1506.d2_live`) - VMProtect's mutation removed and its
control-flow flattening rewritten to native jumps - so you can read the code in **any** decompiler
instead of fighting VMProtect.

Everything here is **tooling and derived metadata**. It contains no game code. You run it against
your own copy and produce the image locally - which is also the only thing that *can* work, for
the reason below.

---

## Quick start

Needs **Python 3.8+** and **capstone** (`pip install -r requirements.txt`) - nothing else. Two
steps:

**1 - Dump the process, where the game runs:**

| game on... | dump with... | -> |
|---|---|---|
| **native Windows** | Task Manager -> right-click `destiny2.exe` -> *Create dump file* &nbsp;(or `procdump -ma destiny2.exe d2.dmp`) | `d2.dmp` |
| **Proton / Linux** | `sudo gcore -o core $(pgrep -x destiny2.exe)` | `core.<pid>` |

> WSL can't dump a native-Windows process - make the `.dmp` on Windows, then move the file.

**2 - Analyse the dump, anywhere (~2-3 min):**

```bash
python demutate.py d2.dmp          # .dmp minidump, ELF core, or an already-extracted image
```

Out comes **`dethread_pe.bin`** - VMProtect's mutation removed *and* its control-flow flattening
rewritten to native `jmp`/`jcc`/`call`. Open it in **Ghidra, IDA, Binary Ninja, or objdump** and the
code reads normally, no plugins or flow-overrides needed. (`data/` ships the derived metadata
precomputed, so if `python verify.py <image>` passes you can even skip straight to loading it.)

Everything below is background - why it works, what it deliberately doesn't, and how to verify or
port it to another build.

---

## Why you must dump: the on-disk exe is encrypted

You cannot run this on `destiny2.exe` as shipped. VMProtect decrypts the code sections at load:

| section | on-disk vs runtime |
|---|---|
| `.text` #1 (28.9 MB @ RVA 0x1000) | **0.58%** identical |
| `.text` #2 (81.3 MB @ RVA 0x3cc3000) | **9.43%** identical |

So step 0 is always: **dump the running process** - and this is the one step that is
environment-specific.

### Dump where the game RUNS; analyse anywhere
The dump must be made in the environment the process actually lives in. The analysis (everything
else in this kit) is pure Python and runs anywhere - WSL, another Linux box, a container.

| game runs on... | make a full dump with... | produces |
|---|---|---|
| **native Windows** | Task Manager -> right-click `destiny2.exe` -> **Create dump file**; or `procdump -ma destiny2.exe d2.dmp` | a **minidump** `.dmp` |
| **Proton/Wine on Linux** | `sudo gcore <pid>` | an ELF **core** |

**WSL cannot dump a native-Windows process.** If the game is on native Windows and you want to
analyse under WSL, make the `.dmp` on the **Windows** side first, then hand the file to WSL.

`extract_image.py` (and `demutate.py`) auto-detect either format and reassemble the module image -
file offset == RVA, from the module base. For a minidump the base is read from the dump's module
list (so Windows **ASLR is handled automatically**); for an ELF core it defaults to `0x140000000`.
Verify with `python verify.py <image>` - if its checks fail you have a different build/base and the
shipped `data/` (pinned to `0x140000000`) will not apply.

A dump also carries runtime state: IAT bound to live DLL addresses, relocations applied, and any
hooks you have installed. Measured 58,282 bytes (0.04%) differ between a live snapshot and the
dump for that reason. It does not affect the code bytes this kit rewrites.

---

## What the kit does

### Layer 1 - MUTATION (solved, 98.84%)
VMProtect rewrites `push`/`pop`/`ret` into stack idioms, which destroys Ghidra's stack-depth model
so functions decompile truncated or not at all. All rewrites preserve length and nop-pad, so
nothing moves and no offset, relocation, `.pdata` entry or vtable slot needs fixing.

| idiom | -> | note |
|---|---|---|
| `mov [rsp-8],reg ; lea rsp,[rsp-8]` | `push reg` | `reg==rsp` is fine (stores the OLD rsp) |
| `lea rsp,[rsp-8] ; mov [rsp],reg` | `push reg` | exclude `reg==rsp` |
| `mov reg,[rsp] ; lea rsp,[rsp+8]` | `pop reg` | exclude `reg==rsp` (yields `[rsp]+8`) |
| `lea rsp,[rsp+8] ; mov reg,[rsp-8]` | `pop reg` | |
| `lea rsp,[rsp+8] ; jmp [rsp-8]` | `ret` | |
| `lea rsp,[rsp+/-8] ; lea rsp,[rsp-/+8]` | nops | cancels |

**Both orders exist and are near-equally common.** Matching one form finds half the sites.

**612,519 of 813,174 sites rewritten. The 9,459 leftovers are embedded DATA** where the byte
pattern occurs by coincidence - proven, because ground-truth relocation anchors decline them too.

### Layer 2 - THREADING (de-threaded to native control flow)
Each flattened block plants its successor address on the stack and `ret`s to it, so a decompiler
reads every block end as a function return and the 81 MB section falls apart into ~150k
disconnected fragments.

`tools/dethread.py` resolves each block's dispatch with a **symbolic-stack interpreter** and
rewrites the threading epilogue **in place** with the real control transfer:

| threaded construct | rewritten to |
|---|---|
| unconditional | `jmp target` |
| conditional (`cmov`-selected) | `jcc taken ; jmp fallthrough` |
| call / deferred continuation | `call target ; jmp continuation` |
| indirect call | `call reg ; jmp continuation` |

The 12-30 byte threading epilogue always has room for these (5-15 bytes), so no relocation is
needed - the earlier "impossible in place" belief mis-measured the 1-byte `ret` alone. **86,597
dispatch blocks de-threaded; 78,881 real returns left native; ~10 complex blocks conservatively
left threaded.** Strictly audited: 0 body corruption, 0 flag issues. The result reads with explicit
native control flow in **any** decompiler - no plugin, no database annotation.

---

## The one non-obvious discovery: the relocation table is hidden

**Do not read the `.reloc` section.** VMProtect leaves a decoy there - 116,914 DIR64 entries, all
in `.rdata`/`.data`, **zero in code**. Reading it concludes "there are no code relocations", which
is false.

The real table is the one the **BASERELOC data directory** points at: RVA `0x8955230`, 1,002,984
bytes, *inside VMProtect's own `.text`*. **441,006 DIR64, 324,064 of them in executable code.**

That is the only ground truth available in the VMP section (`.pdata` covers **0%** of it), and it
gives, with no emulation:
* **309,148 authoritative instruction boundaries** - 95.4% of code relocs have `movabs reg,imm64`
  starting at `reloc-2`, and the loader must patch exactly there or the image breaks.
* **245,572 distinct code targets** = the block-entry / successor set.
* an **audit**: 0 of 557,628 rewrites overlapped a relocated field (had one, that range was data).

---

## Pipeline - packed exe to analysis target

**Step 0 is not optional and the kit does not ship a dumper.** The on-disk exe is encrypted
(above), so you must capture the process image yourself, after the VMProtect stub has decrypted.
That happens at **process entry** - no internet, server, or sign-in required; a stock client that
merely launches and then fails at a "connecting..." screen is already fully unpacked and dumpable.
What the tools require of that dump:

* a **full process image of `destiny2.exe`**, laid out so that **file offset == RVA**
  (an RVA-ordered image, NOT a raw-file-offset copy)
* **image base `0x140000000`** - every address in `data/` is absolute at this base, so the load
  base must match or all of it is off by the delta. **The base is decided by your Proton/Wine
  build's loader, not by the game.** The PE's preferred base is `0x140000000`; whether the loader
  honours it depends on how that build handles ASLR. **Proton Experimental loads it at
  `0x140000000` (confirmed)** - that is the reference. A different Proton/Wine version may relocate
  it elsewhere, in which case `verify.py` fails the image-base check; then pass your actual base to
  `extract_image.py` and regenerate `data/` (steps 11-12) - the tooling is base-agnostic, only the
  shipped metadata is pinned to `0x140000000`.
* taken any time **after the VMProtect stub has unpacked** (i.e. once the process is up), so all
  sections are decrypted
* build 87221 produces exactly **145,010,688 bytes**

**Dump a bone-stock client.** Vanilla - no `version.dll` DLL-redirect, no memory-patcher, no VEH
- so `.text` is stock by construction. Only the memory-patcher writes `.text` code, and that is the
only thing this kit cares about; `version.dll`'s changes are `.data`-only and don't touch the
de-mutated code. Dump stock and there is nothing to undo.

**Final output = `dethread_pe.bin`**: on top of the de-mutation, `tools/dethread.py` replaces
VMProtect's control-flow-flattening (every block dispatches through a threaded `ret`) with native
`jmp`/`jcc`/`call` **in place** - 86,597 dispatch blocks (real returns are left native) - so the
control flow is explicit and traceable in **any** decompiler (Ghidra, IDA, Binary Ninja, objdump)
with zero tool-specific setup. Strictly audited across all patched blocks: 0 body corruption, 0
flag issues; ~10 complex blocks are conservatively left threaded rather than risk corruption.

## Options & outputs

`python demutate.py <dump>` (see **Quick start**) takes:

```
--base HEX      load base if ASLR moved it (default 0x140000000; auto-detected for minidumps)
--keep          retain the devmp*.bin intermediates
--no-verify     skip the alignment sweep
--no-dethread   stop at the de-mutated (still threaded) devmp4_pe.bin
```

It writes: **`dethread_pe.bin`** (load this) / `devmp4_pe.bin` (de-mutated only, control flow still
threaded - from `--no-dethread`) / `successors.json` + `reloc_boundaries.json` (the derived CFG /
boundary metadata, mostly reference).

<details><summary>Run the stages by hand (what <code>demutate.py</code> does internally)</summary>

```bash
D=image.bin                        # your dump/image from step 1
python verify.py $D                # do this first: refuses other builds
python tools/devmp_ret.py       $D                devmp.bin        # obfuscated ret -> ret
python tools/pe_memalign.py     devmp.bin         devmp_pe.bin     # ra==va, so it loads as a PE
python tools/devmp_pushpop.py   devmp_pe.bin      devmp2_pe.bin    # oracle: backward convergence
python tools/devmp_pushpop2.py  devmp2_pe.bin     devmp3_pe.bin    # oracle: global linear sweep

# ORDER MATTERS: pass 3 CONSUMES the anchors, so generate them first.
python tools/devmp_boundaries.py devmp3_pe.bin $D                  # -> reloc_boundaries.json
python tools/devmp_pushpop3.py  devmp3_pe.bin     devmp4_pe.bin    # oracle: relocation anchors

python tools/devmp_boundaries.py devmp4_pe.bin $D                  # regenerate against the FINAL image
python tools/devmp_successors.py devmp4_pe.bin successors.json     # CFG edges (for dethread seeds)
python tools/devmp_reloc.py      $D devmp4_pe.bin                  # audit: expect 0 overlaps
python tools/devmp_verify_sweep.py $D devmp4_pe.bin                # alignment: expect ~99.99%
python tools/dethread.py         devmp4_pe.bin dethread_pe.bin     # de-thread -> native (final)
```
</details>
`data/` ships the derived metadata precomputed as reference.

### What you end up with - and what "stripped" honestly means

**Not** a de-protected, runnable executable. It's an **analysis target**: a memory dump with the IAT
already bound and 612k+ changed bytes, which would fail any integrity check - this project does not
help produce a runnable binary. What you get is:

* 98.84% of the mutation rewritten to native `push`/`pop`/`ret`, so the decompiler's stack model works
* the control-flow flattening de-threaded to native `jmp`/`jcc`/`call` across ~86.6k blocks, so
  functions are connected instead of ~150k fragments
* code that decompiles cleanly in any tool, with no plugin or database annotation

That is the thing that stops you hitting VMProtect walls. It is for reading, not running.

---

## Verification - don't trust this, check it

Two self-contained checks ship in the kit and run anywhere (`demutate.py` runs them for you):

1. **Alignment** (`devmp_verify_sweep.py`) - resync linear sweep of the original bytes, then ask
   which rewritten sites land on a swept boundary: **422,288/422,340 = 99.988%**. Every
   unconfirmed site inspected was a sweep false negative, not a bad rewrite.
2. **Relocation audit** (`devmp_reloc.py`) - **0** of 557,628 rewrites touched a relocated field.

A third, **semantic** check (emulate entry points on both images, compare executed-PC traces:
24 identical + 7 identical-to-cap, 0 mismatches over ~1.4M instructions) needs a Unicorn snapshot of
the live process, so it is **not** shipped - it can't run standalone. The two above are enough to
trust the rewrite; the semantic run is how it was originally validated.

**Three confounds will each fake a failure** if you write your own checks:
* **The snapshot is not the file image** (58,282 B differ). Both sides of a comparison must use a
  full file image, or you are measuring two changes at once.
* **`rdrand` at `0x145160102`** is on several paths, so registers and write sets differ run-to-run
  for *identical* bytes (measured rdx = 0x4d01, 0xfe1, 0x915, 0x3714, 0x4f4b). Compare
  **executed-PC traces**, never registers.
* **Instruction caps** - `push`+8x`nop` costs more instructions than the 2 it replaces, so a
  capped run stops at a different program point. Compare capped runs on their common prefix.

---

## Results and honest limits

| | |
|---|---|
| mutation removed | 612,519 sites / 98.84% |
| CFG edges applied | 152,787 blocks, 174,512 refs (21,711 conditional) |
| `notRet` mismatches | **0 of 152,787** |
| functions | 71,141 |
| VMP-section decompile sample | 40 tried, **33 good, 7 degenerate, 0 failed** |

**Limits, stated plainly:**
* The decompile sample comes from the **194** VMP addresses that are direct call targets - a
  special subset, not representative of 81 MB.
* **Function boundaries still lean on the decompiler.** Before de-threading, VMP bodies were
  entered only by threading (almost never a direct `call`), so nothing marked function starts. The
  de-thread now emits real `call`/`jmp` edges, so a decompiler's own auto-analysis recovers most
  functions - but boundary recovery in the 81 MB section is still imperfect; expect some over/under-
  split functions.
* ~10 blocks are left threaded (complex frame-teardown + dispatch epilogues, skipped to avoid
  corruption). A decompiler reads those ~10 `ret`s as returns - negligible, and their targets are
  reached via other de-threaded edges anyway.
* This image is **ANALYSIS ONLY**: a memory dump with the IAT bound, not a loadable PE, and 612k+
  changed bytes. Run the original game; this is for reading.

## Porting to another build

The **transforms are generic**; the **data is not**. VMProtect's mutation idioms and its threading
shape (`movabs`/`lea` -> `xchg [rsp],reg` -> `ret`) are properties of the protector, not of build
87221, so the tools should apply to any VMProtect-mutated x64 target. What does not carry over:

| | portable? | note |
|---|---|---|
| `tools/*.py` transforms + verifiers | yes | idioms are VMProtect's, not build-specific |
| `tools/peinfo.py` | yes | derives base + exec ranges from the PE header |
| `data/*` | no | absolute addresses for 87221 @ base 0x140000000 |
| `data/SECTION_HASHES.txt` | no | 87221 only - reference hashes; `verify.py` refuses other builds via structural checks |

**Run `verify.py` first.** If the `source=` hashes don't match, delete `data/` and regenerate it -
using 87221 addresses on another build produces plausible-looking, silently wrong results.

**Section layout was hardcoded and is now derived.** Earlier versions of these tools embedded
`EXEC = ((0x140001000, 0x141b8bc00), (0x143cc3000, 0x148a4a200))` - that is 87221's section table.
On another build it silently scans the wrong bytes. All tools now call `peinfo.exec_ranges()`
instead. If you write new tooling, do the same; do not paste those literals back in.

The two shipped verifications - **alignment** (`devmp_verify_sweep.py`) and the **relocation audit**
(`devmp_reloc.py`) - are self-contained and run anywhere. The semantic emulation check needs a
Unicorn snapshot of the live process and build-specific stubs, so it isn't shipped; rebuild that
harness for your target if you want it.

Also expect to re-derive: the `movabs reg,imm64` boundary rule assumes REX at `reloc-2` and
`B8..BF` at `reloc-1` (95.4% of code relocs here) - check that ratio on your build before trusting
the anchors, and check whether its `.reloc` section is a decoy too.

## Also settled: there is no VM

All 31 VM-entry candidates were tested with two independent classifiers: **max 13 distinct segment
bodies** (a real VMProtect VM shows 50-150+ handlers) and **zero multi-target computed branches**.
Build 87221 is **mutation + threading only**. Don't go looking for a bytecode interpreter, and
don't reach for NoVmp (asserts here) or MogVMP (32-bit only). Classic arithmetic junk
(`not/not`, `neg/neg`, self-`mov`) is **absent** - measured 0 occurrences.
