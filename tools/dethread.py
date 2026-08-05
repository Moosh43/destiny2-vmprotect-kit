#!/usr/bin/env python3
"""In-place de-thread: replace VMProtect's ret-dispatch with native jmp/jcc, so the control flow is
explicit and readable in ANY decompiler (Ghidra, IDA, Binary Ninja, objdump) with no tool-specific
setup.

For each resolvable threaded block we overwrite its threading EPILOGUE (the trailing
push/lea/xchg/cmov/mov[rsp]/ret that does the dispatch) with real control flow:
  * jmp block    -> jmp rel32 <target>
  * branch block -> j<cc> rel32 <taken> ; jmp rel32 <fallthrough>   (cc from the block's cmov;
                     the flag-setting instruction stays in the body just before the epilogue)
  * ret block    -> ret
Then nop-pad to the original epilogue length so nothing moves. The epilogue (12-30 B) is always
larger than a jmp (5) or jcc+jmp (11), so this fits in place -- the earlier "impossible" claim
mis-measured the 1-byte ret alone instead of the whole epilogue.

LEFT THREADED (reported, not rewritten): call/defer blocks (the continuation would have to be
relocated), indirect calls, and anything the resolver can't cleanly classify. Those keep working
at runtime and can still get a Ghidra flow-override from successors_complete.txt.

ANALYSIS ONLY. Verified: only epilogue bytes change; block bodies and all other code are
untouched.

  usage: dethread.py [in.bin] [out.bin]
"""
import sys, os, struct, json

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "destiny2_devmp4_pe.bin"
DST = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else "destiny2_dethread_pe.bin"

# deflatten.py loads the image at import; point it at OUR input via the env override, then import
# it as a sibling module (tools/ is on sys.path when run as a script).
os.environ["DEFLAT_IMG"] = SRC
sys.path.insert(0, HERE)
import deflatten as D
import peinfo
B = D.B


def find_data(name):
    for p in (name, os.path.join(HERE, name), os.path.join(HERE, "..", "data", name),
              os.path.join(HERE, "..", name)):
        if os.path.exists(p):
            return p
    sys.exit(f"cannot find {name} (needed for de-thread seeds) - run devmp_successors.py first "
             f"or place it in data/")

# cmov condition suffix -> jcc rel32 opcode (0F 8x)
JCC = {"o": 0x80, "no": 0x81, "b": 0x82, "c": 0x82, "nae": 0x82, "ae": 0x83, "nb": 0x83, "nc": 0x83,
       "e": 0x84, "z": 0x84, "ne": 0x85, "nz": 0x85, "be": 0x86, "na": 0x86, "a": 0x87, "nbe": 0x87,
       "s": 0x88, "ns": 0x89, "p": 0x8A, "pe": 0x8A, "np": 0x8B, "po": 0x8B, "l": 0x8C, "nge": 0x8C,
       "ge": 0x8D, "nl": 0x8D, "le": 0x8E, "ng": 0x8E, "g": 0x8F, "nle": 0x8F}


def epilogue_start(ins_list):
    """First address of the trailing threading epilogue (body ends just before it)."""
    body = D.strip_epilogue(ins_list)
    return ins_list[len(body)].address if len(body) < len(ins_list) else ins_list[-1].address


def clean_epilogue(epi):
    """Positively verify the stripped region is pure threading dispatch, not a real function
    epilogue the heuristic strip over-reached into. Refuse to patch anything that restores
    callee-saved state or tears down a frame -- those `pop`/`mov reg,[rsp]`/`add rsp`/`lea rsp,[rbp`
    LOOK like threading but are real code; stripping them corrupts the return."""
    npush = sum(1 for i in epi if i.mnemonic == "push")
    npop = sum(1 for i in epi if i.mnemonic == "pop")
    if npop > npush:                              # unbalanced pop = real register restore stripped
        return False
    for i in epi:
        m, oo = i.mnemonic, i.op_str.replace(" ", "")
        if m in ("add", "sub") and oo.startswith("rsp,"):
            try:
                if abs(int(oo.split(",")[1], 0)) >= 0x10:   # threading adjusts rsp by <=8; larger = frame
                    return False
            except Exception:
                return False
        if m == "lea" and oo.startswith("rsp,[rbp"):        # frame restore
            return False
        if m == "mov" and oo.startswith("rsp,"):            # mov rsp,reg = frame restore
            return False
    return True


def rel32(frm, to):
    return struct.pack("<i", to - (frm + 5))


# call r/m64 (/2): FF D0+rm, with REX.B for r8-r15
_REGN = {"rax": 0, "rcx": 1, "rdx": 2, "rbx": 3, "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
         "r8": 8, "r9": 9, "r10": 10, "r11": 11, "r12": 12, "r13": 13, "r14": 14, "r15": 15}


def call_reg(reg):
    n = _REGN.get(reg)
    if n is None:
        return None
    pre = b"\x41" if n >= 8 else b""
    return pre + b"\xff" + bytes([0xD0 + (n & 7)])


def recover_icall_reg(epi):
    """The dispatch target = whatever last wrote [rsp] before the ret (push/xchg/mov [rsp])."""
    reg = None
    for i in epi:
        m, o = i.mnemonic, i.op_str
        if m == "push":
            reg = o.strip()
        elif m == "xchg" and "[rsp]" in o:
            reg = o.split(",")[1].strip()
        elif m == "mov" and o.replace(" ", "").startswith("qwordptr[rsp],"):
            reg = o.split(",")[1].strip()
        elif m == "ret":
            break
    return reg if reg in _REGN else None


def reg_clobbered(reg, epi):
    """True if `reg` is written anywhere in the epilogue (so it wouldn't hold the target at
    epilogue-start where our `call reg` lands)."""
    for i in epi:
        m, o = i.mnemonic, i.op_str
        if m == "pop" and o.strip() == reg:
            return True
        if m.startswith("cmov") and o.split(",")[0].strip() == reg:
            return True
        if m in ("mov", "lea", "movabs", "add", "sub", "xor", "and", "or", "inc", "dec") \
                and o.split(",")[0].strip() == reg:
            return True
    return False


def build(d):
    # Enumerate block starts. Seed from BOTH the CFG successors AND every .pdata function start.
    # The successors map is a flow traversal and misses any function no reachable edge names
    # (e.g. reached only by a virtual/indirect call) -- those stay threaded and decompile to an
    # empty LOCK/UNLOCK stub. The exception directory is the ground-truth function table, so
    # unioning it in reaches them. (Build 87221: 86,597 -> 87,424 dispatch blocks converted; the
    # extra ~800 are whole functions the flow traversal never entered.)
    old = json.load(open(find_data("successors.json")))
    seeds = set(int(t, 16) for v in old.values() for t in v)
    seeds |= {a for a in peinfo.pdata_functions(d) if D.incode(a)}
    seen = set()
    frontier = seeds
    starts = []
    while frontier:
        nxt = set()
        for a in frontier:
            if a in seen or not D.incode(a):
                continue
            seen.add(a)
            ins, term = D.disasm_block(a)
            if not ins:
                continue
            if term == "jmp":
                try:
                    t = int(ins[-1].op_str, 16)
                    if t not in seen:
                        nxt.add(t)
                except Exception:
                    pass
                continue
            if term != "ret":
                continue
            starts.append((a, ins))
            c = D.classify(ins, term)
            for e in list(c["targets"]) + list(c.get("conts", [])):
                if e not in seen:
                    nxt.add(e)
        frontier = nxt
    return starts


def main():
    d = bytearray(open(SRC, "rb").read())
    starts = build(d)
    stat = {"jmp": 0, "branch": 0, "ret": 0, "call": 0, "icall": 0, "skip_call": 0,
            "skip_icall": 0, "skip_cond": 0, "skip_room": 0, "skip_other": 0}
    for a, ins in starts:
        c = D.classify(ins, "ret")
        k = c["kind"]
        es = epilogue_start(ins)
        eend = ins[-1].address + ins[-1].size          # past the ret
        room = eend - es
        patch = None
        # SAFETY GATE: only patch a block whose stripped epilogue is verifiably clean threading.
        # If the strip over-reached into a real frame teardown, leave the block threaded (correct,
        # just not de-threaded) rather than corrupt its return.
        if k in ("jmp", "branch", "call", "icall") and not clean_epilogue(ins[len(D.strip_epilogue(ins)):]):
            stat["skip_unsafe"] = stat.get("skip_unsafe", 0) + 1
            continue
        if k == "jmp":
            patch = b"\xe9" + rel32(es, c["targets"][0])
        elif k == "ret":
            stat["ret_native"] = stat.get("ret_native", 0) + 1   # already a native return; leave it
            continue
        elif k == "branch":
            cc = c.get("cond")
            tk = c.get("taken")
            ft = c.get("fallthrough")
            if cc in JCC and isinstance(tk, int) and isinstance(ft, int):
                jcc = b"\x0f" + bytes([JCC[cc]]) + struct.pack("<i", tk - (es + 6))
                patch = jcc + b"\xe9" + rel32(es + 6, ft)
            else:
                stat["skip_cond"] += 1
                continue
        elif k == "call":
            # `push T1..Tn (conts); jmp T` == a call to T that, on return, runs continuations
            # T1..Tn in order. Encode as a nested chain: call T ; call T1 ; ... ; call T(n-1) ;
            # jmp Tn -- each call returns to the next, matching the deferred-continuation order
            # and leaving the stack at the same depth. Works for any number of continuations.
            conts = c.get("conts", [])
            t2 = c["targets"][0] if c.get("targets") else None
            if isinstance(t2, int) and conts and all(isinstance(x, int) for x in conts):
                chain = [t2] + conts[:-1]           # call each of these
                final = conts[-1]                   # then jmp this
                patch, addr = b"", es
                for tc in chain:
                    patch += b"\xe8" + struct.pack("<i", tc - (addr + 5)); addr += 5
                patch += b"\xe9" + struct.pack("<i", final - (addr + 5))
            else:
                stat["skip_call"] += 1
                continue
        elif k == "icall":
            # `push T1(cont); jmp <reg>` == an indirect call to <reg> returning to T1.
            # Encode `call <reg> ; jmp T1`. Recover <reg> directly from the last instruction that
            # writes [rsp] before the ret (the dispatch target), which is more reliable than the
            # symbolic model. Only do it if that reg is NOT clobbered within the epilogue (so it
            # still holds the target at epilogue-start where the `call` lands); else leave threaded.
            conts = c.get("conts", [])
            epi = ins[len(D.strip_epilogue(ins)):]
            reg = c.get("reg") or recover_icall_reg(epi)
            cr = call_reg(reg) if reg else None
            if cr and len(conts) == 1 and isinstance(conts[0], int) and not reg_clobbered(reg, epi):
                jmp = b"\xe9" + rel32(es + len(cr), conts[0])
                patch = cr + jmp
            else:
                stat["skip_icall"] += 1
                continue
        else:
            stat["skip_other"] += 1
            continue
        if len(patch) > room:
            stat["skip_room"] += 1
            continue
        off = es - B
        d[off:off + room] = patch + b"\x90" * (room - len(patch))
        stat[k] += 1
    open(DST, "wb").write(bytes(d))
    done = stat["jmp"] + stat["branch"] + stat["call"] + stat["icall"]
    skipped = sum(v for k, v in stat.items() if k.startswith("skip"))
    print(f"de-threaded {done:,} dispatch blocks in place  (jmp {stat['jmp']:,}, branch "
          f"{stat['branch']:,}, call {stat['call']:,}, icall {stat['icall']:,})")
    print(f"left as native returns (not threaded): {stat.get('ret_native',0):,}")
    print(f"left threaded {skipped:,}: {dict((k,v) for k,v in stat.items() if k.startswith('skip') and v)}")
    print(f"wrote {DST}")


if __name__ == "__main__":
    main()
