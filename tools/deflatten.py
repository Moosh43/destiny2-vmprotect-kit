#!/usr/bin/env python3
"""Deflatten VMProtect's stack-based (RET-dispatch) control-flow flattening.

Every block ends in `ret`, which dispatches to whatever the block left on top of the return stack.
Blocks set that up with a small stack-machine vocabulary: load a target with `lea reg,[rip+d]` or
`movabs reg,imm`, move it onto the stack with `xchg [rsp],reg`, defer continuations with `push`,
patch deeper return slots with `mov [rsp+d],reg`, and select conditionally with `cmov`.

RESOLUTION. For each block we ABSTRACTLY INTERPRET its stack effect from block start to the
terminating `ret`, over a slot-addressed model stack:
  * stack : {offset -> value}; rsp is an integer offset (starts 0); unset slots read as the
    symbolic incoming continuation ('IN', off).
  * a value is a concrete code address (from lea/movabs) or symbolic.
  * `cmov` FORKS the interpretation, so a conditional yields BOTH edges.
Non-stack instructions (arithmetic, loads, even `call` - stack-neutral: it returns) are opaque and
ignored; they can't change the dispatch except by setting flags, which the fork covers.

The block's `ret` target is then a concrete address loaded in THIS block (-> jmp / branch / call
if a continuation was also pushed) or the symbolic incoming continuation (-> a real `ret`). No
cross-block stack threading is needed: locally-loaded targets resolve concretely, and the deferred
continuation flow is carried by emitting call/ret, which the reader/decompiler understands.

  usage: deflatten.py <function_entry_hex> [--max-blocks N] [--img PATH] [--stats]
"""
import sys, os, re
import capstone

B = 0x140000000
# image path: env override (so an importer like dethread.py can point us at its input),
# then --img, then the default in cwd.
IMG = os.environ.get("DEFLAT_IMG", "destiny2_devmp4_pe.bin")
for i, a in enumerate(sys.argv):
    if a == "--img":
        IMG = sys.argv[i + 1]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
d = open(IMG, "rb").read()
EXEC = ((0x140001000, 0x141b8bc00), (0x143cc3000, 0x148a4a200))
incode = lambda x: any(lo <= x < hi for lo, hi in EXEC)

GPR = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
_RSP_DISP = re.compile(r"\[rsp(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\]")


def rsp_disp(operand):
    m = _RSP_DISP.search(operand)
    if not m:
        return None
    if m.group(1) is None:
        return 0
    v = int(m.group(2), 0)
    return v if m.group(1) == "+" else -v


def target_of(ins):
    if ins.mnemonic == "lea" and "rip" in ins.op_str:
        return ins.address + ins.size + ins.disp
    if ins.mnemonic == "movabs":
        try:
            t = int(ins.op_str.split(", ")[1], 0)
            return t if incode(t) else None
        except Exception:
            return None
    return None


def disasm_block(start, limit=2200):
    ins = []
    pos = start
    while pos - start < limit:
        i = next(md.disasm(d[pos - B:pos - B + 16], pos), None)
        if i is None:
            return ins, "bad"
        ins.append(i)
        if i.mnemonic == "ret":
            return ins, "ret"
        # a `call` does NOT end the block - it returns, and the block continues to its threaded
        # `ret`. Only a `jmp` (or an unresolved indirect jmp) terminates. Stopping at a body call
        # was cutting threaded blocks short and losing their real dispatch edges.
        if i.mnemonic == "jmp":
            return ins, ("jmp" if i.op_str.startswith("0x") else "indirect")
        pos = i.address + i.size
    return ins, "toolong"


def interp(ins_list):
    """Abstract-interpret the block's stack effect. Returns list of (target, conts, cond) outcomes;
    target is int | ('IN',off) | None. `cond` is the cmov condition suffix (e.g. 'ne') for the
    TAKEN side of a conditional, else None - used to emit `jcc` when de-threading."""
    outcomes = []

    def run(idx, stack, regs, rsp, depth, cond):
        if depth > 40 or len(outcomes) > 64:
            outcomes.append((None, [], None))
            return
        while idx < len(ins_list):
            ins = ins_list[idx]
            m, ops = ins.mnemonic, ins.op_str
            if m == "nop":
                idx += 1
                continue
            if m == "ret":
                tgt = stack.get(rsp, ("IN", rsp))
                conts = [stack[o] for o in sorted(stack) if o > rsp and isinstance(stack[o], int)]
                outcomes.append((tgt, conts, cond))
                return
            t = target_of(ins)
            if t is not None:
                regs[ops.split(",")[0].strip()] = t
                idx += 1
                continue
            if m == "push":
                rsp -= 8
                r = ops.strip()
                stack[rsp] = regs.get(r, ("REG", r))   # keep the reg NAME for icall recovery
                idx += 1
                continue
            if m == "pop":
                regs[ops.strip()] = stack.get(rsp, ("IN", rsp))
                rsp += 8
                idx += 1
                continue
            if m == "xchg" and "[rsp]" in ops:
                r = ops.split(",")[1].strip()
                top = stack.get(rsp, ("IN", rsp))
                stack[rsp] = regs.get(r)
                regs[r] = top
                idx += 1
                continue
            if m.startswith("cmov"):
                dst, src = [x.strip() for x in ops.split(",")]
                cc = m[4:]                                                     # condition suffix
                run(idx + 1, dict(stack), {**regs, dst: regs.get(src)}, rsp, depth + 1, cc)  # taken
                run(idx + 1, dict(stack), dict(regs), rsp, depth + 1, cond)                  # not taken
                return
            if m in ("add", "sub", "lea") and ops.startswith("rsp"):
                if m == "lea":
                    rsp += (rsp_disp(ops.split(",", 1)[1]) or 0)
                else:
                    try:
                        imm = int(ops.split(",")[1].strip(), 0)
                        rsp += imm if m == "add" else -imm
                    except Exception:
                        pass
                idx += 1
                continue
            if m == "mov":
                dst, src = [x.strip() for x in ops.split(",", 1)]
                if "[rsp" in src:
                    dd = rsp_disp(src)
                    if dd is not None:
                        regs[dst] = stack.get(rsp + dd, ("IN", rsp + dd))
                elif "[rsp" in dst:
                    dd = rsp_disp(dst)
                    if dd is not None:
                        stack[rsp + dd] = regs.get(src)
                elif src in GPR and dst in GPR:
                    regs[dst] = regs.get(src)
                idx += 1
                continue
            idx += 1  # opaque
        outcomes.append((None, [], None))

    run(0, {}, {}, 0, 0, None)
    return outcomes


def classify(ins_list, term):
    if term in ("jmp", "call"):
        return {"kind": term, "targets": [int(ins_list[-1].op_str, 16)], "conts": []}
    if term == "indirect":
        return {"kind": "indirect", "targets": [], "conts": []}
    if term != "ret":
        return {"kind": term, "targets": [], "conts": []}
    ints, has_ret, has_indirect, conts = [], False, False, []
    taken = taken_cond = fallthrough = icall_reg = None
    for tgt, cs, cond in interp(ins_list):
        for c in cs:
            if c not in conts:
                conts.append(c)
        if isinstance(tgt, int):
            if tgt not in ints:
                ints.append(tgt)
            if cond is not None and taken is None:
                taken, taken_cond = tgt, cond      # the cmov-taken side
            elif cond is None and fallthrough is None:
                fallthrough = tgt                  # the default side
        elif isinstance(tgt, tuple) and tgt[0] == "IN":
            has_ret = True                         # returns to an incoming continuation
            if cond is None:
                fallthrough = ("ret",)
        elif isinstance(tgt, tuple) and tgt[0] == "REG":
            has_indirect = True                    # jmp <reg> -> indirect call to that register
            if icall_reg is None:
                icall_reg = tgt[1]
        else:                                       # None -> indirect, register unknown
            has_indirect = True
    if len(ints) >= 2:
        return {"kind": "branch", "targets": ints[:2], "conts": conts,
                "cond": taken_cond, "taken": taken, "fallthrough": fallthrough}
    if len(ints) == 1 and has_ret:
        return {"kind": "cbranch_ret", "targets": ints, "conts": conts,
                "cond": taken_cond, "taken": taken if taken is not None else ints[0]}
    if len(ints) == 1:
        return {"kind": "call" if conts else "jmp", "targets": ints, "conts": conts}
    # icall ONLY when the dispatch target is a genuine runtime register (has_indirect). A ret whose
    # target is the incoming continuation (has_ret) is a REAL return, even if some code pointer sits
    # on the stack as data (that would falsely look like a "continuation") -- classify it as `ret`.
    if conts and has_indirect:
        return {"kind": "icall", "targets": [], "conts": conts, "reg": icall_reg}
    return {"kind": "ret", "targets": [], "conts": []}


def strip_epilogue(ins_list):
    def is_thread(i):
        m, o = i.mnemonic, i.op_str
        if m in ("nop", "ret", "push", "pop"):
            return True
        if target_of(i) is not None:            # lea reg,[rip] / movabs reg,imm (a target load)
            return True
        if m == "xchg" and "[rsp]" in o:
            return True
        if m.startswith("cmov"):
            return True
        if m == "mov" and "[rsp" in o:          # stack-slot read/write (continuation patch)
            return True
        if m in ("add", "sub") and o.startswith("rsp"):          # add/sub rsp,imm (threading)
            return True
        # `lea rsp,[rsp+/-X]` is a threading rsp-adjust, but `lea rsp,[rbp+X]` is a real FRAME
        # RESTORE (function epilogue) -- never strip that, or the return gets corrupted.
        if m == "lea" and o.replace(" ", "").startswith("rsp,[rsp"):
            return True
        return False
    k = len(ins_list)
    while k > 0 and is_thread(ins_list[k - 1]):
        k -= 1
    return ins_list[:k]


def deflatten(entry, maxb):
    seen, order, work = set(), [], [entry]
    stats = {}
    while work and len(order) < maxb:
        a = work.pop(0)
        if a in seen or not incode(a):
            continue
        seen.add(a)
        ins_list, term = disasm_block(a)
        if not ins_list:
            continue
        c = classify(ins_list, term)
        stats[c["kind"]] = stats.get(c["kind"], 0) + 1
        order.append((a, ins_list, c))
        for t in list(c["targets"]) + list(c.get("conts", [])):   # follow branches AND continuations
            if t not in seen:
                work.append(t)
    print(f"; deflattened @ {entry:#x} - {len(order)} blocks   {stats}\n")
    if "--stats" in sys.argv:
        return stats
    for a, ins_list, c in order:
        print(f"loc_{a:x}:")
        for i in strip_epilogue(ins_list):
            print(f"    {i.address:#011x}  {i.mnemonic} {i.op_str}")
        k, tg, ct = c["kind"], c["targets"], c.get("conts", [])
        cs = ("   ; ret-> " + ", ".join(f"loc_{x:x}" for x in ct)) if ct else ""
        if k == "jmp":
            print(f"      jmp    loc_{tg[0]:x}")
        elif k == "call":
            print(f"      call   loc_{tg[0]:x}{cs}")
        elif k == "branch":
            print(f"      jcc    loc_{tg[1]:x}")
            print(f"      jmp    loc_{tg[0]:x}{cs}")
        elif k == "cbranch_ret":
            print(f"      jcc    loc_{tg[0]:x}{cs}")
            print(f"      ret")
        elif k == "icall":
            print(f"      call   <indirect>{cs}")
        elif k == "ret":
            print(f"      ret")
        elif k == "indirect":
            print(f"      {ins_list[-1].mnemonic}    {ins_list[-1].op_str}   ; indirect (unresolved)")
        else:
            print(f"      ; terminator={k}")
        print()
    return stats


if __name__ == "__main__":
    entry = int(sys.argv[1], 16)
    maxb = 300
    if "--max-blocks" in sys.argv:
        maxb = int(sys.argv[sys.argv.index("--max-blocks") + 1])
    deflatten(entry, maxb)
