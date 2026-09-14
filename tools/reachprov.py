#!/usr/bin/env python3
"""Reachability-aware register provenance inside one function.

Unlike provenance.py (which follows the fallthrough path only and therefore
misses anything behind a conditional branch), this walks every reachable
instruction of the containing function and reports, for a chosen stop address,
every write to the registers that feed that instruction.

Usage: reachprov.py <func_va> <stop_va> [regs...]
"""
import importlib.util
import sys

import capstone

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'

# NOTE: capstone 5's *operand* register ids are not the X86_REG_* enum values,
# so names must come from Cs.reg_name() rather than a static enum table.
REG = {}


def rn(insn, reg):
    return insn.reg_name(reg)


# sub-register -> full register
ALIAS = {}
for full, parts in {
    'rax': ('eax', 'ax', 'al', 'ah'),
    'rbx': ('ebx', 'bx', 'bl', 'bh'),
    'rcx': ('ecx', 'cx', 'cl', 'ch'),
    'rdx': ('edx', 'dx', 'dl', 'dh'),
    'rsi': ('esi', 'si', 'sil'),
    'rdi': ('edi', 'di', 'dil'),
    'rbp': ('ebp', 'bp', 'bpl'),
    'rsp': ('esp', 'sp', 'spl'),
}.items():
    ALIAS[full] = full
    for p in parts:
        ALIAS[p] = full
for i in range(8, 16):
    ALIAS['r%d' % i] = 'r%d' % i
    ALIAS['r%dd' % i] = 'r%d' % i
    ALIAS['r%dw' % i] = 'r%d' % i
    ALIAS['r%db' % i] = 'r%d' % i


def canon(name):
    return ALIAS.get(name, name)


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


def mem_text(insn, op):
    base = insn.reg_name(op.mem.base) if op.mem.base else ''
    idx = ''
    if op.mem.index:
        idx = ' + %s*%d' % (insn.reg_name(op.mem.index), op.mem.scale)
    disp = ''
    if op.mem.disp:
        disp = ' + 0x%x' % op.mem.disp if op.mem.disp > 0 else ' - 0x%x' % -op.mem.disp
    return '[%s%s%s]' % (base, idx, disp)


def main():
    tk = load()
    fva = int(sys.argv[1], 16)
    stop = int(sys.argv[2], 16)
    want = set(sys.argv[3:]) or {'rax', 'rcx', 'rdx', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}
    want = {canon(w) for w in want}
    f = tk.func_at(fva)
    md = tk.md()

    # --- decode every instruction in the range -------------------------------
    insns = {}
    pc = f[0]
    while pc < f[1]:
        got = list(md.disasm(tk.data(pc, min(16, f[1] - pc)), pc))
        if not got:
            pc += 1
            continue
        insns[pc] = got[0]
        pc += got[0].size
    order = sorted(insns)

    # --- CFG reachability from entry ----------------------------------------
    reach = set()
    work = [f[0]]
    while work:
        a = work.pop()
        if a in reach or a not in insns:
            continue
        reach.add(a)
        i = insns[a]
        nxt = a + i.size
        mn = i.mnemonic
        if mn == 'ret' or mn.startswith('ret') or mn == 'int3':
            continue
        if mn == 'jmp':
            t = i.operands[0]
            work.append(t.imm if t.type == capstone.x86.X86_OP_IMM else nxt)
            continue
        if mn.startswith('j') or mn in ('loop', 'jrcxz'):
            t = i.operands[0]
            if t.type == capstone.x86.X86_OP_IMM:
                work.append(t.imm)
            work.append(nxt)
            continue
        work.append(nxt)

    print('=== %x..%x: %d/%d instructions reachable from entry ===' %
          (f[0], f[1], len(reach), len(insns)))
    if stop not in insns:
        print('stop %x not inside function' % stop)
        return 1
    if stop not in reach:
        print('WARNING: stop %x is NOT reachable from the entry by linear CFG walk' % stop)

    # --- every write to the wanted registers, anywhere in the function -------
    writes = {r: [] for r in want}
    for a in order:
        i = insns[a]
        if not i.operands:
            continue
        d = i.operands[0]
        if d.type != capstone.x86.X86_OP_REG:
            continue
        r = canon(rn(i, d.reg))
        if r not in want:
            continue
        txt = '%s %s' % (i.mnemonic, i.op_str)
        # only record writers that can reach the stop (or are before it and reachable)
        writes[r].append((a, txt, a in reach))
        if a >= stop and i.mnemonic != 'mov':
            pass

    for r in sorted(want):
        ws = [w for w in writes[r] if w[2]]
        if not ws:
            print('%-4s : no reachable writer (incoming argument)' % r)
            continue
        before = [w for w in ws if w[0] < stop]
        print('%-4s : last writer before %x:' % (r, stop))
        for a, txt, _ in before[-4:]:
            print('         %x  %s' % (a, txt))
        after = [w for w in ws if w[0] > stop]
        if after:
            print('       later writers (would overwrite after the stop):')
            for a, txt, _ in after[:6]:
                print('         %x  %s' % (a, txt))
    return 0


if __name__ == '__main__':
    sys.exit(main())
