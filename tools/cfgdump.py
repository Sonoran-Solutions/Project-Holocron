#!/usr/bin/env python3
"""Recursive-descent disassembly for the retail swtor.exe image.

A flat linear sweep of a function's bytes desynchronises as soon as it runs into
embedded data, a jump table, or alignment padding, and then emits plausible but
completely wrong instructions.  This tool decodes from the function entry and
follows control flow, so every address printed is a real instruction boundary.

Usage:
    cfgdump.py <func_va> [--all]
        --all   keep decoding after a terminator (fills in unreached blocks)
"""
import importlib.util
import sys

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


TERMS = {'ret', 'jmp', 'ud2', 'int3', 'hlt'}


def disasm_func(tk, start, end, keep_after_term=False):
    """Recursive descent over [start, end).  Returns {addr: (mnem, opstr, size)}."""
    import capstone
    md = tk.md()
    seen = {}
    work = [start]
    while work:
        pc = work.pop()
        while start <= pc < end:
            if pc in seen:
                break
            insns = list(md.disasm(tk.data(pc, min(16, end - pc)), pc))
            if not insns:
                break
            i = insns[0]
            seen[i.address] = (i.mnemonic, i.op_str, i.size,
                               tuple((o.type, getattr(o, 'imm', None))
                                     for o in i.operands),
                               i.group(capstone.x86.X86_GRP_JUMP),
                               i.group(capstone.x86.X86_GRP_CALL))
            nxt = i.address + i.size
            groups = (i.group(capstone.x86.X86_GRP_JUMP),
                      i.group(capstone.x86.X86_GRP_CALL),
                      i.group(capstone.x86.X86_GRP_RET),
                      i.group(capstone.x86.X86_GRP_INT))
            is_ret = i.mnemonic in ('ret', 'retn') or bool(groups[2])
            # direct branch target
            tgt = None
            if i.operands and i.operands[0].type == capstone.x86.X86_OP_IMM and \
                    (groups[0] or groups[1]) and i.mnemonic != 'call':
                tgt = i.operands[0].imm
            if i.mnemonic == 'jmp' and tgt is not None:
                if start <= tgt < end:
                    work.append(tgt)
                break                      # tail jump: stop this path
            if tgt is not None and start <= tgt < end:
                work.append(tgt)           # conditional branch
            if is_ret or i.mnemonic in ('ud2', 'int3', 'hlt'):
                if not keep_after_term:
                    break
            pc = nxt
    return seen


def main():
    tk = load()
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    va = int(sys.argv[1], 16)
    keep = '--all' in sys.argv
    f = tk.func_at(va)
    if not f:
        print('no .pdata function at %x' % va)
        return 1
    seen = disasm_func(tk, f[0], f[1], keep)
    print('; fn %x - %x  (%d instructions reached)' % (f[0], f[1], len(seen)))
    for a in sorted(seen):
        mn, ops, sz, _o, _j, _c = seen[a]
        print('%x: %-9s %s' % (a, mn, ops))
    # report byte gaps that were never decoded (data / unreachable)
    gaps = []
    prev = None
    for a in sorted(seen):
        if prev is not None and a > prev:
            gaps.append((prev, a))
        prev = a + seen[a][2]
    if gaps:
        print('; %d undecoded gap(s): %s' %
              (len(gaps), ', '.join('%x-%x' % g for g in gaps[:12])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
