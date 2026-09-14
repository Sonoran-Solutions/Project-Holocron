#!/usr/bin/env python3
"""Print the direct branch targets of a function, in address order.

Usage: branches.py <func_va>
"""
import importlib.util
import sys

import capstone

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


def main():
    tk = load()
    fva = int(sys.argv[1], 16)
    f = tk.func_at(fva)
    md = tk.md()
    pc = f[0]
    print('fn %x - %x' % (f[0], f[1]))
    while pc < f[1]:
        got = list(md.disasm(tk.data(pc, 16), pc))
        if not got:
            pc += 1
            continue
        i = got[0]
        if (i.mnemonic.startswith('j') or i.mnemonic == 'call') and i.operands and \
                i.operands[0].type == capstone.x86.X86_OP_IMM:
            t = i.operands[0].imm
            inside = '' if f[0] <= t < f[1] else '   <== OUTSIDE'
            if i.mnemonic != 'call' or inside:
                print('%x  %-8s -> %x%s' % (pc, i.mnemonic, t, inside))
        pc += i.size
    return 0


if __name__ == '__main__':
    sys.exit(main())
