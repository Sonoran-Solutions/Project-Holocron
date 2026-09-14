#!/usr/bin/env python3
"""Track register provenance through one function to a chosen address.

Walks the function from its entry and records, for every register, whether it
holds a stack temp, a small immediate, a memory load, a result of a call, or is
still the incoming argument.  At the tracked address it prints the chain so a
comparison like `cmp eax, 4` can be attributed to a concrete field instead of
being guessed from the call's name.

Usage: provenance.py <func_va> <stop_va>
"""
import importlib.util
import sys

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


class Val:
    """Symbolic value: kind + text, with a short derivation chain."""

    def __init__(self, kind, text, chain=None):
        self.kind = kind          # arg, imm, mem, call, unknown
        self.text = text
        self.chain = list(chain or [])

    def bind(self, extra):
        return Val(self.kind, self.text, self.chain + [extra])

    def __repr__(self):
        return '%s(%s)' % (self.kind, self.text)


def mem_text(op):
    import capstone
    base = ''
    if op.mem.base:
        base = REG[op.mem.base]
    idx = ''
    if op.mem.index:
        idx = ' + %s*%d' % (REG[op.mem.index], op.mem.scale)
    disp = ''
    if op.mem.disp:
        disp = ' + 0x%x' % op.mem.disp if op.mem.disp > 0 else ' - 0x%x' % -op.mem.disp
    return '[%s%s%s]' % (base, idx, disp)


import capstone
REG = {getattr(capstone.x86, n): n[4:].lower()
       for n in dir(capstone.x86) if n.startswith('X86_REG_')}


def main():
    tk = load()
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    fva = int(sys.argv[1], 16)
    stop = int(sys.argv[2], 16)
    f = tk.func_at(fva)
    md = tk.md()

    # seed args
    env = {}
    for r in ('rcx', 'rdx', 'r8', 'r9'):
        env[r] = Val('arg', 'arg_%s' % r)
    env['rax'] = Val('unknown', 'rax')
    env['rsp'] = Val('arg', 'rsp')

    pc = f[0]
    steps = 0
    while f[0] <= pc < f[1] and steps < 4000:
        steps += 1
        insns = list(md.disasm(tk.data(pc, min(16, f[1] - pc)), pc))
        if not insns:
            break
        i = insns[0]
        mn, ops = i.mnemonic, i.operands

        if pc == stop:
            print('=== state at %x ===' % pc)
            for r in sorted(env):
                print('   %-5s = %r' % (r, env[r]))
                for c in env[r].chain:
                    print('           %s' % c)
            return 0

        def setreg(r, v):
            env[r] = v

        # mov dst, src
        if mn == 'mov' and len(ops) == 2:
            d, s = ops
            if d.type == capstone.x86.X86_OP_REG:
                dr = REG[d.reg]
                if s.type == capstone.x86.X86_OP_REG:
                    setreg(dr, env.get(REG[s.reg], Val('unknown', REG[s.reg])))
                elif s.type == capstone.x86.X86_OP_IMM:
                    setreg(dr, Val('imm', '0x%x' % s.imm))
                elif s.type == capstone.x86.X86_OP_MEM:
                    t = mem_text(s)
                    base = REG.get(s.mem.base)
                    src = env.get(base) if base else None
                    ch = []
                    if src:
                        ch.append('from %s = %s' % (base, src.text))
                        ch.extend(src.chain)
                    if s.mem.disp:
                        ch.append('field +0x%x' % s.mem.disp)
                    setreg(dr, Val('mem', t, ch))
        elif mn in ('xor', 'sub') and len(ops) == 2 and \
                ops[0].type == capstone.x86.X86_OP_REG and \
                ops[1].type == capstone.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
            setreg(REG[ops[0].reg], Val('imm', '0'))
        elif mn == 'lea' and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG:
            if ops[1].type == capstone.x86.X86_OP_MEM:
                t = mem_text(ops[1])
                setreg(REG[ops[0].reg], Val('mem', t, ['lea (address of)']))
        elif mn == 'call':
            tgt = ops[0].imm if ops[0].type == capstone.x86.X86_OP_IMM else None
            if tgt is not None:
                f2 = tk.func_at(tgt)
                setreg('rax', Val('call', 'ret(%x)' % tgt,
                                  ['call %x%s' % (tgt, ' fn %x-%x' % f2 if f2 else '')]))
            else:
                setreg('rax', Val('call', 'ret(indirect)'))
        elif mn.startswith('cmp') and len(ops) == 2:
            a, b = ops
            for side, other in ((a, b), (b, a)):
                if side.type == capstone.x86.X86_OP_REG:
                    r = REG[side.reg]
                    v = env.get(r)
                    o = ('0x%x' % other.imm) if other.type == capstone.x86.X86_OP_IMM else \
                        (mem_text(other) if other.type == capstone.x86.X86_OP_MEM else '?')
                    print('%x: cmp %s, %s' % (pc, r, o))
                    if v:
                        print('        %s = %s' % (r, v.text))
                        for c in v.chain:
                            print('            %s' % c)

        nxt = pc + i.size
        if mn == 'jmp':
            t = ops[0].imm if ops[0].type == capstone.x86.X86_OP_IMM else None
            if t is None:
                break
            pc = t
            continue
        if mn.startswith('j') or mn in ('ret', 'retn'):
            # follow the fallthrough only; branch targets handled by cfdump
            if mn.startswith('j') and mn != 'jmp':
                pass
            elif mn.startswith('ret'):
                break
        pc = nxt
    print('stop address %x not reached before control left the block' % stop)
    return 0


if __name__ == '__main__':
    sys.exit(main())
