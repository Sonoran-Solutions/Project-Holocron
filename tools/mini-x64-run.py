#!/usr/bin/env python3
"""Minimal x86-64 interpreter for one small, self-contained leaf function.

Built to answer one concrete question: what does 0x140414bd0 actually return
given a synthetic object with a chosen value at +0x18?  Reading it by eye
produced two mutually inconsistent conclusions, so run it instead.

Only the instructions this function (and the tiny callees it reaches) use are
implemented: mov/movsd/xor/xorps/inc/dec/cmp/jl/jg/ja/jne/je/jmp/xchg/add/
sub/lea/call/ret/divsd/mulsd/cvtsi2sd/cvttsd2si/push/pop/nop/int3.

Unknown instructions raise rather than silently mis-executing.
"""
import importlib.util
import struct
import sys

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'
# capstone register IDs are NOT sequential from RAX (X86_REG_RCX == 38 while
# X86_REG_RAX == 35), so map by constant name rather than by index arithmetic.
def _regmap():
    """Map *every* capstone x86 register id to its lowercase name.

    Restricting this to the general-purpose registers made any xmm/rip operand
    raise, and the historical index-arithmetic version silently aliased rcx onto
    rbx (X86_REG_RCX is 38, X86_REG_RAX is 35).
    """
    import capstone
    m = {}
    for attr in dir(capstone.x86):
        if attr.startswith('X86_REG_') and attr != 'X86_REG_INVALID':
            cid = getattr(capstone.x86, attr)
            if isinstance(cid, int):
                m[cid] = attr[len('X86_REG_'):].lower()
    return m


REGID = _regmap()

# 32/16/8-bit aliases collapsed onto their 64-bit register name
SUBREG = {}
for _n in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
    SUBREG[_n] = 'r' + _n
    SUBREG['e' + _n] = 'r' + _n
for _n in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'):
    SUBREG[_n] = 'r' + _n[0] + ('x' if _n[0] in 'abcd' else '')
SUBREG.update({'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
               'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
               'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp'})
for _i in range(8, 16):
    for _suf in ('d', 'w', 'b'):
        SUBREG['r%d%s' % (_i, _suf)] = 'r%d' % _i
REGS64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


class Mem:
    """Sparse memory: dict addr -> byte, plus a read-only image overlay."""

    def __init__(self, tk):
        self.tk = tk
        self.store = {}
        self.writes = []

    def _imgoff(self, a):
        o = self.tk._off(a)
        return o

    # synthetic heap: outside the image and outside the stack, reads yield 0
    HEAP_LO = 0x20000000
    HEAP_HI = 0x30000000
    STACK_LO = 0x0f0000
    STACK_HI = 0x110000

    def rb(self, a):
        if a in self.store:
            return self.store[a]
        if self.HEAP_LO <= a < self.HEAP_HI or self.STACK_LO <= a < self.STACK_HI:
            return 0
        o = self._imgoff(a)
        if o is None or o >= len(self.tk.pe().__data__):
            raise RuntimeError('read from unmapped %x' % a)
        return self.tk.pe().__data__[o]

    def wb(self, a, v):
        self.store[a] = v & 0xff
        self.writes.append((a, v & 0xff))

    def rq(self, a):
        return struct.unpack('<Q', bytes(self.rb(a + i) for i in range(8)))[0]

    def wq(self, a, v):
        for i in range(8):
            self.wb(a + i, (v >> (8 * i)) & 0xff)

    def rd(self, a):
        return struct.unpack('<I', bytes(self.rb(a + i) for i in range(4)))[0]

    def wd(self, a, v):
        for i in range(4):
            self.wb(a + i, (v >> (8 * i)) & 0xff)


SHOW = bool(__import__('os').environ.get('EMU_STEPS'))


def run(tk, entry, obj, field_off, field_val, max_steps=20000):
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    mem = Mem(tk)
    r = {k: 0 for k in REGS64}
    r['rsp'] = 0x100000
    r['rcx'] = obj
    r['rdi'] = 0
    r['rbx'] = 0
    # object memory
    mem.wd(obj + field_off, field_val)
    mem.wq(obj + 0x00, 0)
    mem.wq(obj + 0x08, 0)
    mem.wq(obj + 0x20, 0)
    print('   [setup] obj=%x field+0x%x=%x' % (obj, field_off, field_val))
    flags = {'zf': False, 'cf': False, 'sf': False, 'of': False}
    rsp_top = r['rsp']
    mem.wq(rsp_top, 0xDEAD)          # fake return address

    def operand_size(ins):
        """Bit width of the *written* operand.

        Deriving this from the operand text is unreliable for reg-to-reg moves
        (the string has no size keyword), which silently made `mov rdi, rcx`
        an 8-bit store into rsp.  Use capstone's op.size instead.
        """
        return ins.operands[0].size * 8

    def rn(regid):
        """register id -> canonical 64-bit name.

        capstone reports the *written* operand of `mov eax, 1` as register id
        for EAX, not RAX.  Storing that under its own key made every 32-bit
        write invisible to a later 64-bit read (`mov eax,1; ret` returned 0).
        Collapse the sub-register names onto the 64-bit name, which is correct
        for every use in this function (32-bit writes zero-extend).
        """
        if regid not in REGID:
            raise RuntimeError('unsupported register id %d' % regid)
        n = REGID[regid]
        return SUBREG.get(n, n)

    def reg_of(op):
        if op.type != capstone.x86.X86_OP_REG:
            raise RuntimeError('reg_of on non-register operand')
        return rn(op.reg)

    def r32(name):
        v = r[name]
        # 32-bit ops zero-extend
        return v & 0xffffffff

    def set32(name, v):
        r[name] = v & 0xffffffff

    pc = entry
    trace = []
    try:
      for step in range(max_steps):
          code = bytes(mem.rb(pc + i) for i in range(16))
          insns = list(md.disasm(code, pc))
          if not insns:
              raise RuntimeError('bad decode at %x' % pc)
          i = insns[0]
          mn, ops = i.mnemonic, i.operands
          trace.append('%-9s %s' % (mn, i.op_str))
          if SHOW:
              print('  %x: %-9s %-38s rcx=%x rdi=%x rax=%x rsp=%x'
                    % (pc, mn, i.op_str, r['rcx'], r['rdi'], r['rax'], r['rsp']))

          def operand_val(op, size=64):
              if op.type == capstone.x86.X86_OP_REG:
                  return r[reg_of(op)]
              if op.type == capstone.x86.X86_OP_IMM:
                  return op.imm
              if op.type == capstone.x86.X86_OP_MEM:
                  base = r[rn(op.mem.base)] if op.mem.base else 0
                  idx = r[rn(op.mem.index)] * op.mem.scale if op.mem.index else 0
                  addr = (base + idx + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                  if size == 64:
                      return mem.rq(addr)
                  if size == 32:
                      return mem.rd(addr)
                  return mem.rb(addr)
              raise RuntimeError('operand')

          def store(op, val, size=64):
              if op.type == capstone.x86.X86_OP_REG:
                  if size == 64:
                      r[reg_of(op)] = val & 0xFFFFFFFFFFFFFFFF
                  else:
                      set32(reg_of(op), val)
                  return
              base = r[rn(op.mem.base)] if op.mem.base else 0
              idx = r[rn(op.mem.index)] * op.mem.scale if op.mem.index else 0
              addr = (base + idx + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
              if size == 64:
                  mem.wq(addr, val)
              elif size == 32:
                  mem.wd(addr, val)
              else:
                  mem.wb(addr, val)

          if mn == 'mov':
              size = operand_size(i)
              store(ops[0], operand_val(ops[1], size), size)
          elif mn == 'xor' and len(ops) == 2 and \
                  ops[0].type == capstone.x86.X86_OP_REG and \
                  ops[1].type == capstone.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
              store(ops[0], 0, 64)
          elif mn == 'xorps':
              pass
          elif mn == 'movaps':
              pass
          elif mn == 'movsd':
              pass
          elif mn == 'inc':
              store(ops[0], operand_val(ops[0]) + 1, 64)
          elif mn == 'dec':
              store(ops[0], operand_val(ops[0]) - 1, 64)
          elif mn == 'add':
              store(ops[0], operand_val(ops[0]) + operand_val(ops[1]), 64)
          elif mn == 'sub':
              store(ops[0], operand_val(ops[0]) - operand_val(ops[1]), 64)
          elif mn == 'and':
              store(ops[0], operand_val(ops[0]) & operand_val(ops[1]), 64)
          elif mn == 'or':
              store(ops[0], operand_val(ops[0]) | operand_val(ops[1]), 64)
          elif mn == 'lea':
              base = r[rn(ops[1].mem.base)] if ops[1].mem.base else 0
              idx = r[rn(ops[1].mem.index)] * ops[1].mem.scale if ops[1].mem.index else 0
              store(ops[0], (base + idx + ops[1].mem.disp) & 0xFFFFFFFFFFFFFFFF, 64)
          elif mn == 'cmp':
              a = operand_val(ops[0])
              b = operand_val(ops[1])
              d = (a - b) & 0xFFFFFFFFFFFFFFFF
              flags['zf'] = (d == 0)
              flags['sf'] = bool(d & 0x8000000000000000)
              flags['cf'] = a < b
          elif mn == 'test':
              d = operand_val(ops[0]) & operand_val(ops[1])
              flags['zf'] = (d == 0)
              flags['sf'] = bool(d & 0x8000000000000000)
              flags['cf'] = False
          elif mn == 'xchg':
              a = operand_val(ops[0], 32)
              b = operand_val(ops[1], 32)
              store(ops[0], b, 32)
              store(ops[1], a, 32)
          elif mn.startswith('j'):
              if mn == 'jmp':
                  pc = ops[0].imm
                  continue
              take = False
              if mn == 'je' or mn == 'jz':
                  take = flags['zf']
              elif mn == 'jne' or mn == 'jnz':
                  take = not flags['zf']
              elif mn == 'jl':
                  take = flags['sf'] != flags['of']
              elif mn == 'jg':
                  take = (not flags['zf']) and (flags['sf'] == flags['of'])
              elif mn == 'ja':
                  take = (not flags['cf']) and (not flags['zf'])
              elif mn == 'jae':
                  take = not flags['cf']
              elif mn == 'jle':
                  take = flags['zf'] or (flags['sf'] != flags['of'])
              else:
                  raise RuntimeError('unhandled jump %s' % mn)
              pc = ops[0].imm if take else pc + i.size
              continue
          elif mn == 'call':
              if ops[0].type == capstone.x86.X86_OP_IMM:
                  tgt = ops[0].imm
                  # only model the sleep helper as a no-op that succeeds
                  if tgt == 0x140fd9490:
                      r['rax'] = 0
                      pc += i.size
                      continue
                  raise RuntimeError('call to unmodelled %x at %x' % (tgt, pc))
              # indirect import call
              slot = None
              if ops[0].type == capstone.x86.X86_OP_MEM and ops[0].mem.base == \
                      capstone.x86.X86_REG_RIP:
                  slot = pc + i.size + ops[0].mem.disp
              imp = tk.iat_lookup(slot) if slot else None
              name = imp[1] if imp else '?'
              if name == 'QueryPerformanceFrequency':
                  mem.wq(r['rsp'] + 0x48, 10000000)
                  r['rax'] = 1
              elif name == 'QueryPerformanceCounter':
                  mem.wq(r['rsp'] + 0x40, mem.rq(r['rsp'] + 0x40) + 1)
                  r['rax'] = 1
              else:
                  raise RuntimeError('unmodelled import %s at %x' % (name, pc))
          elif mn in ('push',):
              r['rsp'] -= 8
              mem.wq(r['rsp'], operand_val(ops[0]))
          elif mn == 'pop':
              store(ops[0], mem.rq(r['rsp']), 64)
              r['rsp'] += 8
          elif mn == 'nop':
              pass
          elif mn in ('ret', 'retn'):
              pc = mem.rq(r['rsp'])
              if pc == 0xDEAD:
                  return r['rax'] & 0xffffffff, trace, mem
              r['rsp'] += 8
              continue
          elif mn == 'int3':
              raise RuntimeError('int3 at %x' % pc)
          elif mn in ('divsd', 'mulsd', 'cvtsi2sd', 'cvttsd2si'):
              # timing arithmetic: not needed for the lock-word question
              r['rax'] = r.get('rax', 0)
          else:
              raise RuntimeError('unhandled %s %s at %x' % (mn, i.op_str, pc))
          pc += i.size

    except Exception as e:
        raise RuntimeError('%s  [pc=%x] trace_tail=%s' % (e, pc, trace[-4:]))



if __name__ == '__main__':
    tk = load()
    entry = int(sys.argv[1], 16)
    field_off = int(sys.argv[2], 16)
    for fv in [int(x, 16) for x in sys.argv[3:]] or [0, 4, 9]:
        obj = 0x20000000
        trace = []
        trace = []
        try:
            ret, trace, mem = run(tk, entry, obj, field_off, fv)
            final = mem.rd(obj + field_off)
            if __import__('os').environ.get('EMU_STEPS'):
                print('    trace:')
                for t in trace:
                    print('      %s' % t)
            print('[+0x%x]=0x%-4x -> rax=0x%-4x  field_after=0x%x  steps=%d'
                  % (field_off, fv, ret, final, len(trace)))
        except Exception as e:
            print('[+0x%x]=0x%-4x -> ERROR %s' % (field_off, fv, e))
            print('    last 6 executed: %s' % trace[-6:])
            if __import__('os').environ.get('EMU_TRACE'):
                traceback.print_exc()
