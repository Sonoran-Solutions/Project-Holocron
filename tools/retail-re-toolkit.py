#!/usr/bin/env python3
"""Static reverse-engineering toolkit for the retail swtor.exe image.

Read-only. Used by the Project Holocron retail static-analysis passes.

Subcommands
-----------
func   <va>                 containing function boundaries (from .pdata)
dis    <start> <end>        linear disassembly with rip-relative annotation
cfg    <va>                 recursive-descent disassembly of the containing function
xref   <va>                 find all rip-relative and immediate references to <va>
vt     <vtable_va> [n]      dump a vtable slot by slot, resolving each target
rtti   <vtable_va|col_va>   resolve COL -> type descriptor -> class name
strings <va>...             read an ascii/utf16 string at a va
calls  <func_va>            list direct call targets inside a function
callers <func_va>           find all direct call sites of a function
"""
import sys
import struct

import pefile
import capstone

IMAGE = '/home/dq/project-holocron/.local-test/client-v1/game/swtor/retailclient/swtor.exe'
BASE = 0x140000000

_pe = None
_data = None
_funcs = None
_md = None


def pe():
    global _pe, _data
    if _pe is None:
        _pe = pefile.PE(IMAGE, fast_load=True)
        _pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
        _data = _pe.__data__
    return _pe


def _off(va):
    """Map a virtual address to a file offset.

    file_off = PointerToRawData + (va - (ImageBase + VirtualAddress))

    A plain `va - ImageBase` is WRONG: .text has VirtualAddress 0x1000 but
    PointerToRawData 0x400, .rdata 0x1369000 / 0x1367a00, .data 0x1a8c000 /
    0x1a8aa00.  Dropping the section VirtualAddress silently reads the wrong
    bytes and produces plausible-looking nonsense.
    """
    pe()
    if va < BASE:
        return None
    return _pe.get_offset_from_rva(va - BASE)


def data(va, n):
    off = _off(va)
    if off is None:
        return b''
    return _data[off:off + n]


def q(va):
    return struct.unpack('<Q', data(va, 8))[0]


def d(va):
    return struct.unpack('<I', data(va, 4))[0]


def w(va):
    return struct.unpack('<H', data(va, 2))[0]


def b(va):
    return data(va, 1)[0]


def i32(va):
    return struct.unpack('<i', data(va, 4))[0]


def md():
    global _md
    if _md is None:
        _md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        _md.detail = True
    return _md


def string(va, maxlen=512):
    raw = data(va, maxlen)
    if not raw:
        return ''
    if len(raw) > 1 and raw[1] == 0:
        return raw.decode('utf-16le', errors='replace').split('\0')[0]
    return raw.split(b'\0')[0].decode('ascii', errors='replace')


def _runtime_function_table():
    """Parse .pdata into a dict {start: max_end}.

    .pdata may hold several RUNTIME_FUNCTION entries with the same BeginAddress
    (chained unwind info).  The real function extent is the maximum EndAddress
    over those entries; keeping the first/smallest is wrong and silently
    truncates functions.
    """
    global _funcs
    if _funcs is not None:
        return _funcs
    pe()
    table = {}
    for s in pe().sections:
        if s.Name.rstrip(b'\0') == b'.pdata':
            raw = _data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
            n = len(raw) // 12
            for k in range(n):
                st, en, _u = struct.unpack_from('<III', raw, k * 12)
                if st == 0:
                    continue
                st += BASE
                en += BASE
                if en > table.get(st, 0):
                    table[st] = en
            break
    _funcs = table
    return _funcs


def func_at(va):
    fns = _runtime_function_table()
    ks = _sorted_starts()
    import bisect
    i = bisect.bisect_right(ks, va) - 1
    if i < 0:
        return None
    st = ks[i]
    en = fns[st]
    if st <= va < en:
        return st, en
    return None


_start_cache = None


def _sorted_starts():
    global _start_cache
    if _start_cache is None:
        _start_cache = sorted(_runtime_function_table())
    return _start_cache


def func_name(va):
    f = func_at(va)
    if not f:
        return None
    return f


def is_code(va):
    pe()
    for s in pe().sections:
        st = BASE + s.VirtualAddress
        if st <= va < st + s.Misc_VirtualSize:
            return bool(s.Characteristics & 0x20000000)
    return False


def dis(start, end, annotate=True):
    out = []
    for ins in md().disasm(data(start, end - start), start):
        extra = []
        if annotate:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tva = ins.address + ins.size + op.mem.disp
                    note = ''
                    if is_code(tva):
                        f = func_at(tva)
                        note = ' code' + ((' fn=%x-%x' % f) if f else '')
                    else:
                        s = string(tva, 64)
                        if s and all(32 <= ord(c) < 127 for c in s):
                            note = ' "%s"' % s
                        elif not is_code(tva):
                            v = q(tva)
                            if 0x140000000 <= v < 0x142000000:
                                note = ' ->%x' % v
                            else:
                                note = ' dword=%x' % d(tva)
                    extra.append('%x%s' % (tva, note))
                elif op.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ('call', 'jmp'):
                    extra.append('->%x' % op.imm)
        out.append((ins.address, ins.mnemonic, ins.op_str, ' | '.join(extra), ins.size))
    return out


def dis_text(start, end):
    lines = []
    for addr, mn, ops, extra, _sz in dis(start, end):
        lines.append('%x: %-8s %-46s %s' % (addr, mn, ops, extra))
    return lines


def cfg(func_va):
    """Linear sweep of the containing function; returns instruction list."""
    f = func_at(func_va)
    if not f:
        return None, []
    return f, dis(f[0], f[1])


XREF_INDEX = '/home/dq/project-holocron/scratch/retail-xref-index.bin'


def build_xref_index(path=XREF_INDEX):
    """Disassemble every .pdata function from its own entry point.

    A linear sweep from the start of .text desynchronises immediately (the
    stream runs into embedded data / padding), which silently loses real call
    sites.  Disassembling each known function entry independently avoids that,
    because an entry point is always a true instruction boundary.
    """
    pe()
    fns = sorted(_runtime_function_table().items())
    with open(path, 'wb') as f:
        for st, en in fns:
            raw = data(st, en - st)
            if not raw:
                continue
            for ins in md().disasm(raw, st):
                ops = ins.operands
                # call/jmp rel32
                if ops and ops[0].type == capstone.x86.X86_OP_IMM and \
                        ins.mnemonic in ('call', 'jmp'):
                    f.write(struct.pack('<BQQ', 1, ins.address, ops[0].imm))
                # rip-relative memory operand
                for op in ops:
                    if op.type == capstone.x86.X86_OP_MEM and \
                            op.mem.base == capstone.x86.X86_REG_RIP:
                        f.write(struct.pack(
                            '<BQQ', 2, ins.address,
                            ins.address + ins.size + op.mem.disp))
    return path


def _load_index(path=XREF_INDEX):
    import os
    if not os.path.exists(path):
        build_xref_index(path)
    byt = open(path, 'rb').read()
    idx = {}
    for k in range(0, len(byt), 17):
        kind, addr, tgt = struct.unpack_from('<BQQ', byt, k)
        idx.setdefault((kind, tgt), []).append(addr)
    return idx


_index_cache = None


def xref_indexed(target, kind=None):
    global _index_cache
    if _index_cache is None:
        _index_cache = _load_index()
    out = []
    for k in ((1, 2) if kind is None else (kind,)):
        for a in _index_cache.get((k, target), []):
            out.append((a, 'call' if k == 1 else 'rip'))
    return sorted(out)


def import_map():
    """Map each IAT slot VA -> (dll, name) for this image.

    The IAT slots in this build are populated at load time, so the on-disk
    contents are stale; never read them as pointers.  Use this map instead.
    """
    pe()
    out = {}
    d = pe().OPTIONAL_HEADER.DATA_DIRECTORY[1]
    rva = d.VirtualAddress
    while True:
        ent = data(BASE + rva, 20)
        if len(ent) < 20:
            break
        oft, tds, fc, name_rva, fthunk = struct.unpack('<IIIII', ent)
        if not any((oft, tds, fc, name_rva, fthunk)):
            break
        dll = string(BASE + name_rva, 64) if name_rva else ''
        t = BASE + (oft or tds)
        slot = BASE + fthunk
        k = 0
        while True:
            th = q(t + k * 8)
            if th == 0:
                break
            if th & 0x8000000000000000:
                nm = 'ordinal#%d' % (th & 0xffff)
            else:
                nm = string(BASE + th + 2, 128)
            out[slot + k * 8] = (dll, nm)
            k += 1
        rva += 20
    return out


import_map_cache = None


def iat_lookup(slot_va):
    global import_map_cache
    if import_map_cache is None:
        import_map_cache = import_map()
    return import_map_cache.get(slot_va)


def thunk_target(va):
    """If `va` is an `jmp qword ptr [rip+disp]` import thunk, return the slot."""
    ins = list(md().disasm(data(va, 16), va))
    if ins and ins[0].mnemonic == 'jmp' and ins[0].operands and \
            ins[0].operands[0].type == capstone.x86.X86_OP_MEM and \
            ins[0].operands[0].mem.base == capstone.x86.X86_REG_RIP:
        return ins[0].address + ins[0].size + ins[0].operands[0].mem.disp
    return None


def describe_target(va):
    """Human-readable description of a code/data target."""
    slot = thunk_target(va)
    if slot is not None:
        imp = iat_lookup(slot)
        return 'import-thunk -> slot %x %s' % (slot, imp if imp else '(unmapped)')
    f = func_at(va)
    return ('fn %x-%x' % f) if f else '(not in .pdata)'


def xref(target):
    """Rip-relative and immediate references to target, via the .pdata index."""
    return xref_indexed(target)


def xref_le64(target):
    """Find absolute 8-byte little-endian occurrences of target (vtables, etc.)."""
    pe()
    hits = []
    pat = struct.pack('<Q', target)
    for s in pe().sections:
        st = BASE + s.VirtualAddress
        raw = _data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        i = raw.find(pat)
        while i != -1:
            hits.append(st + i)
            i = raw.find(pat, i + 1)
    return hits


def resolve_col(col_va):
    """Complete Object Locator (32-bit RVAs, image loaded at its preferred base).

    Layout observed in this image:
        +0x00 signature        (1)
        +0x04 offset           (0)
        +0x08 constructor displacement
        +0x0c type_descriptor  RVA     -> TypeDescriptor
        +0x10 class_descriptor RVA     -> ClassHierarchyDescriptor
        +0x14 self             RVA     -> the COL itself
    """
    info = {
        'col': col_va,
        'signature': d(col_va),
        'offset': d(col_va + 4),
        'ctor_disp': d(col_va + 8),
        'td_rva': d(col_va + 0x0c),
        'chd_rva': d(col_va + 0x10),
        'self_rva': d(col_va + 0x14),
    }
    if info['td_rva']:
        td = BASE + info['td_rva']
        info['td'] = td
        info['name'] = string(td + 0x10, 200)
    return info


def type_descriptor_name(td_va):
    return string(td_va + 0x10, 200)


def class_hierarchy(chd_va):
    """ClassHierarchyDescriptor -> list of base-class descriptors.

    The BaseClassArray entry holds an RVA; the BaseClassDescriptor it points at
    begins at that address *minus 4* in this image (the first dword of the
    pointed-to block is the previous entry's tail), so the TypeDescriptor RVA is
    at entry+0x04, PMD follows, and pClassDescriptor at entry+0x18.
    """
    signature = d(chd_va)
    attributes = d(chd_va + 4)
    num = d(chd_va + 8)
    arr_rva = d(chd_va + 0x0c)
    out = []
    if arr_rva and 0 < num < 32:
        arr = BASE + arr_rva
        for k in range(num):
            e = BASE + d(arr + k * 4)          # entry base
            bcd = e - 4                        # descriptor base
            td_rva = d(e)
            mdisp = d(e + 4)
            pdisp = d(e + 8)
            vdisp = d(e + 0x0c)
            attrs = d(e + 0x10)
            chd = d(e + 0x18)
            out.append({
                'mdisp': mdisp, 'pdisp': pdisp, 'vdisp': vdisp,
                'attrs': attrs, 'own_chd': chd,
                'td': BASE + td_rva if td_rva else 0,
                'name': type_descriptor_name(BASE + td_rva) if td_rva else '',
            })
    return {'signature': signature, 'attributes': attributes,
            'num_base_classes': num, 'bases': out}


def class_of_vtable(vt):
    """Resolve the runtime class of a vtable.

    MSVC x64 layout around a single-inheritance vtable in this image:
        [vt-0x10] scalar-deleting destructor? (code)
        [vt-0x08] -> CompleteObjectLocator
        [vt+0x00] first virtual function
    The COL pointer is at vt-0x08.
    """
    return resolve_col(q(vt - 0x08))


def rtti_for_vtable(vt):
    return class_of_vtable(vt)


def vtable(vt, n=20):
    out = []
    for k in range(n):
        slot = q(vt + k * 8)
        f = func_at(slot)
        out.append((k, slot, f))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    a = sys.argv[2:]

    if cmd == 'func':
        va = int(a[0], 16)
        f = func_at(va)
        print('func@%x: %s' % (va, ('%x - %x (size %x)' % (f[0], f[1], f[1] - f[0])) if f else 'NOT IN .pdata'))
        return 0

    if cmd == 'dis':
        for l in dis_text(int(a[0], 16), int(a[1], 16)):
            print(l)
        return 0

    if cmd == 'cfg':
        f, ins = cfg(int(a[0], 16))
        if not f:
            print('no func')
            return 1
        print('; func %x - %x' % f)
        for addr, mn, ops, extra, _ in ins:
            print('%x: %-8s %-46s %s' % (addr, mn, ops, extra))
        return 0

    if cmd == 'xref':
        for addr, txt in xref(int(a[0], 16)):
            f = func_at(addr)
            print('%x  %-40s %s' % (addr, txt, ('fn %x' % f[0]) if f else ''))
        return 0

    if cmd == 'xrefle':
        for addr in xref_le64(int(a[0], 16)):
            print(hex(addr))
        return 0

    if cmd == 'vt':
        vt = int(a[0], 16)
        n = int(a[1]) if len(a) > 1 else 20
        info = rtti_for_vtable(vt)
        print('; rtti @%x: %s' % (vt - 8, info))
        for k, slot, f in vtable(vt, n):
            print('  [%02x] +%03x  %x  %s' % (k, k * 8, slot, ('fn %x-%x' % f) if f else ''))
        return 0

    if cmd == 'rtti':
        va = int(a[0], 16)
        print('as vtable   :', class_of_vtable(va))
        print('as COL      :', resolve_col(va))
        return 0

    if cmd == 'strings':
        for x in a:
            print(x, repr(string(int(x, 16))))
        return 0

    if cmd == 'calls':
        va = int(a[0], 16)
        f, ins = cfg(va)
        if not f:
            return 1
        for addr, mn, ops, extra, _ in ins:
            if mn == 'call':
                print('%x: %s' % (addr, ops))
        return 0

    if cmd == 'callers':
        t = int(a[0], 16)
        for addr, txt in xref(t):
            if txt.startswith('call'):
                f = func_at(addr)
                print('%x  in fn %s' % (addr, ('%x-%x' % f) if f else '?'))
        return 0

    print('unknown command', cmd)
    return 1


if __name__ == '__main__':
    sys.exit(main())
