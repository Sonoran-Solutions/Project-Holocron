#!/usr/bin/env python3
"""Name the imported function behind a retail swtor.exe IAT slot.

Version 1 of this file wrongly dereferenced the on-disk contents of the slot as
a 64-bit pointer.  The IAT here is filled by the loader, so the on-disk dword is
a stale RVA (e.g. the mm_alloc slot at 0x141369df8 holds 0x1a86414, which is an
RVA into the allocator name table -- not a pointer).  Resolve through the import
descriptors instead.

Usage: resolve-indirect.py <iat_slot_va> [<iat_slot_va> ...]
"""
import importlib.util
import struct
import sys

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'
IMAGE = '/home/dq/project-holocron/.local-test/client-v1/game/swtor/retailclient/swtor.exe'
BASE = 0x140000000

import pefile

_pe = pefile.PE(IMAGE, fast_load=True)
_raw = _pe.__data__


def off(va):
    return _pe.get_offset_from_rva(va - BASE)


def q(va):
    o = off(va)
    return struct.unpack('<Q', _raw[o:o + 8])[0]


def d(va):
    o = off(va)
    return struct.unpack('<I', _raw[o:o + 4])[0]


def s(va, n=96):
    o = off(va)
    b = _raw[o:o + n].split(b'\0')[0]
    return b.decode('latin1')


def _imports():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk.import_map()


def describe(slot):
    """If `slot` is an IAT slot, name the imported function."""
    ent = _imports().get(slot)
    print('%x -> %s' % (slot, ent if ent else '(not an IAT slot)'))


if __name__ == '__main__':
    for a in sys.argv[1:]:
        describe(int(a, 16))
