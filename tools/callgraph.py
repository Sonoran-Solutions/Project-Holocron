#!/usr/bin/env python3
"""Report the direct callees of every function in a VA range.

Uses the .pdata-derived xref index, so call sites are only ever found at true
instruction boundaries (a flat sweep of .text desynchronises and loses calls).

Usage: callgraph.py <start_va> <end_va>
"""
import importlib.util
import sys

TKPATH = '/home/dq/project-holocron/tools/retail-re-toolkit.py'


def load():
    spec = importlib.util.spec_from_file_location('tk', TKPATH)
    tk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tk)
    return tk


def main():
    tk = load()
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    idx = tk._load_index()
    fns = tk._runtime_function_table()
    # invert: instruction address -> list of (kind, target)
    by_addr = {}
    for (kind, tgt), addrs in idx.items():
        for a in addrs:
            by_addr.setdefault(a, []).append((kind, tgt))
    for fstart in sorted(fns):
        if not (start <= fstart < end):
            continue
        fend = fns[fstart]
        calls = []
        for a, lst in by_addr.items():
            if fstart <= a < fend:
                for kind, tgt in lst:
                    if kind == 1:
                        calls.append((a, tgt))
        calls.sort()
        print('fn %x - %x' % (fstart, fend))
        for a, t in calls:
            print('    %x -> %x' % (a, t))
    return 0


if __name__ == '__main__':
    sys.exit(main())
