#!/usr/bin/env python3
"""Hostile inputs through the whole `sniff dump` command.

Deterministic mutants of recorded fixtures (truncations everywhere, and
corrupted length/offset fields at the start of every debug and unwind
section) run through every mode. Each run must either succeed or refuse by
name: exit 0, or exit 1 with one `error: <row>` line. A trap, a signal, any
other status or an unbounded run is a FAIL. Oversized input is refused before
it is read.
"""
import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

MODES = ['debug-info', 'debug-abbrev', 'debug-line', 'debug-addr', 'debug-str-offsets',
         'debug-ranges', 'debug-rnglists', 'debug-loc', 'debug-loclists', 'eh-frame',
         'debug-frame', 'symbols']
REFUSAL = re.compile(rb'^error: [a-z0-9_]+(: .*)?\n?$')


def sections(data):
    """(offset, size) of every named debug/unwind section, ELF64 or Mach-O 64."""
    out = []
    if data[:4] == b'\x7fELF':
        shoff, = struct.unpack_from('<Q', data, 40)
        shnum, shstr = struct.unpack_from('<HH', data, 60)
        heads = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * i) for i in range(shnum)]
        names = heads[shstr][4]
        for h in heads:
            name = data[names + h[0]:data.index(b'\0', names + h[0])]
            if name.startswith((b'.debug_', b'.eh_frame', b'.symtab', b'.strtab', b'.gnu.version')) and h[1] != 8:
                out.append((h[4], h[5]))
        return out
    count, = struct.unpack_from('<I', data, 16)
    at = 32
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            nsects, = struct.unpack_from('<I', data, at + 64)
            for k in range(nsects):
                s = at + 72 + 80 * k
                name = data[s:s + 16].rstrip(b'\0')
                _, sz, off = struct.unpack_from('<QQI', data, s + 32)
                if (name.startswith((b'__debug_', b'__eh_frame')) and off):
                    out.append((off, sz))
        at += size
    return out


def mutants(data):
    n = len(data)
    for cut in sorted({1, 4, 16, 63, 64, 512, n // 4, n // 2, (3 * n) // 4, n - 1}):
        if 0 < cut < n:
            yield 'truncate-%d' % cut, data[:cut]
    for off, size in sections(data):
        for name, cut in (('mid', off + size // 2), ('head', off + 3)):
            if 0 < cut < n:
                yield 'truncate-%s-%x' % (name, off), data[:cut]
        for delta, value in ((0, b'\xff\xff\xff\x7f'), (0, b'\xf0\xff\xff\xff'), (4, b'\x09\x00'),
                             (8, b'\xff\xff\xff\xff'), (size // 2, b'\xff' * 8)):
            at = off + delta
            if at + len(value) <= n and delta < max(size, 1):
                m = bytearray(data)
                m[at:at + len(value)] = value
                yield 'patch-%x-%d' % (off, delta), bytes(m)


def run(sniff, mode, path, timeout):
    try:
        r = subprocess.run([str(sniff), 'dump', '--' + mode, str(path)], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 'timeout', b''
    return r.returncode, r.stderr


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True, type=Path)
    p.add_argument('--seed', action='append', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--timeout', type=int, default=60)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    failed = total = refused = 0
    for seed in args.seed:
        data = seed.read_bytes()
        label = seed.parent.name + '-' + seed.name
        for name, body in mutants(data):
            path = args.out / ('%s-%s' % (label, name))
            path.write_bytes(body)
            for mode in MODES:
                total += 1
                code, err = run(args.sniff, mode, path, args.timeout)
                if code == 0:
                    continue
                if code == 1 and REFUSAL.fullmatch(err):
                    refused += 1
                    continue
                failed += 1
                print('FAIL hostile-run %s %s exit=%s %r' % (path.name, mode, code, err[-200:]))
            path.unlink()
    big = args.out / 'oversized'
    with open(big, 'wb') as f:
        f.truncate(67108865)
    code, err = run(args.sniff, 'debug-info', big, args.timeout)
    big.unlink()
    total += 1
    if code != 1 or b'resource_limit' not in err:
        failed += 1
        print('FAIL hostile-oversized exit=%s %r' % (code, err))
    if failed:
        print('FAIL hostile-inputs failed=%d runs=%d' % (failed, total))
        return 1
    print('PASS hostile-inputs runs=%d refused=%d succeeded=%d' % (total, refused, total - refused))
    return 0


if __name__ == '__main__':
    sys.exit(main())
