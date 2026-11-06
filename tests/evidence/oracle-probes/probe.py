#!/usr/bin/env python3
"""Synthetic rendering observations from the pinned macOS oracle binary.

Each probe is a minimal MH_DSYM-shaped Mach-O 64 (SDK mach-o/loader.h
declarations) whose __DWARF sections hold hand-encoded DWARF (DWARF 5
chapter 7). The oracle runs only as a binary; its complete output and exit
status are recorded beside the input bytes. Nothing is inferred about an
implementation: each record is what the binary printed for those bytes.

probe.py OUT_DIR NAME...   (names from PROBES below; 'all' runs every probe)
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        if value:
            out.append(byte | 128)
        else:
            out.append(byte)
            return bytes(out)


def sleb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        if (value == 0 and not byte & 64) or (value == -1 and byte & 64):
            out.append(byte)
            return bytes(out)
        out.append(byte | 128)


def macho(sections):
    """sections: list of (name, bytes) placed in one __DWARF segment."""
    count = len(sections)
    command_size = 72 + 80 * count
    offset = 32 + command_size
    payload = b''.join(data for _, data in sections)
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 10, 1, command_size, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, command_size, b'__DWARF', 0,
                          len(payload), offset, len(payload), 0, 0, count, 0)
    table = b''
    delta = 0
    for name, data in sections:
        table += struct.pack('<16s16sQQ8I', name.encode(), b'__DWARF', delta, len(data),
                             offset + delta, 0, 0, 0, 0, 0, 0, 0)
        delta += len(data)
    return header + segment + table + payload


def unit4(dies, address_size=8):
    body = struct.pack('<HIB', 4, 0, address_size) + dies
    return struct.pack('<I', len(body)) + body


def abbrev(entries):
    """entries: (code, tag, children, [(attribute, form[, implicit])])."""
    out = b''
    for code, tag, children, attrs in entries:
        out += uleb(code) + uleb(tag) + bytes([1 if children else 0])
        for spec in attrs:
            out += uleb(spec[0]) + uleb(spec[1])
            if spec[1] == 0x21:
                out += sleb(spec[2])
        out += b'\0\0'
    return out + b'\0'


def probe_names():
    # Unknown tag/attribute codes and a reserved standard attribute, each with
    # a known form, plus a string exercising every escaping class.
    ab = abbrev([
        (1, 0x11, True, [(0x03, 0x08)]),
        (2, 0x4090, False, [(0x3fff, 0x0b), (0x07, 0x0b), (0x03, 0x08)]),
        (3, 0x3a, False, [(0x2fff, 0x0b)]),
    ])
    text = b'a\tb"c\\d\x01e\xc3\xa9f\x7fg\nh\x1b'
    dies = b'\x01cu\0' + b'\x02\x05\x06' + text + b'\0' + b'\x03\x07' + b'\0'
    return [('__debug_abbrev', ab), ('__debug_info', unit4(dies))], ['--debug-abbrev', '--debug-info']


PROBES = {'names': probe_names}


def run(out, name):
    sections, modes = PROBES[name]()
    data = macho(sections)
    path = out / (name + '.macho')
    path.write_bytes(data)
    tool = subprocess.check_output(['xcrun', '--find', 'llvm-dwarfdump'], text=True).strip()
    version = subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
    if version != 'Apple LLVM version 21.0.0':
        raise SystemExit('FAIL probe-oracle-version ' + version)
    record = {'schema': 1, 'probe': name, 'oracle': version,
              'oracle_sha256': hashlib.sha256(Path(tool).read_bytes()).hexdigest(),
              'input_sha256': hashlib.sha256(data).hexdigest(), 'input_hex': data.hex(), 'runs': []}
    for mode in modes:
        r = subprocess.run([tool, mode, path.name], cwd=out, capture_output=True, timeout=60)
        record['runs'].append({'mode': mode, 'exit_code': r.returncode,
                               'stdout': r.stdout.decode('latin-1'), 'stderr': r.stderr.decode('latin-1')})
        print('OBSERVATION %s %s exit=%d' % (name, mode, r.returncode))
        sys.stdout.write(r.stdout.decode('latin-1'))
    (out / (name + '.json')).write_text(json.dumps(record, indent=1) + '\n')


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    names = sys.argv[2:]
    if names == ['all']:
        names = sorted(PROBES)
    for name in names:
        run(out, name)


if __name__ == '__main__':
    main()
