#!/usr/bin/env python3
"""Synthetic vendor encoding observations from the pinned binary, not its source.

Mach-O fields follow Apple's named SDK interface declarations. DWARF fields
follow DWARF5 7.5. The initial discovery exhausts the user opcode byte range;
control opcodes are selected from the resulting recorded binary output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def uleb(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def fixture(expressions):
    # CU with named child variables, each having one bounded exprloc.
    abbrev = bytes([1, 0x11, 1, 3, 8, 0, 0, 2, 0x34, 0, 3, 8, 2, 0x18, 0, 0, 0])
    dies = b'\x01synthetic-expression-observation\0'
    for name, expression in expressions:
        dies += b'\x02' + name.encode('ascii') + b'\0' + uleb(len(expression)) + expression
    dies += b'\0'
    unit = struct.pack('<HIB', 4, 0, 8) + dies
    info = struct.pack('<I', len(unit)) + unit
    payload = abbrev + info
    command_size = 72 + 2 * 80
    offset = 32 + command_size
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 10, 1, command_size, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, command_size, b'__DWARF', 0,
                          len(payload), offset, len(payload), 0, 0, 2, 0)
    sections = b''
    delta = 0
    for name, contents in [(b'__debug_abbrev', abbrev), (b'__debug_info', info)]:
        sections += struct.pack('<16s16sQQ8I', name, b'__DWARF', delta, len(contents),
                                offset + delta, 0, 0, 0, 0, 0, 0, 0)
        delta += len(contents)
    return header + segment + sections + payload


def observe(name, expressions, tool, output):
    data = fixture(expressions)
    path = output / (name + '.macho')
    path.write_bytes(data)
    command = [str(tool), '--debug-info', str(path)]
    result = subprocess.run(command, capture_output=True, timeout=60)
    (output / (name + '.stdout.txt')).write_bytes(result.stdout)
    (output / (name + '.stderr.txt')).write_bytes(result.stderr)
    record = {'schema': 1, 'purpose': 'Synthetic binary encoding observation; no process evaluation',
              'command': command, 'exit_code': result.returncode,
              'input_sha256': hashlib.sha256(data).hexdigest(), 'input_hex': data.hex(),
              'expressions': [{'name': label, 'hex': value.hex()} for label, value in expressions],
              'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
              'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
    (output / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print('OBSERVATION ' + name + ' exit=' + str(result.returncode), flush=True)
    return result.stdout.decode('utf-8', 'strict')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['discover', 'controls'])
    parser.add_argument('--entry-opcode', type=lambda value: int(value, 0))
    parser.add_argument('--tls-opcode', type=lambda value: int(value, 0))
    args = parser.parse_args()
    tool = Path(subprocess.check_output(['xcrun', '--find', 'llvm-dwarfdump'], text=True).strip())
    version = subprocess.run([str(tool), '--version'], capture_output=True, check=True)
    if version.stdout.decode().splitlines()[0] != 'Apple LLVM version 21.0.0':
        raise SystemExit('FAIL expression-oracle-version-mismatch')
    output = Path('target/expression-probes')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'oracle-version.stdout.txt').write_bytes(version.stdout)
    (output / 'oracle-version.stderr.txt').write_bytes(version.stderr)
    (output / 'oracle-identity.json').write_text(json.dumps({
        'command': [str(tool), '--version'], 'exit_code': version.returncode,
        'sha256_read_1': hashlib.sha256(tool.read_bytes()).hexdigest(),
        'sha256_read_2': hashlib.sha256(tool.read_bytes()).hexdigest()}, indent=2) + '\n')
    if args.phase == 'discover':
        expressions = [('vendor-' + format(opcode, '02x'), bytes([opcode, 0, 0x50, 0x9f]))
                       for opcode in range(0xe0, 0x100)]
        observe('vendor-discovery', expressions, tool, output)
    else:
        assert args.entry_opcode is not None and args.tls_opcode is not None
        entry, tls = args.entry_opcode, args.tls_opcode
        expressions = [
            ('tls-followed-by-known-ops', bytes([0x30, tls, 0x31, 0x9f])),
            ('entry-one-byte-register', bytes([entry, 1, 0x50, 0x9f])),
            ('entry-two-byte-uleb-length', bytes([entry, 0x80, 1]) + bytes([0x96]) * 127 + bytes([0x50, 0x9f])),
            ('entry-nested', bytes([entry, 3, 0xa3, 1, 0x51, 0x9f])),
            ('entry-truncated-block', bytes([entry, 2, 0x50])),
        ]
        observe('vendor-layout-controls', expressions, tool, output)


if __name__ == '__main__':
    main()
