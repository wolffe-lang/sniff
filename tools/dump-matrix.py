#!/usr/bin/env python3
"""Compare every `sniff dump` mode with its pinned oracle, full bytes.

One row per (mode, fixture): the oracle and sniff run on the same artifact
path, and the row passes only when stdout bytes and exit status are equal.
No address, path or whitespace normalisation. Large outputs stream to files
and compare by SHA-256; a failing row names its first differing line.

Linux: llvm-dwarfdump-18 and readelf, pinned by version and SHA-256.
macOS: the SDK's llvm-dwarfdump (Apple LLVM 21.0.0) and llvm-nm, pinned.

`notes` (Linux): `sniff dump --notes` against readelf with the [readelf] notes_arguments of sniff-oracle.toml,
over every core in each --cores directory (the cores tools/session.py wrote in this take: NAME.core; the
truncated copies hostile rows read are not dump rows). A core's NT_X86_XSTATE follows the processor that wrote
it, so no dump golden is stored: both run on the same core in the same take.

NT_FILE: the pinned readelf declines to decode gcore's mapped-files note, printing NT_DECLINED after the type.
Where it declines, that one phrase is taken off readelf's line before the comparison (sniff prints the type
line alone), the row says so (nt-file=declined), and the table is held instead by gdb's `info proc mappings`
over the same core (the core-*-mappings session rows). Where readelf decodes the note, its text is compared as
it is: sniff does not decode it, so the row is red by name rather than falling back to the declined form.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DWARF_MODES = ['debug-info', 'debug-abbrev', 'debug-line', 'debug-addr', 'debug-str-offsets',
               'debug-ranges', 'debug-rnglists', 'debug-loc', 'debug-loclists']
FRAME_MODES = ['eh-frame', 'debug-frame']
ALL_MODES = DWARF_MODES + FRAME_MODES + ['symbols']
CORE_MODES = ['notes']
NT_FILE_LINE = b'\tNT_FILE (mapped files)\t'
NT_DECLINED = b'    Cannot decode 64-bit note in 32-bit build'


def nt_file_rule(text):
    """readelf's notes text with its declined NT_FILE phrase taken off, and what readelf did with NT_FILE:
    'declined' (every NT_FILE line ends in the phrase), 'decoded' (one has anything else after its type) or 'none'."""
    out, seen = [], set()
    for line in text.split(b'\n'):
        if NT_FILE_LINE in line:
            head, _, tail = line.partition(NT_FILE_LINE)
            if tail == NT_DECLINED:
                seen.add('declined')
                line = head + NT_FILE_LINE
            else:
                seen.add('decoded')
        out.append(line)
    state = 'decoded' if 'decoded' in seen else 'declined' if seen else 'none'
    return b'\n'.join(out), state


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def pinned(name, platform):
    pins = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())
    if platform == 'linux':
        if name == 'dwarfdump':
            tool = shutil.which('llvm-dwarfdump-18')
            pin = pins['llvm_dwarfdump']
        else:
            tool = shutil.which(pins['readelf']['command'])
            pin = pins['readelf']
        if not tool or sha256(tool) != pin['sha256']:
            raise ValueError('oracle-pin-mismatch ' + name)
        return [tool]
    tool = subprocess.check_output(['xcrun', '--find', 'llvm-dwarfdump' if name == 'dwarfdump'
                                    else pins['llvm_nm_macos']['command']], text=True).strip()
    version = subprocess.run([tool, '--version'], capture_output=True, text=True).stdout
    want = 'Apple LLVM version 21.0.0'
    if name != 'dwarfdump':
        if sha256(tool) != pins['llvm_nm_macos']['sha256']:
            raise ValueError('oracle-pin-mismatch symbols')
        want = pins['llvm_nm_macos']['version_line']
    if want not in version:
        raise ValueError('oracle-version-mismatch ' + name)
    return [tool]


def oracle_command(mode, platform, tools):
    pins = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())
    if mode == 'symbols':
        key = 'readelf' if platform == 'linux' else 'llvm_nm_macos'
        return tools['symbols'] + pins[key]['arguments']
    if mode == 'notes':
        return tools['symbols'] + pins['readelf']['notes_arguments']
    return tools['dwarfdump'] + ['--' + mode]


def artifact(fixture, mode, platform):
    if platform == 'macos' and mode in DWARF_MODES:
        return fixture / 'prog.dSYM/Contents/Resources/DWARF/prog'
    return fixture / 'prog'


def core_rows(dirs):
    """id -> core for every NAME.core in the directories: cores/SET/NAME, the set from the directory's name."""
    out = {}
    for d in dirs:
        for core in sorted(d.glob('*.core')):
            if core.name.count('.') == 1:
                out['cores/%s/%s' % (d.name, core.stem)] = core.resolve()
    return out


def first_diff(a, b):
    with open(a, 'rb') as x, open(b, 'rb') as y:
        number = 0
        while True:
            number += 1
            lx, ly = x.readline(), y.readline()
            if lx != ly:
                return number, lx[:160], ly[:160]
            if not lx:
                return None


def run(command, out):
    with open(out, 'wb') as f:
        try:
            result = subprocess.run(command, stdout=f, stderr=subprocess.PIPE, timeout=1800)
        except FileNotFoundError:
            return 127, b'missing executable ' + command[0].encode()
    return result.returncode, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sniff', required=True, type=Path)
    parser.add_argument('--platform', required=True, choices=['linux', 'macos'])
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--modes', default=','.join(ALL_MODES))
    parser.add_argument('--out', type=Path, default=ROOT / 'target/dump-matrix')
    parser.add_argument('--cores', type=Path, action='append', default=[],
                        help='a directory of core files for the notes rows (Linux; repeatable)')
    args = parser.parse_args()
    modes = args.modes.split(',')
    if any(mode not in ALL_MODES + CORE_MODES for mode in modes):
        raise ValueError('unknown-mode ' + args.modes)
    if ('notes' in modes) != bool(args.cores) or (args.cores and args.platform != 'linux'):
        raise ValueError('notes-needs-cores: the notes rows run on Linux over --cores, and only they take --cores')
    tools = {'dwarfdump': pinned('dwarfdump', args.platform),
             'symbols': pinned('symbols', args.platform)}
    fixture_modes = [m for m in modes if m not in CORE_MODES]
    ids = []
    if fixture_modes:
        builds = json.loads((args.fixtures / 'builds.json').read_text())
        ids = sorted(f['id'] for f in builds['fixtures'])
    cores = core_rows(args.cores)
    if args.cores and not cores:
        raise ValueError('no-cores in ' + ', '.join(map(str, args.cores)))
    rows = failed = 0
    for mode in modes:
        for fid in (sorted(cores) if mode in CORE_MODES else ids):
            rows += 1
            target = cores[fid] if mode in CORE_MODES else artifact(args.fixtures / fid, mode, args.platform).resolve()
            work = args.out / fid
            work.mkdir(parents=True, exist_ok=True)
            want, got = work / (mode + '.oracle'), work / (mode + '.sniff')
            want_rc, _ = run(oracle_command(mode, args.platform, tools) + [str(target)], want)
            got_rc, got_err = run([str(args.sniff), 'dump', '--' + mode, str(target)], got)
            row = 'dump-%s %s' % (mode, fid)
            note = ''
            if mode == 'notes':
                text, state = nt_file_rule(want.read_bytes())
                want.write_bytes(text)
                note = ' nt-file=' + state
                if state == 'decoded':
                    row += ' nt-file-decoded-by-readelf'
            if want_rc == got_rc and sha256(want) == sha256(got):
                print('PASS %s bytes=%d exit=%d%s' % (row, want.stat().st_size, want_rc, note))
                want.unlink()
                got.unlink()
                continue
            failed += 1
            diff = first_diff(want, got)
            where = 'line=%d' % diff[0] if diff else 'stdout-equal'
            print('FAIL %s exit=%d/%d %s %s' % (row, got_rc, want_rc, where,
                  got_err.decode(errors='replace').strip().splitlines()[-1:]))
    if failed:
        print('FAIL dump-matrix failed=%d rows=%d' % (failed, rows))
        return 1
    print('PASS dump-matrix rows=%d platform=%s' % (rows, args.platform))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL dump-matrix ' + str(error))
        sys.exit(1)
