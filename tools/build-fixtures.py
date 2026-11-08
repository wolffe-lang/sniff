#!/usr/bin/env python3
"""Build the corpus twice at fixed paths; never normalize binary comparisons."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def run(command, env):
    print('BUILD ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=ROOT, env=env, check=True, timeout=180)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wolf', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--compilers', nargs='+', default=['clang'])
    args = p.parse_args()
    args.wolf = args.wolf.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH='1700000000')
    mac = platform.system() == 'Darwin'
    rows = []
    versions = {'wolf': subprocess.check_output([str(args.wolf), '--version'], text=True).strip()}
    for cc in args.compilers:
        versions[cc] = subprocess.check_output([cc, '--version'], text=True).strip()
        if cc == 'gcc' and 'clang' in versions[cc].lower():
            raise ValueError('gcc is a clang alias, not a GCC measurement')
    cases = [(s, 'wolf', 'debug') for s in sorted((ROOT / 'fixtures/wolf').glob('*/main.lu'))]
    cases += [(s, cc, opt) for s in sorted((ROOT / 'fixtures/c').glob('*/main.c'))
              for cc in args.compilers for opt in ('O0', 'O2')]
    for source, producer, opt in cases:
        ident = source.parent.relative_to(ROOT / 'fixtures').as_posix() + '/' + producer + '-' + opt
        directory = args.out / ident
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / 'prog'
        takes = []
        commands = []
        for take in range(2):
            for old in directory.iterdir():
                if old.is_dir(): shutil.rmtree(old)
                else: old.unlink()
            if producer == 'wolf':
                # wolf 0.2.38's default tier emits DWARF with source types; -g adds .debug_frame.
                commands = [[args.wolf, 'build', source, '-g', '--no-cache', '-o', exe]]
            else:
                obj = directory / 'main.o'
                commands = [[producer, '-g', '-gdwarf-5', '-' + opt, '-pthread',
                    '-fdebug-prefix-map=' + str(ROOT) + '=/source',
                    '-ffile-prefix-map=' + str(ROOT) + '=/source', '-c', source, '-o', obj],
                    [producer, '-g', '-pthread', *(['-Wl,-reproducible'] if mac else []), obj, '-o', exe]]
            for command in commands:
                run(command, env)
                if producer != 'wolf' and '-c' in command:
                    # Mach-O's OSO debug-map entries otherwise inherit wall time.
                    os.utime(directory / 'main.o', (1700000000, 1700000000))
            if mac and producer != 'wolf': run(['dsymutil', exe, '-o', str(exe) + '.dSYM'], env)
            run([exe], env)
            files = {str(f.relative_to(directory)): sha(f) for f in sorted(directory.rglob('*')) if f.is_file()}
            if mac and not any('.dSYM/Contents/Resources/DWARF/' in f for f in files):
                raise ValueError('missing dSYM: ' + ident)
            takes.append(files)
        equal = takes[0] == takes[1]
        rows.append({'id': ident, 'producer': producer, 'optimization': opt,
                     'sha256_read_1': takes[0], 'sha256_read_2': takes[1], 'reproducible': equal,
                     'commands': [[str(v).replace(str(args.wolf), '<WOLF>').replace(str(ROOT), '<ROOT>')
                                   .replace(str(args.out), '<OUT>') for v in c] for c in commands]})
        print(('PASS ' if equal else 'FAIL ') + 'fixture-reproducibility ' + ident, flush=True)
    result = {'schema': 1, 'platform': platform.system() + '-' + platform.machine(),
              'versions': versions, 'source_date_epoch': 1700000000,
              'c_object_mtime': 1700000000, 'macho_link_control': '-Wl,-reproducible' if mac else None,
              'wolf_debug_mode': '-g: the default tier\'s DWARF plus .debug_frame',
              'fixtures': rows}
    (args.out / 'builds.json').write_text(json.dumps(result, indent=2) + '\n')
    if not all(row['reproducible'] for row in rows): return 1
    print('PASS corpus fixtures=' + str(len(rows)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
