#!/usr/bin/env python3
"""Build the S2 session fixtures at fixed absolute paths, recording digests.

On macOS arm64 (S3) only clang builds: each C program gets a dSYM from dsymutil
and is ad-hoc signed with get-task-allow, and so is each wolf program (its dSYM
is paired by UUID, which signing leaves alone).

Session fixtures are separate from the S1 reader corpus (fixtures/c, wolf):
the dump matrix and census never see them. C programs are built by each
named compiler at -O0 with DWARF 5 and no prefix maps, so a debugger finds
the sources where the line table says they are. A file named plain*.c is
compiled without -g: a callee with no line information. c/exits also gets a
stripped link. Wolf programs (the session tree's and the S1 corpus's) are
built by the pinned wolf with -g: the default tier's DWARF (source types
since 0.2.38) plus a non-allocated .debug_frame.

C programs of the S1 corpus named in CORPUS_C are session fixtures too (the
`list` rows run C recursion). Each one named in GONE is built a second time,
as c/NAME-gone, from a copy of its sources inside the build directory that the
build then removes: its line table names a source file that cannot be read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STRIPPED = ('exits',)
CORPUS_C = ('recursion',)
GONE = ('recursion',)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env, cwd):
    print('BUILD ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True, timeout=180)


def mac_sign(exe, env):
    """Ad-hoc sign with get-task-allow so the debugger can get the task port."""
    run(['codesign', '--force', '--sign', '-', '--entitlements', ROOT / 'tests/get-task-allow.plist', exe], env, ROOT)


def c_build(cc, source_dir, out, env, strip, static=False):
    out.mkdir(parents=True, exist_ok=True)
    objects = []
    for source in sorted(source_dir.glob('*.c')):
        obj = out / (source.stem + '.o')
        debug = [] if source.name.startswith('plain') else ['-g', '-gdwarf-5']
        # the arm64 trap instruction for the signals program (x86-64 keeps the source's int3)
        trap = ['-DTRAP_INSN="brk #0x1"'] if platform.system() == 'Darwin' else []
        # PAX loads only static ET_EXEC files (no PT_INTERP, no ET_DYN): -fno-pie objects
        run([cc, *debug, *trap, '-O0', *(['-fno-pie'] if static else []), '-c', source, '-o', obj], env, source_dir)
        objects.append(obj)
    exe = out / 'prog'
    mac = platform.system() == 'Darwin'
    run([cc, *(['-s'] if strip and not mac else []), *(['-static', '-no-pie'] if static else []), *objects, '-o', exe], env, source_dir)
    if mac:
        if not strip:
            run(['dsymutil', exe, '-o', str(exe) + '.dSYM'], env, source_dir)
        else:
            run(['strip', exe], env, source_dir)
        mac_sign(exe, env)
    return exe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wolf', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--compilers', nargs='+', default=['gcc', 'clang'])
    p.add_argument('--static', action='store_true',
                   help='static ET_EXEC builds for PAX (C: -static -no-pie; wolf: a static cc in front of the link)')
    args = p.parse_args()
    mac = platform.system() == 'Darwin'
    if platform.system() not in ('Linux', 'Darwin'):
        raise SystemExit('FAIL session-fixtures: session fixtures build on Linux x86-64 and macOS arm64')
    if mac:
        args.compilers = ['clang']
    args.wolf = args.wolf.resolve()
    out = args.out.resolve()
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    env = dict(os.environ, LC_ALL='C', TZ='UTC')
    if args.static:
        if mac:
            raise SystemExit('FAIL session-fixtures: --static is for the Linux build that PAX runs')
        # wolf has no --static: it links through the first cc on PATH, so put a static cc there
        shim = out.parent / (out.name + '-static-cc')
        shim.mkdir(parents=True, exist_ok=True)
        real = shutil.which('cc')
        (shim / 'cc').write_text('#!/bin/sh\nexec %s -static "$@"\n' % real)
        (shim / 'cc').chmod(0o755)
        wolf_env = dict(env, PATH=str(shim) + os.pathsep + env['PATH'])
    else:
        wolf_env = env
    env.pop('SOURCE_DATE_EPOCH', None)
    versions = {'wolf': subprocess.check_output([str(args.wolf), '--version'], text=True).strip()}
    rows = []
    for cc in args.compilers:
        versions[cc] = subprocess.check_output([cc, '--version'], text=True).splitlines()[0]
        for source_dir in sorted(d for d in (ROOT / 'fixtures/session/c').iterdir() if d.is_dir()):
            for strip in (False, True) if source_dir.name in STRIPPED else (False,):
                ident = 'c/' + source_dir.name + '/' + cc + '-O0' + ('-stripped' if strip else '')
                exe = c_build(cc, source_dir, out / ident, env, strip, args.static)
                rows.append({'id': ident, 'producer': cc, 'binary': str(exe.relative_to(out)), 'sha256': sha(exe)})
        for name in CORPUS_C:
            ident = 'c/' + name + '/' + cc + '-O0'
            exe = c_build(cc, ROOT / 'fixtures/c' / name, out / ident, env, False, args.static)
            rows.append({'id': ident, 'producer': cc, 'binary': str(exe.relative_to(out)), 'sha256': sha(exe)})
        for name in GONE:
            ident = 'c/' + name + '-gone/' + cc + '-O0'
            copy = out / ident / 'src'
            copy.mkdir(parents=True)
            for source in sorted((ROOT / 'fixtures/c' / name).glob('*.c')):
                shutil.copy(source, copy / source.name)
            exe = c_build(cc, copy, out / ident, env, False, args.static)
            shutil.rmtree(copy)
            rows.append({'id': ident, 'producer': cc, 'binary': str(exe.relative_to(out)), 'sha256': sha(exe),
                         'source_removed': str(copy)})
    wolf_sources = sorted((ROOT / 'fixtures/session/wolf').glob('*/main.lu'))
    wolf_sources += sorted((ROOT / 'fixtures/wolf').glob('*/main.lu'))
    for source in wolf_sources:
        ident = 'wolf/' + source.parent.name + '/wolf-debug'
        directory = out / ident
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / 'prog'
        run([args.wolf, 'build', source, '-g', '--no-cache', '-o', exe], wolf_env, source.parent)
        if mac:
            mac_sign(exe, env)
        rows.append({'id': ident, 'producer': 'wolf', 'source': str(source.relative_to(ROOT)),
                     'binary': str(exe.relative_to(out)), 'sha256': sha(exe)})
    (out / 'builds.json').write_text(json.dumps({'schema': 1, 'versions': versions, 'fixtures': rows}, indent=2) + '\n')
    print('PASS session-fixtures count=' + str(len(rows)))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        print('FAIL session-fixtures ' + str(error))
        raise SystemExit(1)
