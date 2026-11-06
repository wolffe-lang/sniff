#!/usr/bin/env python3
"""S2 live session rows: sniff against recorded gdb transcripts.

A row is a program from the session fixtures and a command script. `capture`
runs the pinned gdb on every row and stores its stdout, stderr and exit status
as the golden. `check` runs sniff on every row and compares with the golden
after the named normalisations. `verify` (no process, any host) checks that
rows and goldens agree. A row that did not run is reported as SKIP and is
never a pass.

Normalisations, each named in every PASS/FAIL line only when it fired:
  pid     the N of '(process N)' and 'child process N'
  banner  gdb's two thread_db lines are dropped from the golden
  tty     (tty rows) carriage returns and the prompt text
  wrap80  (tty rows) gdb's 80-column wrap of a long frame line ("\n    at ")
Terminal rows run both debuggers in a pseudo-terminal with echo off and send
one command per prompt, as R-sn02-1 specifies.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / 'tests/session-rows.json'
GOLD = ROOT / 'tests/evidence/linux-s2'
SCRIPTS = 'target/s2'
ENV_BASE = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}


def load_rows(only=None):
    rows = json.loads(ROWS.read_text())['rows']
    if only:
        rows = [r for r in rows if re.search(only, r['name'])]
    names = [r['name'] for r in rows]
    if len(set(names)) != len(names):
        raise SystemExit('FAIL session-rows: duplicate row names')
    return rows


def normalize(text, fired):
    out = []
    for line in text.splitlines(keepends=True):
        if line.startswith('[Thread debugging using libthread_db enabled]') or \
           line.startswith('Using host libthread_db library'):
            fired.add('banner')
            continue
        n = re.sub(r'(\[Inferior \d+ \(process )\d+(\))', r'\1<PID>\2', line)
        n = re.sub(r'(Detaching after fork from child process )\d+', r'\1<PID>', n)
        if n != line:
            fired.add('pid')
        out.append(n)
    return ''.join(out)


def run_pty(argv, cmds, prompt, work, timeout=60):
    import pty
    master, slave = pty.openpty()
    attr = termios.tcgetattr(slave)
    attr[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attr)
    env = dict(ENV_BASE)
    proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=env, cwd=work)
    os.close(slave)
    buf = b''
    tag = prompt.encode()

    def read_until_prompt():
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                if buf.endswith(tag):
                    return

    read_until_prompt()
    for c in cmds:
        os.write(master, (c + '\n').encode())
        read_until_prompt()
    os.write(master, b'quit\n')
    time.sleep(0.3)
    try:
        while True:
            ready, _, _ = select.select([master], [], [], 0.3)
            if not ready:
                break
            data = os.read(master, 4096)
            if not data:
                break
            buf += data
    except OSError:
        pass
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master)
    return buf.decode(errors='replace'), '', proc.returncode


def normalize_tty(text, fired):
    t = text.replace('\r\n', '\n').replace('\r', '')
    if t != text:
        fired.add('tty')
    for prompt in ('(gdb) ', '(sniff) '):
        t = t.replace(prompt, '')
    t = re.sub(r'\n    at ', ' at ', t)
    if '\n    at ' in text.replace('\r\n', '\n'):
        fired.add('wrap80')
    return t


def tty_argv(tool, row, prog, gdb):
    if gdb:
        return [tool, '-nx', '-q', '-iex', 'set confirm off', '-iex', 'set pagination off', '--args', prog] + row.get('args', [])
    return [tool, prog] + (['--args'] + row['args'] if row.get('args') else [])


def write_script(row, work):
    d = Path(work) / SCRIPTS
    d.mkdir(parents=True, exist_ok=True)
    path = d / (row['name'] + '.cmd')
    path.write_text('\n'.join(row['script']) + '\n')
    return '/work/' + SCRIPTS + '/' + path.name if str(work) == '/work' else str(path)


def run_tool(argv, work, timeout):
    env = dict(ENV_BASE)
    p = subprocess.run(argv, cwd=work, env=env, capture_output=True, timeout=timeout, text=True, errors='replace')
    return p.stdout, p.stderr, p.returncode


def gdb_argv(gdb, row, script, prog):
    return [gdb, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-x', script, '--args', prog] + row.get('args', [])


def sniff_argv(sniff, row, script, prog):
    return [sniff, '-batch', '-x', script, prog] + (['--args'] + row['args'] if row.get('args') else [])


def prog_path(fixtures, row):
    return str(Path(fixtures) / row['prog'])


def golden_paths(row):
    return [GOLD / (row['name'] + ext) for ext in ('.out', '.err', '.rc')]


def cmd_capture(a):
    work = a.work
    GOLD.mkdir(parents=True, exist_ok=True)
    for row in load_rows(a.only):
        if row.get('tty'):
            out, err, rc = run_pty(tty_argv(a.gdb, row, prog_path(a.fixtures, row), True), row['script'], '(gdb) ', work)
            fired = set()
            o = normalize(normalize_tty(out, fired), fired)
            e = ''
            rc = 0
        else:
            script = write_script(row, work)
            out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row)), work, 120)
            fired = set()
            o = normalize(out, fired)
            e = normalize(err, fired)
        for path, text in zip(golden_paths(row), (o, e, str(rc) + '\n')):
            path.write_text(text)
        print('CAPTURE ' + row['name'] + ' rc=' + str(rc))
    return 0


def first_diff(a, b):
    al, bl = a.splitlines(), b.splitlines()
    for i in range(max(len(al), len(bl))):
        x = al[i] if i < len(al) else '<end>'
        y = bl[i] if i < len(bl) else '<end>'
        if x != y:
            return 'line %d: want %r got %r' % (i + 1, x, y)
    return 'equal'


def cmd_check(a):
    work = a.work
    fails = 0
    ran = 0
    for row in load_rows(a.only):
        gold = golden_paths(row)
        if not all(p.exists() for p in gold):
            print('FAIL %s no-golden' % row['name'])
            fails += 1
            continue
        try:
            if row.get('tty'):
                out, err, rc = run_pty(tty_argv(a.sniff, row, prog_path(a.fixtures, row), False), row['script'], '(sniff) ', work)
                fired = set()
                out = normalize_tty(out, fired)
                rc = 0
            else:
                script = write_script(row, work)
                out, err, rc = run_tool(sniff_argv(a.sniff, row, script, prog_path(a.fixtures, row)), work, row.get('timeout', 120))
        except subprocess.TimeoutExpired:
            print('FAIL %s timeout' % row['name'])
            fails += 1
            continue
        ran += 1
        if not row.get('tty'):
            fired = set()
        o, e = normalize(out, fired), normalize(err, fired)
        want_o, want_e, want_rc = (p.read_text() for p in gold)
        bad = []
        if o != want_o:
            bad.append('stdout ' + first_diff(want_o, o))
        if e != want_e:
            bad.append('stderr ' + first_diff(want_e, e))
        if str(rc) != want_rc.strip():
            bad.append('exit want %s got %s' % (want_rc.strip(), rc))
        if bad:
            print('FAIL %s %s' % (row['name'], '; '.join(bad)))
            fails += 1
        else:
            print('PASS %s%s' % (row['name'], (' [normalised: ' + ','.join(sorted(fired)) + ']') if fired else ''))
    print('SUMMARY ran=%d failed=%d' % (ran, fails))
    return 1 if fails else 0


def cmd_oracle(a):
    """Re-run gdb live and compare with the stored goldens (drift check)."""
    work = a.work
    fails = 0
    for row in load_rows(a.only):
        fired = set()
        if row.get('tty'):
            out, err, rc = run_pty(tty_argv(a.gdb, row, prog_path(a.fixtures, row), True), row['script'], '(gdb) ', work)
            got = (normalize(normalize_tty(out, fired), fired), '', '0\n')
        else:
            script = write_script(row, work)
            out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row)), work, 120)
            got = (normalize(out, fired), normalize(err, fired), str(rc) + '\n')
        want = tuple(p.read_text() for p in golden_paths(row))
        if got != want:
            print('FAIL oracle-drift ' + row['name'])
            fails += 1
        else:
            print('PASS oracle-stable ' + row['name'])
    return 1 if fails else 0


def cmd_verify(a):
    rows = load_rows()
    have = {p.name for p in GOLD.glob('*') if p.is_file()}
    want = {p.name for r in rows for p in golden_paths(r)}
    if want - have:
        print('FAIL session-goldens-missing: ' + ', '.join(sorted(want - have)))
        return 1
    if have - want:
        print('FAIL session-goldens-extra: ' + ', '.join(sorted(have - want)))
        return 1
    print('PASS session-rows rows=%d goldens=%d' % (len(rows), len(want)))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    for name in ('capture', 'check', 'oracle'):
        s = sub.add_parser(name)
        s.add_argument('--work', default='/work')
        s.add_argument('--fixtures', default='/work/target/session-fixtures')
        s.add_argument('--only')
        if name in ('capture', 'oracle'):
            s.add_argument('--gdb', default='gdb')
        if name == 'check':
            s.add_argument('--sniff', default='/work/target/sniff')
    sub.add_parser('verify')
    a = p.parse_args()
    return {'capture': cmd_capture, 'check': cmd_check, 'oracle': cmd_oracle, 'verify': cmd_verify}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
