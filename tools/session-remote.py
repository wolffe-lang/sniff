#!/usr/bin/env python3
"""S8's kernel rows: the pinned gdb and sniff over QEMU's gdbstub on PAX's console kernel, at one processor.

  session-remote.py capture --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --gdb GDB --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py check   --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --sniff SNIFF --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py gdb-check (as check, with --gdb: the goldens hold for this accelerator and this run)
  session-remote.py skip --reason TEXT      one SKIP line a row, and the count, where no kernel image is
  session-remote.py selftest                the normalisation and the script forms, no machine

Rows: tests/remote-rows.json. Goldens: tests/evidence/remote/NAME.out, gdb's transcript under KVM on the record host. A
row with "accel" runs only under that accelerator. A row with "qemu": false runs with no QEMU (the refusals).

Each row is one boot of the console image through PAX's tools/qemu-run with `--gdb PORT` (the processor frozen at reset).
The tool runs on a pty that is its controlling terminal, with its standard error on the same terminal, one script line a
prompt. `@PORT@` in a line is the port. A line `!interrupt N CMD` sends CMD and, if no prompt came in N seconds, writes the
byte 0x03 to the pty, which the terminal turns into SIGINT. qemu-run's pid is recorded; if it is still running 10 s after the
tool ends, SIGTERM goes to that pid, whose trap ends its QEMU.

Normalised by name: the port, the kernel's path, the terminal's line ends and the prompts (tools/session.py's
normalize_tty). QEMU's target description never appears in a golden as text: no row prints it.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import subprocess
import sys
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / 'tests/remote-rows.json'
GOLD = ROOT / 'tests/evidence/remote'
GRACE = 20.0


def load_session():
    spec = importlib.util.spec_from_file_location('session_rows', ROOT / 'tools/session.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def listening(port, limit=60.0):
    end = time.time() + limit
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def script_lines(row, port):
    return [line.replace('@PORT@', str(port)) for line in row['script']]


def run_tty(argv, lines, prompt, env, timeout):
    """The tool on a new pty that is its controlling terminal; returns (text, exit status, how each line ended)."""
    tag = prompt.encode()
    pid, master = pty.fork()
    if pid == 0:
        try:
            attr = termios.tcgetattr(0)
            attr[3] &= ~termios.ECHO
            termios.tcsetattr(0, termios.TCSANOW, attr)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    buf = bytearray()
    ends = []

    def read_for(secs, at_prompt=True):
        mark = len(buf)
        end = time.time() + secs
        while time.time() < end:
            ready, _, _ = select.select([master], [], [], 0.2)
            if not ready:
                continue
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b''
            if not data:
                return 'eof'
            buf.extend(data)
            if at_prompt and bytes(buf[mark:]).endswith(tag):
                return 'prompt'
        return 'time'

    first = read_for(timeout)
    ok = first == 'prompt'
    for line in lines if ok else []:
        wait = None
        cmd = line
        if line.startswith('!interrupt '):
            _, n, cmd = line.split(' ', 2)
            wait = float(n)
        os.write(master, (cmd + '\n').encode())
        if wait is not None:
            how = read_for(wait)
            if how == 'time':
                os.write(master, b'\x03')
                how = 'interrupt:' + read_for(timeout)
        else:
            how = read_for(timeout)
            if how == 'time':
                os.write(master, b'\x03')
                how = 'timeout,interrupt:' + read_for(GRACE)
        ends.append((line, how))
        if not how.endswith('prompt'):
            break
    try:
        os.write(master, b'quit\n')
    except OSError:
        pass
    read_for(GRACE, at_prompt=False)
    status = None
    end = time.time() + GRACE
    while time.time() < end:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.2)
    else:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
    os.close(master)
    return bytes(buf).decode(errors='replace'), os.waitstatus_to_exitcode(status), ends


def normalise(text, port, kernel, sess):
    fired = set()
    t = sess.normalize_tty(text, fired)
    if port:
        t = t.replace('127.0.0.1:%d' % port, '127.0.0.1:PORT')
    t = t.replace(str(kernel), 'KERNEL')
    return t


def tool_argv(a, kernel):
    if a.mode in ('capture', 'gdb-check'):
        # gdb retries a refused TCP connect (Remote Configuration, set tcp auto-retry); sniff never does
        return [a.gdb, '-nx', '-q', '-iex', 'set confirm off', '-iex', 'set pagination off', '-iex', 'set tcp auto-retry off', str(kernel)], '(gdb) '
    return [a.sniff, str(kernel)], '(sniff) '


def run_row(a, row, sess, out):
    kernel = Path(a.kernel).resolve()
    env = dict(sess.ENV_BASE)
    env['HOME'] = str(out / 'home')
    env['SHELL'] = '/bin/sh'
    (out / 'home').mkdir(parents=True, exist_ok=True)
    port = 0
    qr = None
    if row.get('qemu', True):
        port = free_port()
        qenv = dict(os.environ)
        qenv.update({'PAX_QEMU': a.qemu, 'PAX_BUILD': str(out / 'qemu'), 'TMPDIR': str(out / 'tmp'), 'SHELL': '/bin/sh'})
        (out / 'qemu').mkdir(parents=True, exist_ok=True)
        (out / 'tmp').mkdir(parents=True, exist_ok=True)
        qr = subprocess.Popen([str(Path(a.pax) / 'tools/qemu-run'), '--accel', a.accel, '--gdb', str(port), '--timeout', str(row.get('qemu_timeout', 300)),
                               '--serial', str(out / (row['name'] + '.serial')), str(Path(a.image).resolve())],
                              stdout=open(out / (row['name'] + '.qemu-run'), 'w'), stderr=subprocess.STDOUT, env=qenv)
        if not listening(port):
            qr.terminate()
            qr.wait()
            return None, 'qemu-not-listening'
    argv, prompt = tool_argv(a, kernel)
    text, rc, ends = run_tty(argv, script_lines(row, port), prompt, env, row.get('timeout', 120))
    (out / (row['name'] + '.tty')).write_text(text)
    if qr is not None:
        try:
            qr.wait(10)
        except subprocess.TimeoutExpired:
            print('qemu-run %d still running 10 s after row %s: TERM to its recorded pid' % (qr.pid, row['name']))
            qr.terminate()
            qr.wait()
    bad = [line for line, how in ends if not how.endswith('prompt')]
    return normalise(text, port, kernel, sess), ('no prompt after: ' + bad[0]) if bad else ''


def first_diff(want, got):
    w, g = want.splitlines(), got.splitlines()
    for i in range(max(len(w), len(g))):
        a = w[i] if i < len(w) else '<end>'
        b = g[i] if i < len(g) else '<end>'
        if a != b:
            return 'line %d: want %r got %r' % (i + 1, a, b)
    return ''


def load_rows(only):
    rows = json.loads(ROWS.read_text())['rows']
    if only:
        rows = [r for r in rows if re.search(only, r['name'])]
    return rows


def cmd_run(a):
    sess = load_session()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    for row in load_rows(a.only):
        if row.get('accel') and row['accel'] != a.accel:
            print('SKIP remote %s reason=this row runs under %s only' % (row['name'], row['accel']))
            counts['skip'] += 1
            continue
        got, why = run_row(a, row, sess, out)
        if got is None:
            print('FAIL remote %s %s' % (row['name'], why))
            counts['fail'] += 1
            continue
        (out / (row['name'] + '.txt')).write_text(got)
        gold = GOLD / (row['name'] + '.out')
        if a.mode == 'capture':
            GOLD.mkdir(parents=True, exist_ok=True)
            gold.write_text(got)
            print('CAPTURED remote %s%s' % (row['name'], (' ' + why) if why else ''))
            counts['pass' if not why else 'fail'] += 1
            continue
        if not gold.exists():
            print('FAIL remote %s no golden' % row['name'])
            counts['fail'] += 1
            continue
        d = first_diff(gold.read_text(), got)
        if d or why:
            print('FAIL remote %s %s' % (row['name'], d or why))
            counts['fail'] += 1
        else:
            print('PASS remote %s' % row['name'])
            counts['pass'] += 1
    print('remote rows (%s, %s): %d pass, %d fail, %d skip' % (a.mode, a.accel, counts['pass'], counts['fail'], counts['skip']))
    return 1 if counts['fail'] else 0


def cmd_skip(a):
    rows = load_rows(None)
    for row in rows:
        print('SKIP remote %s reason=%s' % (row['name'], a.reason))
    print('remote rows (skip): 0 pass, 0 fail, %d skip' % len(rows))
    return 0


def cmd_selftest(_a):
    sess = load_session()
    t = normalise('(gdb) Remote debugging using 127.0.0.1:41001\r\n0x000000000000fff0 in ?? ()\r\n(gdb) ', 41001, Path('/k/kmain_console.elf'), sess)
    assert t == 'Remote debugging using 127.0.0.1:PORT\n0x000000000000fff0 in ?? ()\n', repr(t)
    t = normalise('Detaching from program: /k/kmain_console.elf, process 1\r\n', 0, Path('/k/kmain_console.elf'), sess)
    assert t == 'Detaching from program: KERNEL, process 1\n', repr(t)
    assert script_lines({'script': ['target remote 127.0.0.1:@PORT@', '!interrupt 5 continue']}, 7) == ['target remote 127.0.0.1:7', '!interrupt 5 continue']
    assert first_diff('a\nb\n', 'a\nc\n') == "line 2: want 'b' got 'c'"
    rows = json.loads(ROWS.read_text())['rows']
    names = [r['name'] for r in rows]
    assert len(names) == len(set(names)), 'duplicate row names'
    for r in rows:
        assert r['name'].startswith(('remote-kernel-', 'remote-refuse-')), r['name']
        assert r.get('accel') in (None, 'kvm', 'tcg'), r['name']
        assert isinstance(r['script'], list) and r['script'], r['name']
        assert not any('xml-tdesc' in line for line in r['script']), 'a row may not print QEMU\'s description: ' + r['name']
    print('PASS session-remote-selftest rows=%d' % len(rows))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='mode', required=True)
    for mode in ('capture', 'check', 'gdb-check'):
        q = sub.add_parser(mode)
        for name in ('--kernel', '--image', '--pax', '--qemu'):
            q.add_argument(name, required=True)
        q.add_argument('--gdb', required=mode != 'check')
        q.add_argument('--sniff', required=mode == 'check')
        q.add_argument('--accel', choices=('kvm', 'tcg'), required=True)
        q.add_argument('--only')
        q.add_argument('--out', default=str(ROOT / 'target/remote-out'))
    sk = sub.add_parser('skip')
    sk.add_argument('--reason', required=True)
    sub.add_parser('selftest')
    a = p.parse_args()
    if a.mode == 'skip':
        return cmd_skip(a)
    if a.mode == 'selftest':
        return cmd_selftest(a)
    return cmd_run(a)


if __name__ == '__main__':
    sys.exit(main())
