#!/usr/bin/env python3
"""S8's remote rows: the pinned gdb and sniff over QEMU's gdbstub on PAX's console kernel, at one processor (the kernel
rows), and sniff-server, the stub, on Linux (kind server) and on PAX (kind server-pax).

  session-remote.py capture --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --gdb GDB --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py check   --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --sniff SNIFF --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py gdb-check (as check, with --gdb: the goldens hold for this accelerator and this run)
  session-remote.py server --server SNIFF-SERVER --fixtures DIR [--only RE] [--out DIR]
                                            the server rows on this Linux host, against the pinned gdbserver live
  session-remote.py server-pax-image --pax PAXTREE --kernel ELF --inputs DIR --server SNIFF-SERVER-STATIC --fixtures DIR
                                            the server-pax rows' image (in PAX's image, which has its image tools)
  session-remote.py server-pax --image DIR --pax PAXTREE --kernel ELF --qemu QEMU --fixtures DIR [--accel kvm]
                                            the server-pax rows: one boot of that image under KVM, gdb from this host
  session-remote.py skip [--kind kernel|server|server-pax] --reason TEXT [--expect N]
                                            one SKIP line a row of that kind and the count (held at N), where the
                                            rows cannot run
  session-remote.py selftest                the normalisation and the script forms, no machine

Rows: tests/remote-rows.json. Goldens: tests/evidence/remote/NAME.out, gdb's transcript under KVM on the record host,
written only when a second capture (its own boot) gives the same normalised transcript. A row with "skip" is a named
SKIP with that one-line reason in every mode, counted. A row with "own" is sniff's own answer where gdb gives another
(sniff's words for something it refuses): check holds sniff's normalised transcript to those lines, and capture and
gdb-check pass it by (OWN), counted. A
row with "accel" runs only under that accelerator. A row with "qemu": false runs with no QEMU (the refusals).

Each row is one boot of the console image through PAX's tools/qemu-run with `--gdb PORT` (the processor frozen at reset).
The tool runs on a pty that is its controlling terminal, with its standard error on the same terminal, one script line a
prompt. `@PORT@` in a line is the port. A line `!interrupt N CMD` sends CMD and, if no prompt came in N seconds, writes the
byte 0x03 to the pty, which the terminal turns into SIGINT. qemu-run's pid is recorded; if it is still running 10 s after the
tool ends, SIGTERM goes to that pid, whose trap ends its QEMU.

Each run that boots a row first prints a `QEMU` line (its version line, its binary's sha256, the accelerator) and refuses
by name (FAIL remote-qemu-pin) a QEMU whose version line or binary digest is not this host's pin in sniff-oracle.toml.

Normalised by name: the port, the kernel's path, the terminal's line ends and the prompts (tools/session.py's
normalize_tty). QEMU's target description never appears in a golden as text: no row prints it.

The server rows hold sniff-server to the pinned gdbserver, run live beside it: the same requests and the same gdb
session commands on the same static fixture, and gdb's two transcripts equal after SESSION_NORMALISE's named
differences. Every server run names gdbserver and gdb by version and sha256 (its ORACLES line). On PAX the stub runs in
the console image, reached through a port QEMU forwards from this host's loopback.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
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


def qemu_pin(system):
    """QEMU's pin for this host from sniff-oracle.toml: its --version line and its binary's sha256 (the Mac's own)."""
    import tomllib
    q = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())['qemu']
    return q['version_line'], q['macos_sha256'] if system == 'Darwin' else q['sha256']


def qemu_problems(line, sha, want_line, want_sha):
    """What is wrong between a QEMU binary (its first --version line and sha256) and its pin, each by name."""
    if line != want_line:
        return ['qemu-version %r is not the pin\'s %r' % (line, want_line)]
    if sha != want_sha:
        return ['qemu-sha256 %s is not the pin\'s %s' % (sha, want_sha)]
    return []


def qemu_line(a):
    """The run's QEMU line (its version, its binary's sha256, the accelerator) and what is wrong with it."""
    import hashlib
    import platform as host
    q = Path(a.qemu).resolve()
    try:
        line = subprocess.run([str(q), '--version'], capture_output=True, text=True, timeout=30).stdout.splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired) as e:
        return 'QEMU %s unreadable (%s)' % (q, e), ['qemu-version unreadable']
    sha = hashlib.sha256(q.read_bytes()).hexdigest()
    want_line, want_sha = qemu_pin(host.system())
    return 'QEMU version=%r sha256=%s accel=%s binary=%s' % (line, sha, a.accel, q), qemu_problems(line, sha, want_line, want_sha)


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


FRAME_AT_ADDRESS = re.compile(r'0x[0-9a-f]+ in [^\s(]+ \(.*\)(?: at \S+:(?P<line>\d+))?')
FRAME_AT_LINE = re.compile(r'[^\s(]+ \(.*\) at \S+:(?P<line>\d+)')
LET_GO = '[Inferior 1 (process 1) detached]'


def frame_size(lines, j):
    """How many lines from lines[j] are one frame in either of gdb's two forms: `0x... in NAME (ARGS)`, with ` at
    FILE:LINE` or without, and `NAME (ARGS) at FILE:LINE` (a stop at a line's first instruction). A frame that names a
    line is followed by that line's source, `LINE<tab>...`, which is part of it; without that line it is no frame.
    0 when lines[j] is in neither form."""
    if j >= len(lines):
        return 0
    m = FRAME_AT_ADDRESS.fullmatch(lines[j]) or FRAME_AT_LINE.fullmatch(lines[j])
    if not m:
        return 0
    line = m.group('line')
    if line is None:
        return 1
    return 2 if j + 1 < len(lines) and lines[j + 1].startswith(line + '\t') else 0


def stop_location(t):
    """The frame a connect prints right after a detach let the machine run: `[Inferior 1 (process 1) detached]`, the
    connect's `Remote debugging using ...` line, the blank line and `Program received signal ...` when gdb prints them,
    then the frame, which becomes <LOCATION>. Every line around it stays as it came."""
    lines = t.split('\n')
    out = []
    i = 0
    while i < len(lines):
        out.append(lines[i])
        if lines[i] != LET_GO or i + 1 >= len(lines) or not lines[i + 1].startswith('Remote debugging using '):
            i += 1
            continue
        out.append(lines[i + 1])
        j = i + 2
        if j + 1 < len(lines) and lines[j] == '' and lines[j + 1].startswith('Program received signal '):
            out += lines[j:j + 2]
            j += 2
        n = frame_size(lines, j)
        if n:
            out.append('<LOCATION>')
        i = j + n
    return '\n'.join(out)


def normalise(text, port, kernel, sess, names=()):
    """The port, the kernel's path and the terminal, always; a row's own normalisations by name: `watch-values` (a
    watchpoint's old and new values, which the time decides) and `stop-location` (where a machine a detach let run was
    when the next connect stopped it: stop_location). Each replaces a value in a line that must be there: the hit's own
    line, the connect's line, the signal's line and a frame in one of gdb's two forms stay asserted, so a transcript
    that lacks one, or prints a line in neither form, still differs from its golden."""
    fired = set()
    t = sess.normalize_tty(text, fired)
    if port:
        t = t.replace('127.0.0.1:%d' % port, '127.0.0.1:PORT')
    t = t.replace(str(kernel), 'KERNEL')
    if 'watch-values' in names:
        t = re.sub(r'^(Old|New) value = .*$', r'\1 value = <VALUE>', t, flags=re.M)
    if 'stop-location' in names:
        t = stop_location(t)
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
    return normalise(text, port, kernel, sess, row.get('normalise', [])), ('no prompt after: ' + bad[0]) if bad else ''


def first_diff(want, got):
    w, g = want.splitlines(), got.splitlines()
    for i in range(max(len(w), len(g))):
        a = w[i] if i < len(w) else '<end>'
        b = g[i] if i < len(g) else '<end>'
        if a != b:
            return 'line %d: want %r got %r' % (i + 1, a, b)
    return ''


def load_rows(only, kind='kernel'):
    # a row's kind: the kernel rows (sniff or gdb over QEMU's gdbstub) unless it says server or server-pax (sniff-server's)
    rows = [r for r in json.loads(ROWS.read_text())['rows'] if r.get('kind', 'kernel') == kind]
    if only:
        rows = [r for r in rows if re.search(only, r['name'])]
    return rows


def cmd_run(a):
    sess = load_session()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    if any(r.get('qemu', True) and not r.get('skip') for r in load_rows(a.only)):
        text, problems = qemu_line(a)
        print(text)
        if problems:
            print('FAIL remote-qemu-pin ' + '; '.join(problems))
            print('remote rows (%s, %s): 0 pass, 1 fail, 0 skip' % (a.mode, a.accel))
            return 1
    for row in load_rows(a.only):
        if row.get('skip'):
            print('SKIP remote %s reason=%s' % (row['name'], row['skip']))
            counts['skip'] += 1
            continue
        if row.get('own') is not None and a.mode != 'check':
            print('OWN remote %s (sniff\'s own answer; gdb is not its oracle)' % row['name'])
            counts['skip'] += 1
            continue
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
            # a golden is written only when a second capture, its own boot, holds the first
            again, why2 = run_row(a, row, sess, out / 'second')
            if why or why2 or again is None or again != got:
                d = why or why2 or ('second capture: ' + first_diff(got, again or ''))
                print('FAIL remote %s capture not held by a second capture: %s' % (row['name'], d))
                counts['fail'] += 1
                continue
            GOLD.mkdir(parents=True, exist_ok=True)
            gold.write_text(got)
            print('CAPTURED remote %s (held by a second capture)' % row['name'])
            counts['pass'] += 1
            continue
        if row.get('own') is not None:
            want = ''.join(line + '\n' for line in row['own'])
            d = first_diff(want, got)
            if d or why:
                print('FAIL remote %s (own) %s' % (row['name'], d or why))
                counts['fail'] += 1
            else:
                print('PASS remote %s (own)' % row['name'])
                counts['pass'] += 1
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
    rows = load_rows(None, a.kind)
    for row in rows:
        print('SKIP remote %s reason=%s' % (row['name'], row.get('skip') or a.reason))
    print('remote rows (skip): 0 pass, 0 fail, %d skip' % len(rows))
    # the count is held: a row that stops being listed here stops being skipped by name, and shows
    if a.expect is not None and len(rows) != a.expect:
        print('FAIL remote-skip-count %d rows skipped where %d are held' % (len(rows), a.expect))
        return 1
    return 0


# sniff-server's rows (kind server): the stub on loopback in this host, its client this harness or the pinned gdb. Each
# row's check names what it holds; the stub is started by its recorded pid and ended by it.
SERVER_CHECKS = ('refuse-second', 'refuse-non-loopback', 'loopback-default', 'idle-cost', 'interrupt-latency',
                 'z1-hbreak', 'fp-write', 'fp-tag', 'threads', 'detach', 'gdb-session', 'oracle-stable', 'native-golden')
SESSION_ROWS = ROOT / 'tests/session-rows.json'
# what gdb prints differently through the two stubs, by design, each by name: only through gdbserver, which offers Host
# I/O, does gdb read files over the connection, so only there does it print the two lines of that feature (a separate
# debug file read from the remote target, and its warning that file transfers from remote targets can be slow); only
# through gdbserver (which offers multiprocess) does gdb name the inferior by its pid and a thread as PID.TID; and each
# run's port is its own
SESSION_NORMALISE = (
    ('host-io', re.compile(r'^(?:Reading \S+ from remote target\.\.\.|warning: File transfers from remote targets can be slow\. '
                           r'Use "set sysroot" to access files locally instead\.)\n', re.M), ''),
    ('inferior-name', re.compile(r'\[Inferior 1 \((?:process \d+|Remote target)\)'), '[Inferior 1 (INFERIOR)'),
    ('port', re.compile(r'127\.0\.0\.1:\d+'), '127.0.0.1:PORT'),
    ('thread-id', re.compile(r'\bThread (?:\d+\.)?\d+\b'), 'Thread TID'),
    # the session set's own rule (tools/session.py's spin): the workers fixture's spinning threads stop anywhere in a
    # one-line loop, so their pc is the run's own
    ('spin', re.compile(r'\b0x[0-9a-f]+ in spin \('), 'spin ('),
    # `info threads` pads its Target Id column to the longest id: gdbserver's ids are longer by the pid
    # (multiprocess, as `inferior-name`), so the padding before the Frame column is each stub's own
    ('thread-table', re.compile(r'^(  Id +Target Id|[* ] +\d+ +Thread TID(?: "[^"]*")?) +', re.M), r'\1 '),
)
ANY_LISTENING = re.compile(r'Listening on (?:\S+:)?(?:port )?(\d+)')  # sniff-server's line, or gdbserver's
RUN_POLL_MS = 100  # sniff-server's run_poll_ms: the longest wait on the sockets while the program runs
LISTENING = re.compile(r'^Listening on (\S+):(\d+)$', re.M)


def frame(data):
    b = data.encode()
    return b'$' + b + b'#' + ('%02x' % (sum(b) % 256)).encode()


def read_packet(s, limit=5.0):
    """The first packet's data off the socket within limit seconds, acknowledgments skipped; None if it closed or
    timed out first."""
    buf, end = b'', time.time() + limit
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            chunk = s.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
        i = buf.find(b'$')
        j = buf.find(b'#', i + 1) if i >= 0 else -1
        if i >= 0 and j >= 0 and len(buf) >= j + 3:
            return buf[i + 1:j].decode(errors='backslashreplace')
    return None


def ask(s, data):
    s.sendall(frame(data))
    got = read_packet(s)
    if got is not None:
        s.sendall(b'+')
    return got


def closed(s, limit=5.0):
    s.settimeout(limit)
    try:
        return s.recv(64) == b''
    except OSError:
        return False


def tcp_sockets(port):
    """(local address in /proc/net/tcp's hex, state) of every socket on this TCP port."""
    found = []
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        f = line.split()
        addr, hexport = f[1].split(':')
        if int(hexport, 16) == port:
            found.append((addr, f[3]))
    return found


def start_server(a, args, out, name):
    log = out / (name + '.server')
    p = subprocess.Popen([a.server] + args, stdout=open(log, 'w'), stderr=subprocess.STDOUT)
    end = time.time() + 20
    while time.time() < end and p.poll() is None and not LISTENING.search(log.read_text(errors='replace')):
        time.sleep(0.05)
    return p, LISTENING.search(log.read_text(errors='replace'))


def end_server(p, name):
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        print('sniff-server %d still running 10 s after row %s: TERM to its recorded pid' % (p.pid, name))
        p.terminate()
        p.wait()


def check_refuse_second(a, row, out):
    """While one client is attached a second is refused by name: it gets the stub's E.text reply to its first packet and
    its connection is closed, sniff-server says so, and the first client's session goes on."""
    want = 'E.sniff-server serves one client at a time'
    port = free_port()
    p, up = start_server(a, ['127.0.0.1:%d' % port, str(Path(a.fixtures) / row['prog'])], out, row['name'])
    problems = []
    try:
        if not up:
            return FAULT + 'sniff-server never said it was listening', ''
        first = socket.create_connection(('127.0.0.1', port), timeout=5)
        r1 = ask(first, 'qSupported:swbreak+;vContSupported+')
        if not r1 or 'PacketSize=' not in r1:
            problems.append('the first client got %r to qSupported' % r1)
        second = socket.create_connection(('127.0.0.1', port), timeout=5)
        r2 = ask(second, 'qSupported:swbreak+')
        if r2 != want:
            problems.append('the second client got %r, not %r' % (r2, want))
        if not closed(second):
            problems.append('the second connection was not closed')
        second.close()
        r3 = ask(first, '?')
        if not r3 or r3[0] not in 'TS':
            problems.append('the first client lost its session: %r to ?' % r3)
        first.sendall(frame('k'))
        first.close()
    finally:
        end_server(p, row['name'])
    said = (out / (row['name'] + '.server')).read_text(errors='replace')
    if 'sniff-server: refused a second client: one client at a time' not in said:
        problems.append('sniff-server did not say it refused the second client')
    return '; '.join(problems), 'the second client got %r and was closed; the first went on' % want


def check_refuse_non_loopback(a, row, out):
    """A HOST that is not loopback is refused by name, binding nothing, unless --non-loopback asks for it by name."""
    prog = str(Path(a.fixtures) / row['prog'])
    port = free_port()
    problems = []
    r = subprocess.run([a.server, '0.0.0.0:%d' % port, prog], capture_output=True, text=True, timeout=20)
    (out / (row['name'] + '.refused')).write_text(r.stdout + r.stderr)
    words = 'sniff-server: 0.0.0.0 is not a loopback address'
    if r.returncode == 0 or words not in r.stderr or '--non-loopback' not in r.stderr:
        problems.append('without --non-loopback: exit %d, %r' % (r.returncode, r.stderr.strip()[:160]))
    if tcp_sockets(port):
        problems.append('a socket was bound on port %d without --non-loopback' % port)
    p, up = start_server(a, ['--non-loopback', '0.0.0.0:%d' % port, prog], out, row['name'])
    try:
        if not up:
            problems.append('with --non-loopback sniff-server never said it was listening')
        elif ('00000000', '0A') not in tcp_sockets(port):
            problems.append('with --non-loopback the listener is %r, not 0.0.0.0 listening' % tcp_sockets(port))
        if up:
            c = socket.create_connection(('127.0.0.1', port), timeout=5)
            c.sendall(frame('k'))
            c.close()
    finally:
        end_server(p, row['name'])
    return '; '.join(problems), 'refused by name without --non-loopback (%s); listening on 0.0.0.0 with it' % words


def check_loopback_default(a, row, out):
    """`:PORT` listens on 127.0.0.1 alone (the kernel's socket table) and says so."""
    port = free_port()
    p, up = start_server(a, [':%d' % port, str(Path(a.fixtures) / row['prog'])], out, row['name'])
    problems = []
    try:
        if not up:
            return FAULT + 'sniff-server never said it was listening', ''
        if up.group(1) != '127.0.0.1' or int(up.group(2)) != port:
            problems.append('it said Listening on %s:%s' % (up.group(1), up.group(2)))
        if tcp_sockets(port) != [('0100007F', '0A')]:
            problems.append('the sockets on port %d are %r, not 127.0.0.1 listening alone' % (port, tcp_sockets(port)))
        c = socket.create_connection(('127.0.0.1', port), timeout=5)
        c.sendall(frame('k'))
        c.close()
    finally:
        end_server(p, row['name'])
    return '; '.join(problems), 'listening on 127.0.0.1:PORT alone'


def proc_cost(pid):
    """(CPU ticks, context switches) a process has used: utime and stime from /proc/PID/stat, and its voluntary and
    involuntary switches from /proc/PID/status (each wakeup from a wait is one)."""
    stat = Path('/proc/%d/stat' % pid).read_text()
    f = stat[stat.rindex(')') + 2:].split()
    sw = 0
    for line in Path('/proc/%d/status' % pid).read_text().splitlines():
        if line.startswith(('voluntary_ctxt_switches:', 'nonvoluntary_ctxt_switches:')):
            sw += int(line.split(':')[1])
    return int(f[11]) + int(f[12]), sw


def cost_problems(idle_ticks, idle_wakes, run_rate):
    """A stopped program with a silent client costs nothing measurable (no CPU tick and at most 2 wakeups in 5 s);
    a running one wakes about 1000/RUN_POLL_MS times a second, and never more than half again that."""
    problems = []
    if idle_ticks != 0:
        problems.append('stopped with a silent client it used %d CPU ticks in 5 s' % idle_ticks)
    if idle_wakes > 2:
        problems.append('stopped with a silent client it woke %d times in 5 s' % idle_wakes)
    if run_rate > 1.5 * 1000 / RUN_POLL_MS:
        problems.append('running it woke %.1f times a second, past %.0f' % (run_rate, 1.5 * 1000 / RUN_POLL_MS))
    return problems


def latency_problems(reply, seconds):
    """The interrupt byte stops a running program with SIGINT's stop reply (T02, measured: protocol 2) within five
    times RUN_POLL_MS."""
    problems = []
    if not reply or not reply.startswith('T02'):
        problems.append('the interrupt got %r, not a T02 stop reply' % reply)
    if seconds > 5 * RUN_POLL_MS / 1000:
        problems.append('the stop came %.0f ms after the interrupt, past %d ms' % (seconds * 1000, 5 * RUN_POLL_MS))
    return problems


def started(a, row, out):
    port = free_port()
    p, up = start_server(a, ['127.0.0.1:%d' % port, str(Path(a.fixtures) / row['prog'])] + row.get('args', []), out, row['name'])
    if not up:
        end_server(p, row['name'])
        return None, None, None
    c = socket.create_connection(('127.0.0.1', port), timeout=5)
    ask(c, 'qSupported:swbreak+;vContSupported+')
    ask(c, '?')
    return p, c, port


def check_idle_cost(a, row, out):
    """What the polling loop costs: 5 s stopped with a silent client, then 5 s running (sniff-server's own ticks and
    wakeups); each number stated."""
    p, c, _port = started(a, row, out)
    if p is None:
        return FAULT + 'sniff-server never said it was listening', ''
    try:
        time.sleep(0.5)
        t0, s0 = proc_cost(p.pid)
        time.sleep(5)
        t1, s1 = proc_cost(p.pid)
        c.sendall(frame('vCont;c'))
        time.sleep(0.5)
        t2, s2 = proc_cost(p.pid)
        time.sleep(5)
        t3, s3 = proc_cost(p.pid)
        rate = (s3 - s2) / 5.0
        c.sendall(b'\x03')
        read_packet(c, 5)
        c.sendall(b'+')
        c.sendall(frame('k'))
        c.close()
    finally:
        end_server(p, row['name'])
    held = ('stopped, silent client: %d CPU ticks and %d wakeups in 5 s; running: %d CPU ticks in 5 s and %.1f wakeups a '
            'second (the %d ms wait: %d)' % (t1 - t0, s1 - s0, t3 - t2, rate, RUN_POLL_MS, 1000 // RUN_POLL_MS))
    return '; '.join(cost_problems(t1 - t0, s1 - s0, rate)), held


def check_interrupt_latency(a, row, out):
    """The interrupt byte to the stop reply, while the program runs: the time measured and its bound stated."""
    p, c, _port = started(a, row, out)
    if p is None:
        return FAULT + 'sniff-server never said it was listening', ''
    try:
        c.sendall(frame('vCont;c'))
        time.sleep(1)
        t = time.monotonic()
        c.sendall(b'\x03')
        reply = read_packet(c, 5)
        took = time.monotonic() - t
        c.sendall(b'+')
        c.sendall(frame('k'))
        c.close()
    finally:
        end_server(p, row['name'])
    held = 'the stop reply %r came %.0f ms after the interrupt (bound %d ms, five times the %d ms wait)' % (
        (reply or '')[:3], took * 1000, 5 * RUN_POLL_MS, RUN_POLL_MS)
    return '; '.join(latency_problems(reply, took)), held


def symbol(prog, name):
    """A symbol's address in a static fixture, from nm."""
    for line in subprocess.run(['nm', str(prog)], capture_output=True, text=True).stdout.splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == name:
            return int(f[0], 16)
    return None


def thread_ids(ask_fn):
    """Every thread id by qfThreadInfo and then qsThreadInfo until `l` (General Query Packets: a reply may hold one id
    or several): [] when the first reply is no list, None when there is no reply."""
    first = ask_fn('qfThreadInfo')
    if first is None:
        return None
    if not first.startswith('m'):
        return []
    ids, got = [], first
    for _ in range(4096):
        if not got or not got.startswith('m'):
            break
        ids += [x for x in got[1:].split(',') if x]
        got = ask_fn('qsThreadInfo')
    return ids


# Byte offsets in the g packet, in the order of both stubs' descriptions (core, then sse): rax to r15 at 8 bytes
# each, then rip; eflags and the six segment registers at 4; st0 to st7 at 10; fctrl, fstat, ftag, fiseg, fioff,
# foseg, fooff and fop at 4; then xmm0. gdbserver answers p and P with the empty reply, so the driver uses g and G.
G_RIP, G_FCTRL, G_FTAG, G_XMM0 = 16 * 8, 17 * 8 + 7 * 4 + 8 * 10, 17 * 8 + 7 * 4 + 8 * 10 + 2 * 4, 17 * 8 + 7 * 4 + 8 * 10 + 8 * 4


def g_field(g, off, n):
    """The little-endian number of n bytes at byte off of a g reply."""
    return int.from_bytes(bytes.fromhex(g[2 * off:2 * off + 2 * n]), 'little')


def g_with(g, off, hexbytes):
    """A g reply with the bytes at byte off replaced: the body of the G that writes them."""
    return g[:2 * off] + hexbytes + g[2 * off + len(hexbytes):]


def hg_for(stop):
    """The Hg the pinned gdb sends after `?` (its remote log): the thread the stop reply names, or None."""
    m = re.search(r'thread:([^;]+);', stop or '')
    return 'Hg' + m.group(1) if m else None


def oracle_silent(answers):
    """True when the oracle gave no reply to some request (None): such a row compares nothing."""
    vals = answers.values() if isinstance(answers, dict) else answers
    return any(v is None or (isinstance(v, (list, dict)) and oracle_silent(v)) for v in vals)


# A row's FAIL is its own comparison, or a fault by this prefix: the driver lost its connection or its process, a stub
# never listened, or a side gave no reply where one was asked for. A red is never a fault (the rig's red steps
# refuse a fault line by this prefix).
FAULT = 'fault: '


def run_check(fn, a, row, out):
    """A row's check, a driver exception made a fault by name."""
    try:
        return fn(a, row, out)
    except (OSError, subprocess.SubprocessError) as e:
        return FAULT + '%s: %s (the driver lost its connection or its process; nothing compared)' % (type(e).__name__, e), ''


def compare(mine, theirs, what):
    """sniff-server's answers against gdbserver's: a fault when either side gave no reply ('-' is a request not made,
    because an earlier answer ruled it out), else the comparison."""
    if oracle_silent(mine):
        return FAULT + 'the stub gave no reply (sniff-server %r): nothing compared' % (mine,), ''
    if oracle_silent(theirs):
        return FAULT + 'the oracle gave no reply (gdbserver %r): nothing compared' % (theirs,), ''
    if mine != theirs:
        return '%s: sniff-server %r, gdbserver %r' % (what, mine, theirs), ''
    return '', '%s equal to gdbserver\'s: %r' % (what, mine)


def both_stubs(a, row, out, steps):
    """steps(socket, prog) run against sniff-server and then against the pinned gdbserver, each on its own free port
    with the row's fixture and arguments: (sniff-server's answers, gdbserver's), or a reason one never listened."""
    prog = Path(a.fixtures) / row['prog']
    got = {}
    for who in ('sniff-server', 'gdbserver'):
        port = free_port()
        argv = ([a.server, '127.0.0.1:%d' % port] if who == 'sniff-server' else ['gdbserver', '--once', '127.0.0.1:%d' % port])
        log = out / ('%s.%s' % (row['name'], who))
        p = subprocess.Popen(argv + [str(prog)] + row.get('args', []), stdout=open(log, 'w'), stderr=subprocess.STDOUT)
        end = time.time() + 20
        while time.time() < end and p.poll() is None and not ANY_LISTENING.search(log.read_text(errors='replace')):
            time.sleep(0.05)
        if not ANY_LISTENING.search(log.read_text(errors='replace')):
            end_server(p, row['name'])
            return None, None, FAULT + '%s never said it was listening' % who
        c = socket.create_connection(('127.0.0.1', port), timeout=5)
        # the pinned gdb's own opening, in its order (its remote log): qSupported, `?`, then Hg for the thread named
        ask(c, 'qSupported:swbreak+;vContSupported+')
        h = hg_for(ask(c, '?'))
        if h:
            ask(c, h)
        try:
            got[who] = steps(c, prog)
        finally:
            c.sendall(frame('k'))
            c.close()
            end_server(p, row['name'])
    return got['sniff-server'], got['gdbserver'], ''


def resumed(c):
    """vCont;c, then the stop reply."""
    c.sendall(frame('vCont;c'))
    got = read_packet(c, 20)
    if got is not None:
        c.sendall(b'+')
    return got


def check_same(a, row, out, steps, what):
    mine, theirs, why = both_stubs(a, row, out, steps)
    if why:
        return why, ''
    return compare(mine, theirs, what)


def check_z1_hbreak(a, row, out):
    """Z1, a hardware breakpoint in a debug register (the platform's execute kind): accepted, and the stop is at it."""
    def steps(c, prog):
        addr = symbol(prog, row['symbol'])
        z = ask(c, 'Z1,%x,1' % addr)
        stop = resumed(c) if z == 'OK' else '-'
        g = ask(c, 'g') if stop not in (None, '-') else '-'
        at = g if g in (None, '-') else (len(g) >= 2 * (G_RIP + 8) and g_field(g, G_RIP, 8) == addr)
        return {'Z1': z, 'stop': stop if stop in (None, '-') else stop[:3], 'rip at the breakpoint': at}
    return check_same(a, row, out, steps, 'Z1, the stop and the pc')


def check_fp_write(a, row, out):
    """An SSE register written with G and read back with g (xmm0, at the same byte offset in both stubs' g)."""
    value = '0102030405060708090a0b0c0d0e0f10'
    def steps(c, prog):
        g = ask(c, 'g')
        w = ask(c, 'G' + g_with(g, G_XMM0, value)) if g else ('-' if g == '' else None)
        r = ask(c, 'g') if w not in (None, '-') else w
        return {'g': None if g is None else 'read', 'G with xmm0': w,
                'xmm0 read back is the value': r if r in (None, '-') else r[2 * G_XMM0:2 * G_XMM0 + 32] == value}
    return check_same(a, row, out, steps, 'the write and the read back')


def check_fp_tag(a, row, out):
    """The x87 tag word (register 34, ftag). FXSAVE keeps an abridged byte, one bit a register, where gdb's register is
    the full tag word, two bits a register. Held to gdbserver's answers by g and G: the eight x87 control registers
    read, ftag written as 0x3fff (R7 in use, the rest empty), and read back."""
    def steps(c, prog):
        g = ask(c, 'g')
        before = [g[2 * (G_FCTRL + 4 * i):2 * (G_FCTRL + 4 * i) + 8] for i in range(8)] if g else g
        w = ask(c, 'G' + g_with(g, G_FTAG, 'ff3f0000')) if g else ('-' if g == '' else None)
        r = ask(c, 'g') if w not in (None, '-') else w
        return {'fctrl to fop': before, 'G with ftag': w, 'ftag read back': r if r in (None, '-') else r[2 * G_FTAG:2 * G_FTAG + 8]}
    return check_same(a, row, out, steps, 'the x87 control registers, and the tag word written and read back')


def check_detach(a, row, out):
    """D with a breakpoint and a watchpoint set: the stub takes both out and lets the program go, and it runs to its
    end on its own (the sleeper's last line, `done N`, comes into the stub's log). Held to gdbserver."""
    def steps(c, prog):
        z0 = ask(c, 'Z0,%x,1' % symbol(prog, 'nap'))
        z2 = ask(c, 'Z2,%x,4' % symbol(prog, 'ticks'))
        return {'Z0': z0, 'Z2': z2, 'D': ask(c, 'D')}
    mine, theirs, why = both_stubs(a, row, out, steps)
    if why:
        return why, ''
    if oracle_silent(mine) or oracle_silent(theirs):
        return compare(mine, theirs, 'the detach')
    want = 'done %s' % row['args'][0]
    for who, got in (('sniff-server', mine), ('gdbserver', theirs)):
        log = out / ('%s.%s' % (row['name'], who))
        end = time.time() + 10
        while time.time() < end and want not in log.read_text(errors='replace'):
            time.sleep(0.1)
        got['ran to its end'] = want in log.read_text(errors='replace')
    return compare(mine, theirs, 'the detach')


def check_threads(a, row, out):
    """A program's new threads are traced and listed: at a breakpoint a worker thread hits, qfThreadInfo lists more
    than one thread, and the stop is a trap."""
    def steps(c, prog):
        addr = symbol(prog, row['symbol'])
        z = ask(c, 'Z0,%x,1' % addr)
        stop = resumed(c) if z == 'OK' else '-'
        ids = thread_ids(lambda q: ask(c, q)) if stop not in (None, '-') else '-'
        return {'Z0': z, 'stop': stop if stop in (None, '-') else stop[:3],
                'threads listed': ids if ids in (None, '-') else len(ids) >= 2}
    return check_same(a, row, out, steps, 'the stop and the thread list')


def session_script(name):
    """A session row's fixture, the stub's arguments and gdb's commands: its one `run ARGS` becomes ARGS for the stub
    and a `continue` (the stub started the program, stopped at its first instruction)."""
    row = {r['name']: r for r in json.loads(SESSION_ROWS.read_text())['rows']}[name]
    script = list(row['script'])
    runs = [k for k, c in enumerate(script) if c == 'run' or c.startswith('run ')]
    if len(runs) != 1 or set(row) - {'name', 'prog', 'script'}:
        return None
    cmds = script[:runs[0]] + ['continue'] + script[runs[0] + 1:]
    return row['prog'], script[runs[0]].split()[1:], cmds


def gdb_at(port, prog, cmds, timeout=120):
    """gdb's batch transcript of cmds against the stub at 127.0.0.1:PORT, the program file given to gdb as a user gives
    it; None if gdb did not end within timeout seconds."""
    g = ['gdb', '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-iex', 'set width 0',
         '-ex', 'target remote 127.0.0.1:%d' % port]
    for c in cmds:
        g += ['-ex', c]
    try:
        r = subprocess.run(g + [str(prog)], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    return (r.stdout + r.stderr).decode('utf-8', 'backslashreplace')


def gdb_through(a, who, prog, args, cmds, out, label):
    """gdb's transcript through one stub (batch mode, the program file given to gdb as a user gives it)."""
    port = free_port()
    argv = [a.server, '127.0.0.1:%d' % port] if who == 'sniff-server' else ['gdbserver', '--once', '127.0.0.1:%d' % port]
    log = out / (label + '.stub')
    s = subprocess.Popen(argv + [str(prog)] + args, stdout=open(log, 'w'), stderr=subprocess.STDOUT)
    end = time.time() + 20
    while time.time() < end and s.poll() is None and not ANY_LISTENING.search(log.read_text(errors='replace')):
        time.sleep(0.05)
    if not ANY_LISTENING.search(log.read_text(errors='replace')):
        end_server(s, label)
        return None
    text = gdb_at(port, prog, cmds)
    end_server(s, label)
    if text is not None:
        (out / (label + '.txt')).write_text(text)
    return text


def session_normalise(text):
    for _name, rx, to in SESSION_NORMALISE:
        text = rx.sub(to, text)
    return text


def stable_normalise(text):
    """gdbserver's transcript with what is each run's own named (the port, the inferior's pid, the thread ids), as the
    session rows name them: its own stability is held over the rest."""
    for name, rx, to in SESSION_NORMALISE:
        if name in ('port', 'inferior-name', 'thread-id', 'spin'):
            text = rx.sub(to, text)
    return text


# On PAX the initial stack is the kernel's, not Linux's: an address on the stack is named <STACK> by the rule the PAX
# set's rows already use for the same cause (tools/session.py's `stack`), here by the name `stack`.
PAX_STACK_HEX = re.compile(r'0x7ff[0-9a-f]{9}\b')
PAX_STACK_DEC = re.compile(r'\b140[67][0-9]{11}\b')


def pax_normalise(text):
    return PAX_STACK_DEC.sub('<STACK>', PAX_STACK_HEX.sub('<STACK>', session_normalise(text)))


def check_gdb_session(a, row, out):
    """gdb through sniff-server against gdb through the pinned gdbserver: one session row's commands on its static
    fixture, both transcripts with the named normalisations, held equal."""
    got = session_script(row['row'])
    if got is None:
        return FAULT + 'session row %s is not one plain run' % row['row'], ''
    prog, args, cmds = got
    prog = Path(a.fixtures) / prog
    mine = gdb_through(a, 'sniff-server', prog, args, cmds, out, row['name'] + '.sniff-server')
    theirs = gdb_through(a, 'gdbserver', prog, args, cmds, out, row['name'] + '.gdbserver')
    if mine is None or theirs is None:
        return FAULT + 'a stub never listened, or gdb did not end in 120 s', ''
    d = first_diff(session_normalise(theirs), session_normalise(mine))
    if d:
        return d, ''
    return '', 'gdb through sniff-server equals gdb through gdbserver (%d lines; normalised: %s)' % (
        len(mine.splitlines()), ', '.join(n for n, _rx, _to in SESSION_NORMALISE))


# One fixture through the stub is held to the pinned gdb's native golden as well (tests/evidence/pax-linux, the same
# static build): gdb's transcript through the stub against what gdb printed debugging the program itself. Only two
# lines differ, both gdb's own on a remote target, each dropped by name from the stub's side alone: the stop a remote
# target reports on connecting (the program at its first instruction, which a native `run` never shows), and gdb's
# line on leaving a remote target at the end of batch mode (a native session ends without one).
NATIVE_NORMALISE = (
    ('connect-stop', re.compile(r'\A0x[0-9a-f]{16} in _start \(\)\n'), ''),
    ('remote-kill', re.compile(r'^\[Inferior 1 \(Remote target\) killed\]\n\Z', re.M), ''),
)
NATIVE_GOLD = ROOT / 'tests/evidence/pax-linux'


def native_normalise(text):
    for _name, rx, to in NATIVE_NORMALISE:
        text = rx.sub(to, text)
    return text


def check_native_golden(a, row, out):
    """gdb through sniff-server on the session row's static fixture against the pinned gdb's native golden for it
    (its standard output, then its standard error), with NATIVE_NORMALISE's two named drops."""
    got = session_script(row['row'])
    if got is None:
        return FAULT + 'session row %s is not one plain run' % row['row'], ''
    prog, args, cmds = got
    want = (NATIVE_GOLD / (row['row'] + '.out')).read_text() + (NATIVE_GOLD / (row['row'] + '.err')).read_text()
    mine = gdb_through(a, 'sniff-server', Path(a.fixtures) / prog, args, cmds, out, row['name'] + '.sniff-server')
    if mine is None:
        return FAULT + 'the stub never listened, or gdb did not end in 120 s', ''
    d = first_diff(want, native_normalise(mine))
    if d:
        return d, ''
    return '', "gdb through sniff-server equals the pinned gdb's native golden (%d lines; dropped from the stub's side: %s)" % (
        len(want.splitlines()), ', '.join(n for n, _rx, _to in NATIVE_NORMALISE))


def check_oracle_stable(a, row, out):
    """The oracle's own stability: gdb through the pinned gdbserver, taken twice on the session row's fixture, is
    byte-equal once each run's port is named."""
    got = session_script(row['row'])
    if got is None:
        return FAULT + 'session row %s is not one plain run' % row['row'], ''
    prog, args, cmds = got
    prog = Path(a.fixtures) / prog
    one = gdb_through(a, 'gdbserver', prog, args, cmds, out, row['name'] + '.first')
    two = gdb_through(a, 'gdbserver', prog, args, cmds, out, row['name'] + '.second')
    if one is None or two is None:
        return FAULT + 'gdbserver never listened, or gdb did not end in 120 s', ''
    d = first_diff(stable_normalise(one), stable_normalise(two))
    if d:
        return 'gdbserver\'s transcript changed between two runs: ' + d, ''
    return '', 'gdbserver\'s transcript held by a second run (%d lines; named: port, inferior-name, thread-id, spin)' % len(one.splitlines())


# sniff-server's rows on PAX (kind server-pax). The stub runs in PAX's console image under KVM as a static program, one
# row after another. Each listens on the guest's 0.0.0.0:1234, asked for by name (--non-loopback), which only QEMU's
# user network reaches, through a port it forwards from this host's loopback. The pinned gdb connects from here and
# runs the session row's commands. Its oracle is gdb through the pinned gdbserver on Linux, live, on the same static
# fixture with the same commands, and the two transcripts are held equal under SESSION_NORMALISE.
PAX_GUEST_IP, PAX_GUEST_PORT, PAX_MAC = '10.0.2.15', 1234, '52:54:00:12:34:56'
# QEMU accepts a connection to the forwarded port at once, and resets it while nothing in the guest listens. The first
# round trip on PAX held after 3.0 s and three resets; a row connects with a retry every 0.5 s for up to twenty times that.
PAX_MEASURED_S, PAX_RETRY_EVERY_S, PAX_RETRY_FOR_S = 3.0, 0.5, 60.0
PAX_BOOT_S = 240.0  # the first row's listener: the boot, the shell and the stub's start
PAX_SERVE, PAX_SERVED = '@@SERVE ', '@@SERVED '
PAX_LISTENING = 'Listening on 0.0.0.0:%d' % PAX_GUEST_PORT
PAX_CONNECT_FAILED = re.compile(r'Connection (?:reset by peer|refused|timed out)|Remote connection closed')
PAX_CHECKS = ('pax-session', 'pax-fp-refused')
PAX_FP_WANT = {'stop': 'T05', 'P xmm0': 'E01', 'xmm0 unchanged': True}


def load_session_pax():
    spec = importlib.util.spec_from_file_location('session_pax', ROOT / 'tools/session-pax.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def file_sha(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pax_target(row):
    """A PAX server row's static fixture and the stub's arguments for it."""
    if row['check'] == 'pax-session':
        prog, args, _cmds = session_script(row['row'])
        return prog, args
    return row['prog'], row.get('args', [])


def pax_guest_script(rows, fx_guest):
    """/etc/rows.sh: for each row in order its marker, the stub on the guest's port, and the stub's exit status. The
    stub's own lines go to the console, where the host waits for each row's `Listening on` before it connects."""
    lines = []
    for row in rows:
        prog, args = pax_target(row)
        lines.append("printf '%s\\n' '" + PAX_SERVE + row['name'] + "'")
        lines.append(' '.join(['/bin/sniff-server', '--non-loopback', '0.0.0.0:%d' % PAX_GUEST_PORT, fx_guest + '/' + prog] + args))
        lines.append("printf '%s\\n' \"" + PAX_SERVED + "$?\"")
    return '\n'.join(lines) + '\n'


def pax_served(text, sp):
    """name -> (the stub's console lines, its exit status) for every row whose two markers came off the console."""
    got, cur, lines = {}, None, []
    for line in sp.serial_norm(text).split('\n'):
        if line.startswith(PAX_SERVE):
            cur, lines = line[len(PAX_SERVE):].strip(), []
        elif cur is not None and line.startswith(PAX_SERVED):
            got[cur] = (lines, line[len(PAX_SERVED):].strip())
            cur = None
        elif cur is not None:
            lines.append(line)
    return got


def pax_gdb_failed_to_connect(text):
    """gdb never reached the guest's stub: QEMU took the connection and reset it (the first lines say so)."""
    return text is not None and bool(PAX_CONNECT_FAILED.search('\n'.join(text.splitlines()[:3])))


def pax_fp_refused(port):
    """On PAX, P of xmm0 (register 40): PAX's PTRACE_SETFPREGS answers EIO, so the stub answers E01, and xmm0 reads
    back as it was. (answers, failed to connect)."""
    try:
        c = socket.create_connection(('127.0.0.1', port), timeout=5)
    except OSError:
        return None, True
    try:
        first = ask(c, '?')
        if first is None:
            return None, True
        before = ask(c, 'p28')
        value = '1112131415161718191a1b1c1d1e1f20' if before == '0102030405060708090a0b0c0d0e0f10' else '0102030405060708090a0b0c0d0e0f10'
        w = ask(c, 'P28=' + value)
        after = ask(c, 'p28')
        c.sendall(frame('k'))
        return {'stop': first[:3], 'P xmm0': w, 'xmm0 unchanged': before is not None and len(before) == 32 and after == before}, False
    finally:
        c.close()


def pax_wait_listening(serial, count, q, limit):
    """Until the console shows the count-th row's `Listening on`, the boot ends, or limit seconds pass."""
    end = time.time() + limit
    while time.time() < end and q.poll() is None:
        if serial.exists() and serial.read_text(errors='replace').count(PAX_LISTENING) >= count:
            return True
        time.sleep(0.1)
    return serial.exists() and serial.read_text(errors='replace').count(PAX_LISTENING) >= count


def pax_retry(attempt, ended):
    """attempt() -> (result, failed to connect), again every 0.5 s while it fails to connect, for up to 60 s, and never
    once ended() (the row's stub has ended): (result, attempts, seconds from the first attempt to the start of the
    one that connected; on no answer, to the end of the last)."""
    start, n = time.time(), 0
    while True:
        n += 1
        began = time.time() - start
        got, failed = attempt()
        took = time.time() - start
        if not failed:
            return got, n, began
        if took >= PAX_RETRY_FOR_S or ended():
            return None, n, took
        time.sleep(PAX_RETRY_EVERY_S)


def cmd_server_pax_image(a):
    """The server rows' PAX image, built in PAX's image (its image tools): pelt as the shell, cat and env, sniff-server
    built static, the rows' static fixtures where the Linux goldens name them, /etc/pax-net giving the guest
    10.0.2.15, and one typed line that runs the rows; manifest.json names the rows in order and the digests."""
    sp = load_session_pax()
    rows = load_rows(a.only, 'server-pax')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pax, inputs = Path(a.pax), Path(a.inputs)
    files = [('/bin/sh', inputs / 'pelt/pelt', 755), ('/bin/cat', inputs / 'bore/cat', 755), ('/bin/env', inputs / 'bore/env', 755),
             ('/bin/sniff-server', Path(a.server), 755)]
    for prog in sorted({pax_target(r)[0] for r in rows}):
        files.append((sp.GUEST_FX + '/' + prog, Path(a.fixtures) / prog, 755))
    rows_sh, run_line, net = out / 'rows.sh', out / 'pax-run', out / 'pax-net'
    rows_sh.write_text(pax_guest_script(rows, sp.GUEST_FX))
    run_line.write_text('/bin/env HOME=/ /bin/sh -i\n')
    net.write_text('static %s/24 gateway 10.0.2.2 dns 10.0.2.3\n' % PAX_GUEST_IP)
    files += [('/etc/rows.sh', rows_sh, 644), ('/etc/pax-run', run_line, 644), ('/etc/pax-net', net, 644)]
    missing = [str(s) for _d, s, _m in files if not Path(s).is_file()]
    if missing:
        print('FAIL remote-server-pax-image missing %s' % ', '.join(missing))
        return 1
    cpio, iso = out / 'server.cpio', out / 'server.iso'
    for what, cmd in (('mkinitramfs', [str(pax / 'tools/mkinitramfs'), str(cpio), '/tmp/:1777'] + ['%s=%s:%s' % f for f in files]),
                      ('mkimage', [str(pax / 'tools/mkimage'), '--conf', str(pax / 'boot/limine-initramfs-quiet.conf'), '--add',
                                   str(cpio), 'initramfs.cpio', str(a.kernel), str(iso)])):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout[-1500:], r.stderr[-1500:])
            print('FAIL remote-server-pax-image %s exit=%d' % (what, r.returncode))
            return 1
    (out / 'server.keys').write_text('/bin/sh /etc/rows.sh; exit\n')
    m = {'rows': [r['name'] for r in rows], 'iso_sha256': file_sha(iso), 'sniff_server_sha256': file_sha(a.server),
         'kernel_sha256': file_sha(a.kernel)}
    (out / 'manifest.json').write_text(json.dumps(m, indent=1) + '\n')
    print('PASS remote-server-pax-image rows=%d iso_sha256=%s sniff_server_sha256=%s kernel_sha256=%s' %
          (len(rows), m['iso_sha256'], m['sniff_server_sha256'], m['kernel_sha256']))
    return 0


def cmd_server_pax(a):
    """The server rows on PAX: gdbserver's transcripts on Linux first, then one boot of the image, each row reached in
    the image's order, then every row's verdict by name."""
    sp = load_session_pax()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = load_rows(a.only, 'server-pax')
    image = Path(a.image)
    m = json.loads((image / 'manifest.json').read_text())
    summary = 'remote rows (server-pax, %s): %d pass, %d fail, %d skip'
    if m['rows'] != [r['name'] for r in rows] or file_sha(image / 'server.iso') != m['iso_sha256']:
        print('FAIL remote-server-pax-image the image holds rows %s (iso %s), not these %s' % (m['rows'], m['iso_sha256'], [r['name'] for r in rows]))
        print(summary % (a.accel, 0, 1, 0))
        return 1
    line, problems = qemu_line(a)
    print(line)
    if problems:
        print('FAIL remote-qemu-pin ' + '; '.join(problems))
        print(summary % (a.accel, 0, 1, 0))
        return 1
    print(oracle_line())
    print('IMAGE server.iso sha256 %s, sniff-server sha256 %s, kernel sha256 %s' % (m['iso_sha256'], m['sniff_server_sha256'], m['kernel_sha256']))
    theirs = {}
    for r in rows:
        if r['check'] == 'pax-session':
            prog, args, cmds = session_script(r['row'])
            theirs[r['name']] = gdb_through(a, 'gdbserver', Path(a.fixtures) / prog, args, cmds, out, r['name'] + '.gdbserver')
    port = free_port()
    serial = out / 'boot.serial'
    for d in ('qemu', 'tmp'):
        (out / d).mkdir(parents=True, exist_ok=True)
    qenv = dict(os.environ)
    qenv.update({'PAX_QEMU': a.qemu, 'PAX_BUILD': str(out / 'qemu'), 'TMPDIR': str(out / 'tmp'), 'SHELL': '/bin/sh'})
    netdev = 'user,id=n0,ipv6=off,hostfwd=tcp:127.0.0.1:%d-%s:%d' % (port, PAX_GUEST_IP, PAX_GUEST_PORT)
    cmd = [str(Path(a.pax) / 'tools/qemu-halt'), '--firmware', 'bios', '--serial', str(serial), '--timeout', str(a.timeout),
           '--accel', a.accel, '--qemu', '-m', '--qemu', '4096M', '--qemu', '-netdev', '--qemu', netdev,
           '--qemu', '-device', '--qemu', 'virtio-net-pci,netdev=n0,mac=%s,id=nic0' % PAX_MAC,
           '--elf', str(a.kernel), '--marker', 'halt|PANIC .*', '--type', str(image / 'server.keys'), '--prompt', '$ ',
           str(image / 'server.iso')]
    print('RUN ' + ' '.join(cmd), flush=True)
    q = subprocess.Popen(cmd, stdout=open(out / 'qemu-halt.out', 'w'), stderr=subprocess.STDOUT, env=qenv)
    mine, reached = {}, {}
    for k, r in enumerate(rows):
        if not pax_wait_listening(serial, k + 1, q, PAX_BOOT_S if k == 0 else PAX_RETRY_FOR_S):
            break
        name = r['name']
        ended = lambda name=name: name in pax_served(serial.read_text(errors='replace'), sp)
        if r['check'] == 'pax-session':
            prog, _args, cmds = session_script(r['row'])
            def attempt(prog=prog, cmds=cmds):
                t = gdb_at(port, Path(a.fixtures) / prog, cmds)
                return t, pax_gdb_failed_to_connect(t)
        else:
            attempt = lambda: pax_fp_refused(port)
        got, n, took = pax_retry(attempt, ended)
        mine[name], reached[name] = got, (n, took)
        if r['check'] == 'pax-session' and got is not None:
            (out / (name + '.sniff-server.txt')).write_text(got)
    try:
        rc = q.wait(timeout=a.timeout + 60)
    except subprocess.TimeoutExpired:
        print('qemu-halt %d still running 60 s after its own timeout: TERM to its recorded pid' % q.pid)
        q.terminate()
        rc = q.wait(timeout=30)
    print('qemu-halt exit=%s' % rc)
    served = pax_served(serial.read_text(errors='replace') if serial.exists() else '', sp)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    bound = 'retry every %.1f s for up to %.0f s, twenty times the %.1f s measured' % (PAX_RETRY_EVERY_S, PAX_RETRY_FOR_S, PAX_MEASURED_S)
    for r in rows:
        name = r['name']
        why = ''
        if name not in reached:
            why = FAULT + 'never reached: its stub never said it was listening on the console'
        elif mine[name] is None:
            why = FAULT + 'no answer: %d attempts in %.1f s (%s)' % (reached[name][0], reached[name][1], bound)
        elif name not in served:
            why = FAULT + 'its stub did not end on the console'
        elif served[name][1] != '0':
            why = FAULT + 'sniff-server on PAX exited %s: %s' % (served[name][1], ' | '.join(served[name][0][-3:]))
        elif r['check'] == 'pax-session':
            if theirs.get(name) is None:
                why = FAULT + 'no oracle: gdbserver never listened, or gdb did not end'
            else:
                why = first_diff(pax_normalise(theirs[name]), pax_normalise(mine[name]))
        elif mine[name] != PAX_FP_WANT:
            why = 'answers %r, not %r' % (mine[name], PAX_FP_WANT)
        if why:
            if name in reached:
                why += ' (gdb connected at attempt %d, %.1f s after the first)' % reached[name]
            print('FAIL remote %s %s' % (name, why))
            for line in (served.get(name, ([], ''))[0] or ['(no console lines between its markers)'])[-12:]:
                print('CONSOLE %s | %s' % (name, line))
            counts['fail'] += 1
            continue
        n, took = reached[name]
        held = ('gdb through sniff-server on PAX equals gdb through gdbserver on Linux (%d lines; normalised: %s, stack)' %
                (len(mine[name].splitlines()), ', '.join(x for x, _rx, _to in SESSION_NORMALISE))
                if r['check'] == 'pax-session' else 'PAX refuses the SSE write by name: %r' % mine[name])
        print('PASS remote %s [%s; connected at attempt %d, %.1f s after the first, %s]' % (name, held, n, took, bound))
        counts['pass'] += 1
    if rc != 0:
        print('FAIL remote-server-pax-boot qemu-halt exit=%s (its verdict: qemu-halt.out)' % rc)
        counts['fail'] += 1
    print(summary % (a.accel, counts['pass'], counts['fail'], counts['skip']))
    return 1 if counts['fail'] else 0


def oracle_line():
    """The pinned gdbserver and gdb this host runs, by version and digest (each server run names them)."""
    import hashlib
    parts = []
    for name in ('gdbserver', 'gdb'):
        path = shutil.which(name)
        if path is None:
            parts.append('%s absent' % name)
            continue
        real = os.path.realpath(path)
        v = subprocess.run([real, '--version'], capture_output=True, text=True).stdout.splitlines()
        parts.append('%s %r sha256 %s' % (name, v[0] if v else '?', hashlib.sha256(Path(real).read_bytes()).hexdigest()))
    return 'ORACLES ' + '; '.join(parts)


def cmd_server(a):
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    checks = {'refuse-second': check_refuse_second, 'refuse-non-loopback': check_refuse_non_loopback,
              'loopback-default': check_loopback_default, 'idle-cost': check_idle_cost,
              'interrupt-latency': check_interrupt_latency, 'z1-hbreak': check_z1_hbreak, 'fp-write': check_fp_write,
              'fp-tag': check_fp_tag, 'detach': check_detach, 'native-golden': check_native_golden,
              'threads': check_threads, 'gdb-session': check_gdb_session, 'oracle-stable': check_oracle_stable}
    print(oracle_line())
    for row in load_rows(a.only, 'server'):
        if row.get('skip'):
            print('SKIP remote %s reason=%s' % (row['name'], row['skip']))
            counts['skip'] += 1
            continue
        if not Path(a.server).is_file():
            print('FAIL remote %s no sniff-server at %s' % (row['name'], a.server))
            counts['fail'] += 1
            continue
        why, held = run_check(checks[row['check']], a, row, out)
        if why:
            print('FAIL remote %s %s' % (row['name'], why))
            counts['fail'] += 1
        else:
            print('PASS remote %s [%s]' % (row['name'], held))
            counts['pass'] += 1
    print('remote rows (server): %d pass, %d fail, %d skip' % (counts['pass'], counts['fail'], counts['skip']))
    return 1 if counts['fail'] else 0


def cmd_selftest(_a):
    sess = load_session()
    t = normalise('(gdb) Remote debugging using 127.0.0.1:41001\r\n0x000000000000fff0 in ?? ()\r\n(gdb) ', 41001, Path('/k/kmain_console.elf'), sess)
    assert t == 'Remote debugging using 127.0.0.1:PORT\n0x000000000000fff0 in ?? ()\n', repr(t)
    t = normalise('Detaching from program: /k/kmain_console.elf, process 1\r\n', 0, Path('/k/kmain_console.elf'), sess)
    assert t == 'Detaching from program: KERNEL, process 1\n', repr(t)
    assert script_lines({'script': ['target remote 127.0.0.1:@PORT@', '!interrupt 5 continue']}, 7) == ['target remote 127.0.0.1:7', '!interrupt 5 continue']
    assert first_diff('a\nb\n', 'a\nc\n') == "line 2: want 'b' got 'c'"
    w = normalise('Old value = 0\r\nNew value = 10468460\r\n', 0, Path('/k'), sess, ['watch-values'])
    assert w == 'Old value = <VALUE>\nNew value = <VALUE>\n', repr(w)
    # stop-location: the frame a connect after a detach prints, in either of gdb's two frame forms
    let_go = '[Inferior 1 (process 1) detached]\r\nRemote debugging using 127.0.0.1:41001\r\n'
    end = '[Inferior 1 (process 1) killed]\r\n'
    def loc(text):
        return normalise(text, 41001, Path('/k'), sess, ['stop-location'])
    gold_s = loc(let_go + '0xffffffff800001e3 in pax_inb ()\r\n' + end)
    want_s = '[Inferior 1 (process 1) detached]\nRemote debugging using 127.0.0.1:PORT\n<LOCATION>\n[Inferior 1 (process 1) killed]\n'
    assert gold_s == want_s, 'stop-location, the form 0x... in NAME (ARGS): ' + repr(gold_s)
    with_line = loc(let_go + '0xffffffff80142b2d in smp.hold () at ./smp/smp.lu:273\r\n273\t        x = 1\r\n' + end)
    assert with_line == want_s, 'stop-location, the form 0x... in NAME (ARGS) at FILE:LINE and its source line: ' + repr(with_line)
    at_line = loc(let_go + 'boot_info.cmdline_has () at ./boot_info/boot_info.lu:184\r\n184\t                if x {\r\n' + end)
    assert at_line == want_s, 'stop-location, the form NAME (ARGS) at FILE:LINE and its source line: ' + repr(at_line)
    signalled = loc(let_go + '\r\nProgram received signal SIGTRAP, Trace/breakpoint trap.\r\n0xffffffff80000786 in pax_idle ()\r\n' + end)
    assert signalled == want_s.replace('<LOCATION>', '\nProgram received signal SIGTRAP, Trace/breakpoint trap.\n<LOCATION>'), \
        'stop-location keeps the signal line it follows: ' + repr(signalled)
    # a line in neither form stays as it came, and so differs from the golden; so does a missing line
    for name, text in (
            ('a line in neither form', let_go + 'Cannot access memory at address 0xffffffff800001e3\r\n' + end),
            ('a frame from a library', let_go + '0xffffffff800001e3 in pax_inb () from /lib/x.so\r\n' + end),
            ('a bare name', let_go + 'pax_inb\r\n' + end),
            ('a frame at a line without its source line', let_go + 'boot_info.cmdline_has () at ./boot_info/boot_info.lu:184\r\n' + end),
            ('a source line of another line', let_go + 'boot_info.cmdline_has () at ./boot_info/boot_info.lu:184\r\n185\t    y\r\n' + end),
            ('a missing frame line', let_go + end),
            ('a missing signal line', let_go + '0xffffffff80000786 in pax_idle ()\r\n' + end),
            ('a missing connect line', '[Inferior 1 (process 1) detached]\r\n0xffffffff800001e3 in pax_inb ()\r\n' + end)):
        got = loc(text)
        gold = signalled if name == 'a missing signal line' else gold_s
        assert first_diff(gold, got), 'stop-location hid %s: %r' % (name, got)
    # a connect that no detach came before keeps its frame: the machine was at reset, frozen
    first = loc('Remote debugging using 127.0.0.1:41001\r\n0x000000000000fff0 in ?? ()\r\n')
    assert first == 'Remote debugging using 127.0.0.1:PORT\n0x000000000000fff0 in ?? ()\n', 'stop-location took a first connect: ' + repr(first)
    gold_w = normalise('Hardware watchpoint 2: *(unsigned long *) 0xffffffff80652068\r\n\r\nOld value = 0\r\nNew value = 1\r\n', 0, Path('/k'), sess, ['watch-values'])
    no_hit = normalise('Old value = 0\r\nNew value = 1\r\n', 0, Path('/k'), sess, ['watch-values'])
    assert first_diff(gold_w, no_hit), 'a missing watchpoint line was hidden'
    no_new = normalise('Hardware watchpoint 2: *(unsigned long *) 0xffffffff80652068\r\n\r\nOld value = 0\r\n', 0, Path('/k'), sess, ['watch-values'])
    assert first_diff(gold_w, no_new), 'a missing new value was hidden'
    # a QEMU that is not the pin for this host is refused by name: its version line, then its binary's digest
    pin_line, pin_sha = 'QEMU emulator version 11.1.2', 'b5cb670e0eda020fba60bb3249226d7ae424695fe2d190ad3ff76de1abcef447'
    assert qemu_problems(pin_line, pin_sha, pin_line, pin_sha) == []
    assert qemu_problems('QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)', pin_sha, pin_line, pin_sha) == \
        ["qemu-version 'QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)' is not the pin's 'QEMU emulator version 11.1.2'"], 'a QEMU of another version was taken'
    assert qemu_problems(pin_line, '0' * 64, pin_line, pin_sha) == ['qemu-sha256 %s is not the pin\'s %s' % ('0' * 64, pin_sha)], 'a QEMU of another build was taken'
    assert qemu_pin('Linux')[1] != qemu_pin('Darwin')[1] and qemu_pin('Linux')[0] == pin_line
    rows = json.loads(ROWS.read_text())['rows']
    names = [r['name'] for r in rows]
    assert len(names) == len(set(names)), 'duplicate row names'
    assert frame('qC') == b'$qC#b4' and frame('') == b'$#00'
    # the cost and latency rows' verdicts, held red on planted numbers
    assert cost_problems(0, 0, 10.0) == [] and cost_problems(0, 2, 14.9) == []
    assert cost_problems(1, 0, 10.0) and cost_problems(0, 3, 10.0) and cost_problems(0, 0, 15.1)
    assert latency_problems('T02thread:4d2;', 0.12) == []
    assert latency_problems('T02thread:4d2;', 0.51) and latency_problems('T05thread:4d2;', 0.1) and latency_problems(None, 0.1)
    for r in [r for r in rows if r.get('kind') == 'server']:
        assert r['name'].startswith('server-') and r.get('check') in SERVER_CHECKS, r['name']
        if r['check'] in ('gdb-session', 'oracle-stable', 'native-golden'):
            assert session_script(r['row']) is not None and r.get('why'), 'a session row names one plain session row: ' + r['name']
        else:
            assert r.get('prog', '').startswith('c/') and r.get('why'), 'a server row names its fixture and says what it holds: ' + r['name']
    n = session_normalise('Reading /usr/lib/debug/.build-id/a0/ab.debug from remote target...\n[Inferior 1 (process 19) killed]\n'
                          'Remote debugging using 127.0.0.1:41234\n* 1    Thread 77.78 "prog" main ()\n'
                          'warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.\n')
    assert n == '[Inferior 1 (INFERIOR) killed]\nRemote debugging using 127.0.0.1:PORT\n* 1    Thread TID "prog" main ()\n', repr(n)
    assert session_normalise('[Inferior 1 (Remote target) killed]\n') == '[Inferior 1 (INFERIOR) killed]\n'
    # the native golden's two drops, each from the stub's side only, and nothing else
    s = native_normalise('0x0000000000401740 in _start ()\nBreakpoint 1 at 0x4018d9: file m.c, line 20.\n'
                         '0x0000000000401e58 in __libc_start_call_main ()\n[Inferior 1 (Remote target) killed]\n')
    assert s == 'Breakpoint 1 at 0x4018d9: file m.c, line 20.\n0x0000000000401e58 in __libc_start_call_main ()\n', repr(s)
    assert native_normalise('x\n0x0000000000401740 in _start ()\n') == 'x\n0x0000000000401740 in _start ()\n'
    assert len([r for r in rows if r.get('check') == 'native-golden']) == 1, 'one fixture is held to its native golden'
    # replies decoded as the manual's Overview says: run-length encoding ('0* ' is 0000, '0*"00' is 00000000) and the
    # '}' escape (the next byte XOR 0x20)
    assert decode_reply('0* ') == '0000' and decode_reply('0*"00') == '00000000' and decode_reply('a}]b') == 'a}b'
    left, right = socket.socketpair()
    try:
        enc = b'1*!ff* '
        left.sendall(b'+$' + enc + b'#' + ('%02x' % (sum(enc) % 256)).encode())
        assert read_packet(right, 2.0) == '1111ffff', 'read_packet decodes the reply'
    finally:
        left.close()
        right.close()
    # a refusal's command that never exits is a comparison (still running, not refused), never an exception
    rc, err, running = refusal_run([sys.executable, '-c', 'import time; time.sleep(30)'], 1.0)
    assert running and rc is None, (rc, running)
    rc, err, running = refusal_run([sys.executable, '-c', 'import sys; sys.stderr.write("no"); sys.exit(2)'], 5.0)
    assert not running and rc == 2 and err == 'no', (rc, err, running)
    # a red is the row's own comparison: a driver exception, a stub that never listened, and either side's silence
    # are faults by name, never a comparison's FAIL
    def broken(_a, _row, _out):
        raise BrokenPipeError(32, 'Broken pipe')
    assert run_check(broken, None, {}, None)[0].startswith(FAULT), run_check(broken, None, {}, None)
    assert compare({'g': None}, {'g': '00'}, 'w')[0].startswith(FAULT) and compare({'g': '00'}, {'g': None}, 'w')[0].startswith(FAULT)
    assert not compare({'g': '01'}, {'g': '00'}, 'w')[0].startswith(FAULT) and compare({'g': '01'}, {'g': '00'}, 'w')[0]
    assert compare({'Z1': '', 'stop': '-'}, {'Z1': 'OK', 'stop': 'T05'}, 'w')[0].startswith('w: sniff-server ')
    assert compare({'g': '00'}, {'g': '00'}, 'w') == ('', "w equal to gdbserver's: {'g': '00'}")
    # a thread list may come one id a reply (qfThreadInfo, then qsThreadInfo until `l`), as gdbserver gives it
    replies = iter(['m5f3', 'm5f4', 'm5f5', 'l'])
    assert thread_ids(lambda q: next(replies)) == ['5f3', '5f4', '5f5']
    replies = iter(['m4d2,4d3', 'l'])
    assert thread_ids(lambda q: next(replies)) == ['4d2', '4d3']
    assert thread_ids(lambda q: None) is None and thread_ids(lambda q: '') == []
    # registers by g and G (gdbserver answers p and P with the empty reply): fields at the description's byte offsets
    g = '00' * G_RIP + '7740400000000000' + '00' * 400
    assert g_field(g, G_RIP, 8) == 0x404077 and g_with(g, G_RIP, '01').startswith('00' * G_RIP + '01404000')
    assert (G_RIP, G_FCTRL, G_FTAG, G_XMM0) == (128, 244, 252, 276)
    # the spinning threads' pcs and the thread table's padding, named
    a = session_normalise('  Id   Target Id             Frame \n* 1    Thread 595.595 "prog" 0x00000000004019c2 in spin (flag=1)\n')
    b = session_normalise('  Id   Target Id         Frame \n* 1    Thread 595 "prog" 0x00000000004019d8 in spin (flag=1)\n')
    assert a == b, (a, b)
    assert stable_normalise('  2    Thread 7.8 "prog" 0x00000000004019c2 in spin (x)\n') == stable_normalise('  2    Thread 7.8 "prog" 0x00000000004019d8 in spin (x)\n')
    # the packet driver opens as the pinned gdb does (its remote log: `?`, then Hg for the thread the stop names)
    assert hg_for('T05thread:4d2;') == 'Hg4d2' and hg_for('T0506:00;07:90;thread:p13.13;core:5;') == 'Hgp13.13'
    assert hg_for('W00') is None and hg_for(None) is None
    # an oracle that gave no reply is no comparison
    assert oracle_silent({'Z1': None, 'stop': 'T05'}) and not oracle_silent({'Z1': '', 'stop': 'T05'})
    # gdbserver's per-run ids, named in its own stability check as in the session rows
    assert stable_normalise('[New Thread 595.608]\n[Inferior 1 (process 595) exited normally]\n') == \
        stable_normalise('[New Thread 612.625]\n[Inferior 1 (process 612) exited normally]\n')
    # on PAX the initial stack is the kernel's, not Linux's: the PAX set's own stack rule, by name
    assert pax_normalise('0x7fffffffeb50:\t0x00000001\t0x00000002\n') == pax_normalise('0x7fffffffece0:\t0x00000001\t0x00000002\n')
    assert pax_normalise('0x404028 <cell>:\t0x01\n') == '0x404028 <cell>:\t0x01\n'
    # the retry's report is when the attempt that connected began (two failures, two 0.5 s waits), not its session's end
    tries = []
    def attempt():
        tries.append(1)
        if len(tries) < 3:
            return None, True
        time.sleep(0.3)
        return 'ok', False
    got, n, took = pax_retry(attempt, lambda: False)
    assert got == 'ok' and n == 3 and 0.95 <= took < 1.2, (got, n, took)
    for r in [r for r in rows if r.get('kind') == 'server-pax']:
        assert r['name'].startswith('server-pax-') and r.get('check') in PAX_CHECKS and r.get('why'), r['name']
        if r['check'] == 'pax-session':
            assert session_script(r['row']) is not None, 'a PAX session row names one plain session row: ' + r['name']
        else:
            assert r.get('prog', '').startswith('c/'), 'a PAX row names its fixture: ' + r['name']
    g = pax_guest_script([{'name': 'server-pax-x', 'check': 'pax-fp-refused', 'prog': 'c/calls/gcc-O0/prog', 'args': ['3']}], '/fx')
    assert g == ("printf '%s\\n' '@@SERVE server-pax-x'\n/bin/sniff-server --non-loopback 0.0.0.0:1234 /fx/c/calls/gcc-O0/prog 3\n"
                 "printf '%s\\n' \"@@SERVED $?\"\n"), repr(g)
    sp = load_session_pax()
    got = pax_served('$ /bin/sh /etc/rows.sh; exit\r\n@@SERVE a\r\nProcess p created; pid = 9\r\n\x1b[0mListening on 0.0.0.0:1234\r\n'
                     '@@SERVED 0\r\n@@SERVE b\r\nListening on 0.0.0.0:1234\r\n', sp)
    assert got == {'a': (['Process p created; pid = 9', 'Listening on 0.0.0.0:1234'], '0')}, repr(got)
    assert pax_gdb_failed_to_connect('Remote debugging using 127.0.0.1:5\nRemote connection closed\n')
    assert not pax_gdb_failed_to_connect('Remote debugging using 127.0.0.1:5\n0x0000000000401650 in _start ()\n')
    assert not pax_gdb_failed_to_connect(None)
    for r in [r for r in rows if r.get('kind', 'kernel') == 'kernel']:
        assert r['name'].startswith(('remote-kernel-', 'remote-refuse-')), r['name']
        assert r.get('accel') in (None, 'kvm', 'tcg'), r['name']
        assert set(r.get('normalise', [])) <= {'watch-values', 'stop-location'}, r['name']
        assert not (r.get('skip') and r.get('own') is not None), r['name']
        if r.get('skip'):
            assert '\n' not in r['skip'] and r['skip'].strip(), 'a skip names its reason in one line: ' + r['name']
        if r.get('own') is not None:
            assert isinstance(r['own'], list) and r.get('why'), 'an own row says why gdb is not its oracle: ' + r['name']
        assert isinstance(r['script'], list) and r['script'], r['name']
        assert not any('xml-tdesc' in line for line in r['script']), 'a row may not print QEMU\'s description: ' + r['name']
    print('PASS session-remote-selftest rows=%d (kernel %d, server %d, server-pax %d)' % (
        len(rows), len(load_rows(None)), len(load_rows(None, 'server')), len(load_rows(None, 'server-pax'))))
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
    sv = sub.add_parser('server')
    sv.add_argument('--server', required=True, help='the sniff-server binary')
    sv.add_argument('--fixtures', required=True, help='the static session fixtures')
    sv.add_argument('--only')
    sv.add_argument('--out', default=str(ROOT / 'target/server-out'))
    pi = sub.add_parser('server-pax-image')
    for name, what in (('--pax', 'the PAX tree (its image tools)'), ('--kernel', "PAX's console kernel"),
                       ('--inputs', 'pelt and boreutils, built as the PAX harness builds them'),
                       ('--server', 'sniff-server built static'), ('--fixtures', 'the static session fixtures')):
        pi.add_argument(name, required=True, help=what)
    pi.add_argument('--only')
    pi.add_argument('--out', default=str(ROOT / 'target/server-pax-image'))
    ps = sub.add_parser('server-pax')
    for name, what in (('--image', "server-pax-image's output"), ('--pax', 'the PAX tree (tools/qemu-halt)'),
                       ('--kernel', "PAX's console kernel"), ('--qemu', 'the pinned QEMU'), ('--fixtures', 'the static session fixtures')):
        ps.add_argument(name, required=True, help=what)
    ps.add_argument('--accel', choices=('kvm',), default='kvm')
    ps.add_argument('--timeout', type=int, default=900, help="qemu-halt's own bound on the boot, in seconds")
    ps.add_argument('--only')
    ps.add_argument('--out', default=str(ROOT / 'target/server-pax-out'))
    sk = sub.add_parser('skip')
    sk.add_argument('--kind', choices=('kernel', 'server', 'server-pax'), default='kernel')
    sk.add_argument('--reason', required=True)
    sk.add_argument('--expect', type=int, help='the held number of rows, refused by name when the row file differs')
    sub.add_parser('selftest')
    a = p.parse_args()
    if a.mode == 'skip':
        return cmd_skip(a)
    if a.mode == 'selftest':
        return cmd_selftest(a)
    if a.mode == 'server':
        return cmd_server(a)
    if a.mode == 'server-pax-image':
        return cmd_server_pax_image(a)
    if a.mode == 'server-pax':
        return cmd_server_pax(a)
    return cmd_run(a)


if __name__ == '__main__':
    sys.exit(main())
