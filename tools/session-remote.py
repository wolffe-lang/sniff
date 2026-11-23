#!/usr/bin/env python3
"""S8's kernel rows: the pinned gdb and sniff over QEMU's gdbstub on PAX's console kernel, at one processor.

  session-remote.py capture --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --gdb GDB --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py check   --kernel ELF --image ISO --pax PAXTREE --qemu QEMU --sniff SNIFF --accel kvm|tcg [--only RE] [--out DIR]
  session-remote.py gdb-check (as check, with --gdb: the goldens hold for this accelerator and this run)
  session-remote.py skip --reason TEXT [--expect N]   one SKIP line a row and the count (held at N), where no
                                            kernel image is
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
    # a row's kind: the kernel rows (sniff or gdb over QEMU's gdbstub) unless it says server (sniff-server's rows)
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
SERVER_CHECKS = ('refuse-second', 'refuse-non-loopback', 'loopback-default', 'idle-cost', 'interrupt-latency')
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
            return 'sniff-server never said it was listening', ''
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
            return 'sniff-server never said it was listening', ''
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
        return 'sniff-server never said it was listening', ''
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
        return 'sniff-server never said it was listening', ''
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


def cmd_server(a):
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    checks = {'refuse-second': check_refuse_second, 'refuse-non-loopback': check_refuse_non_loopback,
              'loopback-default': check_loopback_default, 'idle-cost': check_idle_cost,
              'interrupt-latency': check_interrupt_latency}
    for row in load_rows(a.only, 'server'):
        if row.get('skip'):
            print('SKIP remote %s reason=%s' % (row['name'], row['skip']))
            counts['skip'] += 1
            continue
        if not Path(a.server).is_file():
            print('FAIL remote %s no sniff-server at %s' % (row['name'], a.server))
            counts['fail'] += 1
            continue
        try:
            why, held = checks[row['check']](a, row, out)
        except (OSError, subprocess.SubprocessError) as e:
            why, held = '%s: %s' % (type(e).__name__, e), ''
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
        assert r.get('prog', '').startswith('c/') and r.get('why'), 'a server row names its fixture and says what it holds: ' + r['name']
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
    print('PASS session-remote-selftest rows=%d (kernel %d, server %d)' % (len(rows), len(load_rows(None)), len(load_rows(None, 'server'))))
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
    sk = sub.add_parser('skip')
    sk.add_argument('--kind', choices=('kernel', 'server'), default='kernel')
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
    return cmd_run(a)


if __name__ == '__main__':
    sys.exit(main())
