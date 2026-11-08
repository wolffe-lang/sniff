#!/usr/bin/env python3
"""S2 live session rows: sniff against recorded gdb transcripts.

A row is a program from the session fixtures and a command script. `capture`
runs the pinned gdb on every row and stores its stdout, stderr and exit status
as the golden. `check` runs sniff on every row and compares with the golden
after the named normalisations. `verify` (no process, any host) checks that
rows and goldens agree. A row that did not run is reported as SKIP and is
never a pass.

Normalisations, each named in every PASS/FAIL line only when it fired:
  pid     the N of 'process N' ('(process N)', 'child process N', a Target Id, the attach, detach and
          already-traced lines): an allocation order, not a debugger fact
  banner  gdb's two thread_db lines are dropped from the golden
  lwp     an LWP id becomes <Ln>, n counting the distinct ids in the order they first appear, so a
          thread's lines still name one thread
  spin    the workers fixture's spinning threads stop anywhere in a one-line loop, so 'spin (' may follow
          '0x... in ' or not; the address is dropped
  threads-table  'info threads': the header's and the Target Id column's padding, which follows the
          ids' digits, become one space
  ticks   (rows that name it in "normalise") the tick a breakpoint after an attach lands on: the
          sleeper's progress when the debugger arrived
  tty     (tty rows) carriage returns and the prompt text
  wrap80  (tty rows) gdb's 80-column wrap of a long frame line ("\n    at ")
  heap    (PAX set) an address in the program's break becomes <HEAP>. A static program's break starts
          at the page above its highest loaded byte on Linux (its random offset is off under both
          debuggers) and on PAX (kernel/vm's `start`), and PAX refuses a break more than 64 MiB above
          that. What the runtime allocated there first depends on the arguments and environment it
          was given, which gdb's inferior on Linux and PAX's console do not share.
Terminal rows run both debuggers in a pseudo-terminal with echo off and send
one command per prompt, as R-sn02-1 specifies.

Attach rows ("attach": {...}) start the row's program, the sleeper, as this harness's own child with
address randomisation off (as both debuggers start their own programs), read its 'ready PID' line, put
the pid in the script for {pid}, run the debugger, and append how the sleeper ended to stdout:
'[sleeper exited with code N: LAST LINE]' or '[sleeper killed by signal N]'. "ticks" is the sleeper's
argument; "form" is "script" (the default), "dash-p" (-p PID before the program) or "positional"
(PROG PID); "held" first starts the holder fixture of the same build on the sleeper, so that another
tracer has it.

A row compares standard output byte for byte unless its "compare" says otherwise
(standard error and the exit status are always compared with the golden's):
  head    the first "head" lines are gdb's, byte for byte, and sniff prints more after
          them, in its own words; "why" says what gdb's text describes that sniff lacks
  subset  every line sniff prints is one of gdb's, in gdb's order, or one of the row's
          "own" lines, each of which sniff must print; sniff prints something
  own     sniff's text is the row's "expect" lines (and "expect_err", "expect_rc" when
          given), and the golden shows gdb answering the command with text and status 0
          (or, with "gdb": "lacks", refusing it: a command of sniff's own; with "gdb": "refuses",
          refusing it too, in words sniff does not share: "why" says whose words differ and why)
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / 'tests/session-rows.json'
GOLD = ROOT / 'tests/evidence/linux-s2'
# S4: the same rows on static ET_EXEC builds (all PAX loads), with goldens captured from the pinned gdb on those
# builds. tests/pax-rows.json overrides a row's script, names the lines it drops and names a row's SKIP.
PAX_GOLD = ROOT / 'tests/evidence/pax-linux'
PAX_ROWS = ROOT / 'tests/pax-rows.json'
PAX_MODE = False
STACK_HEX = re.compile(r'0x7ff[0-9a-f]{9}\b')
# a thread's address is its C library's thread record, at the top of a stack the library mapped: where the
# kernel puts that mapping is the kernel's (PAX maps it below Linux's 0x7ff... range)
THREAD_ADDR = re.compile(r'\bThread 0x[0-9a-f]+ \(LWP ')
STACK_DEC = re.compile(r'\b140[67][0-9]{11}\b')
HEX = re.compile(r'\b0x[0-9a-f]+\b')
# where each row's prog is (set by main and by session-pax.py), for the heap normalisation
FIXTURES = None
HEAPS = {}
SCRIPTS = 'target/s2'
ENV_BASE = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}


def use_pax():
    """Select the PAX row set: static builds, their own goldens."""
    global GOLD, PAX_MODE
    GOLD = PAX_GOLD
    PAX_MODE = True


def load_rows(only=None):
    rows = json.loads(ROWS.read_text())['rows']
    if PAX_MODE:
        over = json.loads(PAX_ROWS.read_text())['rows']
        unknown = sorted(set(over) - {r['name'] for r in rows})
        if unknown:
            raise SystemExit('FAIL session-rows: pax override for no row: ' + ', '.join(unknown))
        merged = []
        for r in rows:
            o = over.get(r['name'], {})
            merged.append(dict(r, **{k: v for k, v in o.items()}))
        rows = merged
    if only:
        rows = [r for r in rows if re.search(only, r['name'])]
    names = [r['name'] for r in rows]
    if len(set(names)) != len(names):
        raise SystemExit('FAIL session-rows: duplicate row names')
    return rows


def heap_range(prog):
    """The break's range of a static ELF64 ET_EXEC: the page above its highest PT_LOAD byte, and 64 MiB up.
    None for anything else."""
    if prog in HEAPS:
        return HEAPS[prog]
    r = None
    try:
        with open(prog, 'rb') as f:
            h = f.read(64)
            if len(h) == 64 and h[:4] == b'\x7fELF' and h[4] == 2 and h[5] == 1 and struct.unpack_from('<H', h, 16)[0] == 2:
                phoff = struct.unpack_from('<Q', h, 32)[0]
                phentsize, phnum = struct.unpack_from('<HH', h, 54)
                f.seek(phoff)
                ph = f.read(phentsize * phnum)
                top = 0
                for i in range(phnum):
                    p_type, _, _, vaddr, _, _, memsz = struct.unpack_from('<IIQQQQQ', ph, i * phentsize)
                    if p_type == 1:
                        top = max(top, vaddr + memsz)
                if top:
                    lo = (top + 0xfff) & ~0xfff
                    r = (lo, lo + 0x4000000)
    except (OSError, struct.error):
        r = None
    HEAPS[prog] = r
    return r


LWP = re.compile(r'\bLWP (\d+)\b')
SPIN = re.compile(r'\b0x[0-9a-f]+ in spin \(')
THREADS_HEAD = re.compile(r'^  Id +Target Id +Frame ?$', re.M)
THREADS_ROW = re.compile(r'^([* ]) (\d+) +(Thread (?:0x[0-9a-f]+|<STACK>) \(LWP <L\d+>\)|LWP <L\d+>|process <PID>)( "[^"]*")? +(\S.*)$', re.M)
TICK = re.compile(r'\btick \(n=\d+\)')


def normalize(text, fired, row=None):
    out = []
    lwps = {}
    drops = [re.compile(d) for d in (row or {}).get('drop', [])] if PAX_MODE else []
    heap = heap_range(str(Path(FIXTURES) / row['prog'])) if PAX_MODE and FIXTURES and row and row.get('prog') else None
    for line in text.splitlines(keepends=True):
        if PAX_MODE:
            m = STACK_DEC.sub('<STACK>', STACK_HEX.sub('<STACK>', line))
            if m != line:
                fired.add('stack')
                line = m
            if heap:
                m = HEX.sub(lambda x: '<HEAP>' if heap[0] <= int(x.group(0), 16) < heap[1] else x.group(0), line)
                if m != line:
                    fired.add('heap')
                    line = m
            # after the heap's: a static program's main thread keeps its record in the heap
            m = THREAD_ADDR.sub('Thread <STACK> (LWP ', line)
            if m != line:
                fired.add('thread-map')
                line = m
        if any(d.search(line) for d in drops):
            fired.add('drop')
            continue
        if line.startswith('[Thread debugging using libthread_db enabled]') or \
           line.startswith('Using host libthread_db library'):
            fired.add('banner')
            continue
        n = re.sub(r'\bprocess \d+\b', 'process <PID>', line)
        if n != line:
            fired.add('pid')
        line = n
        n = LWP.sub(lambda m: 'LWP <L%d>' % lwps.setdefault(m.group(1), len(lwps) + 1), line)
        if n != line:
            fired.add('lwp')
        line = n
        n = SPIN.sub('spin (', line)
        if n != line:
            fired.add('spin')
        line = n
        n = THREADS_ROW.sub(r'\1 \2 \3\4 \5', THREADS_HEAD.sub('  Id Target Id Frame', line))
        if n != line:
            fired.add('threads-table')
        line = n
        if 'ticks' in (row or {}).get('normalise', []):
            n = TICK.sub('tick (n=<N>)', line)
            if n != line:
                fired.add('ticks')
            line = n
        out.append(line)
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


def no_randomization():
    """personality(2) ADDR_NO_RANDOMIZE in the sleeper before its exec: it starts as both debuggers start theirs."""
    if sys.platform.startswith('linux'):
        import ctypes
        ctypes.CDLL(None).personality(0x0040000)


def sleeper_line(p, timeout=60):
    """How the sleeper ended, as the line an attach row appends to stdout."""
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return '[sleeper did not end in %d s]\n' % timeout
    if p.returncode < 0:
        return '[sleeper killed by signal %d]\n' % -p.returncode
    last = (out.strip().splitlines() or [''])[-1]
    return '[sleeper exited with code %d: %s]\n' % (p.returncode, last)


def attach_run(tool, row, prog, work, gdb, timeout=120):
    """An attach row: the sleeper started as this harness's child, the debugger given its pid. Returns
    (stdout with the sleeper's line, stderr, status); a terminal row's stdout is the raw pty text."""
    a = row['attach']
    env = dict(ENV_BASE)
    s = subprocess.Popen([prog, str(a.get('ticks', 100))], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                         env=env, cwd=work, preexec_fn=no_randomization)
    first = s.stdout.readline()
    m = re.match(r'ready (\d+)$', first.strip())
    if not m:
        s.kill()
        s.communicate()
        return '', 'the sleeper did not say ready: %r\n' % first, 99
    pid = m.group(1)
    holder = None
    if a.get('held'):
        holder = subprocess.Popen([prog.replace('/c/sleeper/', '/c/holder/'), pid, '3000'], stdout=subprocess.PIPE, text=True,
                                  env=env, cwd=work)
        holder.stdout.readline()
    script = [x.replace('{pid}', pid) for x in row['script']]
    try:
        if row.get('tty'):
            out, err, rc = run_pty(tty_argv(tool, row, prog, gdb), script, '(gdb) ' if gdb else '(sniff) ', work, timeout)
        else:
            path = write_script(dict(row, script=script), work)
            if gdb:
                base = [tool, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-x', path]
            else:
                base = [tool, '-batch', '-x', path]
            form = a.get('form', 'script')
            argv = base + (['-p', pid, prog] if form == 'dash-p' else [prog, pid] if form == 'positional' else [prog])
            out, err, rc = run_tool(argv, work, timeout)
    finally:
        tail = sleeper_line(s)
        if holder:
            holder.wait(timeout=30)
    return out + tail, err, rc


def prog_path(fixtures, row):
    return str(Path(fixtures) / row['prog'])


def golden_paths(row):
    return [GOLD / (row['name'] + ext) for ext in ('.out', '.err', '.rc')]


def cmd_capture(a):
    work = a.work
    GOLD.mkdir(parents=True, exist_ok=True)
    for row in load_rows(a.only):
        if row.get('skip'):
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        if row.get('tty'):
            if row.get('attach'):
                out, err, rc = attach_run(a.gdb, row, prog_path(a.fixtures, row), work, True)
            else:
                out, err, rc = run_pty(tty_argv(a.gdb, row, prog_path(a.fixtures, row), True), row['script'], '(gdb) ', work)
            fired = set()
            o = normalize(normalize_tty(out, fired), fired, row)
            e = ''
            rc = 0
        else:
            if row.get('attach'):
                out, err, rc = attach_run(a.gdb, row, prog_path(a.fixtures, row), work, True)
            else:
                script = write_script(row, work)
                out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row)), work, 120)
            fired = set()
            o = normalize(out, fired, row)
            e = normalize(err, fired, row)
        for path, text in zip(golden_paths(row), (o, e, str(rc) + '\n')):
            path.write_text(text)
        print('CAPTURE ' + row['name'] + ' rc=' + str(rc))
    return 0


def subset_lines(want, got, own):
    """'' when every line of got is a line of want in want's order or one of own, else the reason."""
    if not got:
        return 'prints nothing'
    i = 0
    for k, line in enumerate(got):
        if line in own:
            continue
        while i < len(want) and want[i] != line:
            i += 1
        if i == len(want):
            return 'line %d is not one of gdb\'s, in order: %r' % (k + 1, line)
        i += 1
    missing = [x for x in own if x not in got]
    if missing:
        return 'its own line is missing: %r' % missing[0]
    return ''


def lines_verdict(row, want, got):
    """'' when sniff's stdout lines hold against gdb's as the row's compare mode says, else the reason."""
    mode = row.get('compare', 'bytes')
    if mode == 'bytes':
        return '' if got == want else first_diff('\n'.join(want), '\n'.join(got))
    if mode == 'head':
        n = row['head']
        if got[:n] != want[:n]:
            return 'held lines: ' + first_diff('\n'.join(want[:n]), '\n'.join(got[:n]))
        if len(got) <= n:
            return 'nothing of its own after the %d held lines' % n
        return ''
    if mode == 'subset':
        return subset_lines(want, got, row.get('own', []))
    if mode == 'own':
        return '' if got == row['expect'] else first_diff('\n'.join(row['expect']), '\n'.join(got))
    return 'unknown compare mode ' + mode


def judge(row, out, err, rc, want_o, want_e, want_rc):
    """What differs between sniff's run of a row and the golden (normalised texts); [] when it holds."""
    bad = []
    mode = row.get('compare', 'bytes')
    if mode == 'bytes':
        if out != want_o:
            bad.append('stdout ' + first_diff(want_o, out))
    else:
        why = lines_verdict(row, want_o.splitlines(), out.splitlines())
        if why:
            bad.append('stdout (%s) %s' % (mode, why))
    if mode == 'own':
        if row.get('gdb', 'has') == 'has' and (want_rc.strip() != '0' or not want_o.strip()):
            bad.append('golden: gdb does not answer this command with text and status 0')
        if row.get('gdb') == 'lacks' and want_rc.strip() == '0':
            bad.append('golden: gdb answers this command, which the row says it lacks')
        if row.get('gdb') == 'refuses' and want_rc.strip() == '0':
            bad.append('golden: gdb does not refuse this command, as the row says it does')
        # sniff's own answer: its stderr and status are the row's (none and 0 unless it says otherwise)
        want_e = ''.join(x + '\n' for x in row.get('expect_err', []))
        want_rc = str(row.get('expect_rc', 0))
    if err != want_e:
        bad.append('stderr ' + first_diff(want_e, err))
    if str(rc) != want_rc.strip():
        bad.append('exit want %s got %s' % (want_rc.strip(), rc))
    return bad


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
        if row.get('skip'):
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        gold = golden_paths(row)
        if not all(p.exists() for p in gold):
            print('FAIL %s no-golden' % row['name'])
            fails += 1
            continue
        try:
            if row.get('tty'):
                if row.get('attach'):
                    out, err, rc = attach_run(a.sniff, row, prog_path(a.fixtures, row), work, False)
                else:
                    out, err, rc = run_pty(tty_argv(a.sniff, row, prog_path(a.fixtures, row), False), row['script'], '(sniff) ', work)
                fired = set()
                out = normalize_tty(out, fired)
                rc = 0
            elif row.get('attach'):
                out, err, rc = attach_run(a.sniff, row, prog_path(a.fixtures, row), work, False, row.get('timeout', 120))
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
        o, e = normalize(out, fired, row), normalize(err, fired, row)
        want_o, want_e, want_rc = (p.read_text() for p in gold)
        bad = judge(row, o, e, rc, want_o, want_e, want_rc)
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
        if row.get('skip'):
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        fired = set()
        if row.get('tty'):
            if row.get('attach'):
                out, err, rc = attach_run(a.gdb, row, prog_path(a.fixtures, row), work, True)
            else:
                out, err, rc = run_pty(tty_argv(a.gdb, row, prog_path(a.fixtures, row), True), row['script'], '(gdb) ', work)
            got = (normalize(normalize_tty(out, fired), fired, row), '', '0\n')
        else:
            if row.get('attach'):
                out, err, rc = attach_run(a.gdb, row, prog_path(a.fixtures, row), work, True)
            else:
                script = write_script(row, work)
                out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row)), work, 120)
            got = (normalize(out, fired, row), normalize(err, fired, row), str(rc) + '\n')
        want = tuple(p.read_text() for p in golden_paths(row))
        if got != want:
            names = ('stdout', 'stderr', 'exit')
            why = '; '.join(n + ' ' + first_diff(w, g) for n, g, w in zip(names, got, want) if g != w)
            print('FAIL oracle-drift ' + row['name'] + ' ' + why)
            fails += 1
        else:
            print('PASS oracle-stable ' + row['name'])
    return 1 if fails else 0


def row_form(r):
    """'' when a row's compare fields are well formed, else the reason."""
    mode = r.get('compare', 'bytes')
    if mode == 'bytes':
        extra = sorted({'head', 'own', 'expect', 'expect_err', 'expect_rc', 'gdb'} & set(r))
        return 'fields of another compare mode: ' + ', '.join(extra) if extra else ''
    if r.get('tty'):
        return 'a terminal row compares bytes'
    if not str(r.get('why', '')).strip():
        return 'compare %s without a why' % mode
    if mode == 'head':
        return '' if isinstance(r.get('head'), int) and r['head'] > 0 else 'head needs a positive line count'
    if mode == 'subset':
        own = r.get('own', [])
        return '' if isinstance(own, list) and all(isinstance(x, str) for x in own) else 'own must be a list of lines'
    if mode == 'own':
        if r.get('gdb', 'has') not in ('has', 'lacks', 'refuses'):
            return 'gdb must be has, lacks or refuses'
        if not isinstance(r.get('expect'), list) or not (r['expect'] or r.get('expect_err')):
            return 'own needs its expect lines'
        return ''
    return 'unknown compare mode ' + mode


def cmd_verify(a):
    rows = load_rows()
    bad = ['%s: %s' % (r['name'], row_form(r)) for r in rows if row_form(r)]
    if bad:
        print('FAIL session-rows-form: ' + '; '.join(bad))
        return 1
    have = {p.name for p in GOLD.glob('*') if p.is_file() and p.suffix in ('.out', '.err', '.rc')}
    want = {p.name for r in rows if not r.get('skip') for p in golden_paths(r)}
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
    p.add_argument('--set', choices=('s2', 'pax'), default='s2', help='pax: static builds and their goldens (S4)')
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
    if a.set == 'pax':
        use_pax()
    global FIXTURES
    FIXTURES = getattr(a, 'fixtures', None)
    return {'capture': cmd_capture, 'check': cmd_check, 'oracle': cmd_oracle, 'verify': cmd_verify}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
