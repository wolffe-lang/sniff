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
In the PAX set a skipped row names its "gap": "harness" for the harness's own limit, or a probe ("probes" in
tests/pax-rows.json, a static C program under tests/pax-probe/) whose Linux answer is its golden
(probe-NAME.out, .rc). tools/session-pax.py runs each probe at PAX's console; a skip that blames PAX stands only
while PAX answers its probe differently from Linux, and is red by name (skip-stale) once PAX answers alike.
A row with "golden_of" is held to another row's golden: capture and oracle pass it by (SHARED), and check
runs sniff on its own script against that golden. sniff's bare `info registers` is held so to the named form's
26 lines, which gdb's bare form exceeds on AVX-512 hosts (k0-k7).
Terminal rows run both debuggers in a pseudo-terminal with echo off and send
one command per prompt, as R-sn02-1 specifies.

Attach rows ("attach": {...}) start the row's program, the sleeper, as this harness's own child with
address randomisation off (as both debuggers start their own programs), read its 'ready PID' line, put
the pid in the script for {pid}, run the debugger, and append how the sleeper ended to stdout:
'[sleeper exited with code N: LAST LINE]' or '[sleeper killed by signal N]'. "ticks" is the sleeper's
argument; the debugger starts once the sleeper blocks in its nap (State S in /proc/PID/status): the ready
line is written by a system call the sleeper may not have returned from yet, and an attach there stops it in
write(), where sniff, quicker to start than gdb, stopped it on one CPU. "form" is "script" (the default), "dash-p" (-p PID before the program) or "positional"
(PROG PID); "held" first starts the holder fixture of the same build on the sleeper, so that another
tracer has it.

Core rows ("core": {"of": NAME, ...}) read a core file instead of starting the program. "cores" in
tests/session-rows.json names each core: the program (under --fixtures), its arguments and the gdb commands that
reach the stop; in each take the pinned gdb runs it there and writes the core with gcore, once, before the first
row that reads it (`cores`, or capture, check and oracle for the cores their rows need). The cores of a set are
in target/cores/s2 or target/cores/pax beside the set's fixtures (/work/target/cores/... in the oracle image and
at PAX's console alike); a core is never committed. "form" is how the debugger is given it, the GDB manual's
forms: "positional" (PROG CORE, the default), "dash-c" (-c CORE PROG), "dash-c-only" (-c CORE) or "script" (PROG
only; the script names the core as {core}, for core-file). "file" is "truncated" (the core's first 4096 bytes) or
"missing" (a path where no file is). A row whose program is not its core's says so with "other_program": true.

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
import time
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
# A thread's address is its C library's thread record, at the top of a stack the library mapped. Where that
# mapping lands is the host's: the C library sizes a thread's stack by the stack limit (an 8 MiB limit on one
# host, 16 MiB on a CI runner, put the second thread 8 MiB apart), and PAX maps it below Linux's 0x7ff...
# range. So a thread's address is named by first appearance, as an LWP id is: <T1>, <T2>, ...
THREAD_ADDR = re.compile(r'\bThread (0x[0-9a-f]+) \(LWP ')
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


def load_probes():
    """The PAX set's kernel probes, tests/pax-rows.json "probes": name -> C source. Each is built static and run
    on Linux (its answer there is its golden) and at PAX's console; none in the S2 set."""
    if not PAX_MODE:
        return {}
    return json.loads(PAX_ROWS.read_text()).get('probes', {})


def load_probe_differences():
    """The PAX set's documented differences, tests/pax-rows.json "probe_differences": probe name -> [{call, linux, pax,
    why}], a line of the probe's where PAX answers otherwise than Linux, both answers, and why."""
    if not PAX_MODE:
        return {}
    return json.loads(PAX_ROWS.read_text()).get('probe_differences', {})


def difference_problems(probes, differences):
    """What the inventory refuses in the probes' named differences: one for a probe that is not registered, an entry
    without its call, both answers and a reason, and an entry whose two answers are the same; [] when nothing is."""
    bad = []
    for name, entries in sorted(differences.items()):
        if name not in probes:
            bad.append('probe_differences %s: no such probe' % name)
            continue
        for d in entries:
            if not all(isinstance(d.get(k), str) and d[k].strip() for k in ('call', 'linux', 'pax', 'why')):
                bad.append('probe_differences %s: an entry needs its call, linux, pax and why' % name)
            elif d['linux'] == d['pax']:
                bad.append('probe_differences %s: %r answers the same on both' % (name, d['call']))
    return bad


CORE_FORMS = ('positional', 'dash-c', 'dash-c-only', 'script')
CORE_FILES = ('missing', 'truncated')


def load_cores():
    """The cores the rows read, tests/session-rows.json "cores": name -> {"prog", "args", "stop"}."""
    return json.loads(ROWS.read_text()).get('cores', {})


def cores_dir(fixtures):
    """Where a set's cores are written: target/cores/SET beside the set's fixtures (target/session-fixtures or
    target/pax-fixtures)."""
    return Path(fixtures).parent / 'cores' / ('pax' if PAX_MODE else 's2')


def core_path(row, fixtures):
    c = row['core']
    suffix = {'missing': '.missing.core', 'truncated': '.truncated.core'}.get(c.get('file'), '.core')
    return str(cores_dir(fixtures) / (c['of'] + suffix))


XSTATE_WARNING = re.compile(r"warning: (?:Unexpected size of section `\.reg-xstate/([0-9]+)' in core file\."
                            r"|Section `\.reg-xstate/([0-9]+)' in core file too small\.)")


def drop_xstate(err):
    """gdb's standard error with its xstate-size warnings taken out: (text, the LWP each warning named, lines).

    gdb reads a core's XSAVE note (`.reg-xstate/LWP`) against its own layouts for the note's features, and warns when
    the host wrote it at another size: `Unexpected size of section `.reg-xstate/LWP' in core file.` when it is larger
    (a runner whose XSAVE area carries AMX tile state) and `Section `.reg-xstate/LWP' in core file too small.` when it
    is smaller (an AMD EPYC runner's 2432 bytes). gcore writes the note at the host's size, so the same core rows
    differ by these warnings from host to host. Only gdb's standard error passes through here. The two exact
    sentences with a decimal LWP are dropped, each with the blank line gdb prints before it when that blank line
    directly precedes it; nothing else is."""
    out = []
    lwps = []
    lines = 0
    for line in err.splitlines(keepends=True):
        m = XSTATE_WARNING.fullmatch(line.rstrip('\n'))
        if m:
            lwps.append(int(m.group(1) or m.group(2)))
            lines += 1
            if out and out[-1] == '\n':
                out.pop()
                lines += 1
            continue
        out.append(line)
    return ''.join(out), lwps, lines


def xstate_excess(lwps, threads):
    """'' when every xstate-size warning names a thread of the row's core (its NT_PRSTATUS pids), none more than
    twice (gdb warns twice for the thread it selects, once for each other), else the reason. A row with no core has
    no thread to warn about."""
    for lwp in sorted(set(lwps)):
        if lwp not in threads:
            return 'xstate-size dropped a warning naming LWP %d, not a thread of its core %s' % (lwp, sorted(threads))
        if lwps.count(lwp) > 2:
            return 'xstate-size dropped %d warnings naming LWP %d, more than twice' % (lwps.count(lwp), lwp)
    return ''


def core_facts(path):
    """From a core's own bytes: its NT_PRSTATUS notes (owner CORE), the size of its first NT_X86_XSTATE (owner LINUX)
    and the pr_pid of each NT_PRSTATUS (offset 32, tools/abi-probe.c), walked as src/readers/core.lu walks them (the
    ELF gABI's notes, laid at 8 when the PT_NOTE says 8 and at 4 otherwise); (0, 0, []) for a file that is not a
    whole ELF64 core."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return 0, 0, []
    up = lambda n, a: (n + a - 1) // a * a
    try:
        if data[:4] != b'\x7fELF' or data[4] != 2 or struct.unpack_from('<H', data, 16)[0] != 4:
            return 0, 0, []
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phentsize, phnum = struct.unpack_from('<HH', data, 54)
        xstate = 0
        pids = []
        for i in range(phnum):
            at = phoff + i * phentsize
            if struct.unpack_from('<I', data, at)[0] != 4:
                continue
            off, size, align = (struct.unpack_from('<Q', data, at + k)[0] for k in (8, 32, 48))
            if off + size > len(data):
                return 0, 0, []
            a = 8 if align == 8 else 4
            k = 0
            while k + 12 <= size:
                namesz, descsz, kind = struct.unpack_from('<III', data, off + k)
                name = data[off + k + 12:off + k + 12 + namesz].rstrip(b'\0')
                desc = up(k + 12 + namesz, a)
                if name == b'CORE' and kind == 1:
                    pids.append(struct.unpack_from('<I', data, off + desc + 32)[0])
                if name == b'LINUX' and kind == 0x202 and not xstate:
                    xstate = descsz
                k = up(desc + descsz, a)
        return len(pids), xstate, pids
    except struct.error:
        return 0, 0, []


def row_threads(row, fixtures):
    """The thread ids of the core a row reads ([] for a row with no core, or a core missing by design)."""
    c = row.get('core')
    if not c or c.get('file') == 'missing':
        return []
    return core_facts(core_path(row, fixtures))[2]


def host_facts():
    """The kernel and the processor a take's cores were written on: gcore writes each thread's XSAVE area at the
    size the host gives it, so the facts behind any xstate-size line. Linux's /proc/cpuinfo; '-' where it is not."""
    model = flags = ''
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            key, _, value = line.partition(':')
            key = key.strip()
            if key == 'model name' and not model:
                model = value.strip()
            if key == 'flags' and not flags:
                have = set(value.split())
                flags = ','.join(f for f in ('xsave', 'avx2', 'avx512f', 'amx_tile', 'amx_bf16', 'amx_int8') if f in have)
    except OSError:
        pass
    return 'HOST kernel=%s cpu=%s flags=%s' % (os.uname().release, re.sub(r'\s+', '_', model) or '-', flags or '-')


def keep_drift(name, out, err, where=None, core=None):
    """gdb's whole output for a row that drifted, before any normalisation, kept where the gate's evidence is
    (target/gate/oracle-drift/NAME.out and .err), so the next difference is read rather than inferred. For a core
    row, core is its core_facts: NAME.core holds its thread ids and XSAVE note size as text, so the xstate-size
    rule's membership check can be replayed without the core."""
    d = Path(where) if where else ROOT / 'target/gate/oracle-drift'
    d.mkdir(parents=True, exist_ok=True)
    (d / (name + '.out')).write_text(out)
    (d / (name + '.err')).write_text(err)
    if core is not None:
        threads, xstate, pids = core
        (d / (name + '.core')).write_text('threads=%d xstate=%d pids=%s\n' % (threads, xstate, ','.join(map(str, pids)) or '-'))
    return d / (name + '.err')


def row_core_facts(row, fixtures):
    """core_facts of the core a row reads, or None for a row with no core."""
    if not row.get('core'):
        return None
    if row['core'].get('file') == 'missing':
        return 0, 0, []
    return core_facts(core_path(row, fixtures))


def xstate_note(dropped):
    """The evidence line for the rows whose gdb text needed the xstate-size rule, or ''."""
    if not dropped:
        return ''
    return 'xstate-size dropped %d lines on rows %s' % (sum(dropped.values()), ','.join(sorted(dropped)))


def core_tail(row, prog, fixtures):
    """What follows the script on a core row's command line, in the row's form."""
    core = core_path(row, fixtures)
    return {'positional': [prog, core], 'dash-c': ['-c', core, prog], 'dash-c-only': ['-c', core],
            'script': [prog]}[row['core'].get('form', 'positional')]


def core_script(row, fixtures):
    """The row with {core} in its script replaced by its core's path (a script-form row's core-file)."""
    if not row.get('core'):
        return row
    return dict(row, script=[x.replace('{core}', core_path(row, fixtures)) for x in row['script']])


def gcore_argv(gdb, core, prog, path):
    argv = [gdb, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off']
    for c in core['stop']:
        argv += ['-ex', c]
    return argv + ['-ex', 'gcore ' + path, '--args', prog] + core.get('args', [])


def make_cores(rows, gdb, fixtures, work, timeout=120):
    """Write the cores the rows read that this take has not (or that are older than their program): gdb's gcore at
    each core's stop, then the truncated copies the rows name. Returns the names of the cores that were not made."""
    want = sorted({r['core']['of'] for r in rows if r.get('core')})
    if not want:
        return set()
    table = load_cores()
    d = cores_dir(fixtures)
    d.mkdir(parents=True, exist_ok=True)
    bad = set()
    print(host_facts())
    for name in want:
        c = table[name]
        prog = Path(fixtures) / c['prog']
        path = d / (name + '.core')
        if not path.exists() or not prog.exists() or path.stat().st_mtime < prog.stat().st_mtime:
            part = d / (name + '.core.part')
            if part.exists():
                part.unlink()
            start = time.time()
            try:
                _, err, rc = run_tool(gcore_argv(gdb, c, str(prog), str(part)), work, timeout)
            except subprocess.TimeoutExpired:
                err, rc = '', 'timeout'
            if rc != 0 or not part.exists():
                print('FAIL core-%s gcore exit=%s %s' % (name, rc, (err.strip().splitlines() or [''])[-1][:120]))
                bad.add(name)
                continue
            os.replace(part, path)
            threads, xstate, _ = core_facts(path)
            print('CORE %s bytes=%d secs=%.1f threads=%d xstate=%d' % (name, path.stat().st_size, time.time() - start,
                                                                     threads, xstate))
        if any(r.get('core', {}).get('of') == name and r['core'].get('file') == 'truncated' for r in rows):
            (d / (name + '.truncated.core')).write_bytes(path.read_bytes()[:4096])
        missing = d / (name + '.missing.core')
        if missing.exists():
            missing.unlink()
    return bad


def core_problems(rows, cores):
    """What is wrong with the core rows and the cores table; [] when nothing is."""
    bad = []
    for name, c in sorted(cores.items()):
        if not isinstance(c, dict) or not isinstance(c.get('prog'), str) or not isinstance(c.get('args', []), list) \
                or not isinstance(c.get('stop'), list) or not c['stop'] or not all(isinstance(x, str) for x in c['stop']):
            bad.append('core %s: needs a prog, an args list and the gdb commands of its stop' % name)
    used = set()
    for r in rows:
        c = r.get('core')
        if c is None:
            continue
        if not isinstance(c, dict) or c.get('of') not in cores:
            bad.append('%s: core names no core of the table' % r['name'])
            continue
        used.add(c['of'])
        if c.get('form', 'positional') not in CORE_FORMS:
            bad.append('%s: core form %s is none of %s' % (r['name'], c.get('form'), ', '.join(CORE_FORMS)))
        if c.get('file') is not None and c['file'] not in CORE_FILES:
            bad.append('%s: core file %s is none of %s' % (r['name'], c['file'], ', '.join(CORE_FILES)))
        if r.get('args') or r.get('attach') or r.get('tty'):
            bad.append('%s: a core row is a batch row with no args or attach' % r['name'])
        if (c.get('form') == 'script') != any('{core}' in x for x in r['script']):
            bad.append('%s: a script-form core row names {core} in its script, and only it' % r['name'])
        if (r['prog'] != cores[c['of']].get('prog')) != bool(c.get('other_program')):
            bad.append('%s: its program differs from its core\'s exactly when it says other_program' % r['name'])
    bad += ['core %s: no row reads it' % n for n in sorted(set(cores) - used)]
    return bad


def probe_golden_paths(name):
    return [PAX_GOLD / ('probe-' + name + ext) for ext in ('.out', '.rc')]


def skip_problems(rows, probes):
    """What is wrong with the PAX set's skips: a skipped row says why with "gap", either "harness" (the harness's
    own limit) or the name of the probe that witnesses a gap in PAX, and a gap goes with a skip; [] when nothing is."""
    bad = []
    for r in rows:
        if 'gap' in r and not r.get('skip'):
            bad.append('%s: a gap without a skip' % r['name'])
        elif r.get('skip') and 'gap' not in r:
            bad.append('%s: a skip that names no gap (a probe, or harness)' % r['name'])
        elif r.get('skip') and r['gap'] != 'harness' and r['gap'] not in probes:
            bad.append('%s: gap %s names no probe' % (r['name'], r['gap']))
    return bad


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
THREADS_ROW = re.compile(r'^([* ]) (\d+) +(Thread <T\d+> \(LWP <L\d+>\)|LWP <L\d+>|process <PID>)( "[^"]*")? +(\S.*)$', re.M)
TICK = re.compile(r'\btick \(n=\d+\)')


def normalize(text, fired, row=None):
    out = []
    lwps = {}
    taddrs = {}
    drops = [re.compile(d) for d in (row or {}).get('drop', [])] if PAX_MODE else []
    heap = heap_range(str(Path(FIXTURES) / row['prog'])) if PAX_MODE and FIXTURES and row and row.get('prog') else None
    for line in text.splitlines(keepends=True):
        # before the PAX set's stack and heap rules, which would otherwise take the address first
        m = THREAD_ADDR.sub(lambda x: 'Thread <T%d> (LWP ' % taddrs.setdefault(x.group(1), len(taddrs) + 1), line)
        if m != line:
            fired.add('thread-addr')
            line = m
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


def gdb_argv(gdb, row, script, prog, fixtures=None):
    base = [gdb, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-x', script]
    if row.get('core'):
        return base + core_tail(row, prog, fixtures)
    return base + ['--args', prog] + row.get('args', [])


def sniff_argv(sniff, row, script, prog, fixtures=None):
    if row.get('core'):
        return [sniff, '-batch', '-x', script] + core_tail(row, prog, fixtures)
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


def status_state(text):
    """The state letter of a /proc/PID/status text (proc_pid_status(5)), or ''."""
    for ln in text.splitlines():
        if ln.startswith('State:') and len(ln.split()) > 1:
            return ln.split()[1]
    return ''


def proc_state(pid):
    try:
        return status_state(Path('/proc/%s/status' % pid).read_text())
    except OSError:
        return ''


def wait_blocked(pid, state=proc_state, tries=2000, nap=0.001):
    """Wait until the sleeper blocks (S): only its nap blocks it. Bounded; no wait where no state is kept."""
    for _ in range(tries):
        st = state(pid)
        if st == 'S':
            return True
        if st == '':
            return False
        time.sleep(nap)
    return False


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
    wait_blocked(pid)
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
    """A row's golden files; a row with "golden_of" is held to that row's golden (its own command would give gdb
    lines sniff does not print, as gdb's bare `info registers` adds k0-k7 on AVX-512 hosts)."""
    return [GOLD / (row.get('golden_of', row['name']) + ext) for ext in ('.out', '.err', '.rc')]


def golden_of_problems(rows):
    """What is wrong with the rows' "golden_of" fields: each names another row that runs, has its own golden, and
    compares bytes; [] when nothing is."""
    by = {r['name']: r for r in rows}
    bad = []
    for r in rows:
        g = r.get('golden_of')
        if g is None:
            continue
        t = by.get(g)
        if not isinstance(g, str) or t is None or g == r['name']:
            bad.append('%s: golden_of names no other row' % r['name'])
        elif t.get('golden_of') or t.get('skip'):
            bad.append('%s: golden_of names a row without its own golden' % r['name'])
        elif r.get('tty') or r.get('compare', 'bytes') != 'bytes':
            bad.append('%s: a golden_of row is a batch row that compares bytes' % r['name'])
    return bad


def cmd_capture(a):
    work = a.work
    GOLD.mkdir(parents=True, exist_ok=True)
    rows = load_rows(a.only)
    no_core = make_cores([r for r in rows if not r.get('golden_of') and (a.include_skipped or not r.get('skip'))],
                         a.gdb, a.fixtures, work)
    fails = 0
    dropped = {}
    for row in rows:
        if row.get('skip') and not a.include_skipped:
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        if row.get('golden_of'):
            print('SHARED %s golden=%s' % (row['name'], row['golden_of']))
            continue
        if row.get('core', {}).get('of') in no_core:
            print('FAIL %s no-core %s' % (row['name'], row['core']['of']))
            fails += 1
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
                script = write_script(core_script(row, a.fixtures), work)
                out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row), a.fixtures), work, 120)
            err, lwps, lines = drop_xstate(err)
            excess = xstate_excess(lwps, row_threads(row, a.fixtures))
            if excess:
                print('FAIL %s %s' % (row['name'], excess))
                fails += 1
                continue
            if lines:
                dropped[row['name']] = lines
            fired = set()
            o = normalize(out, fired, row)
            e = normalize(err, fired, row)
        for path, text in zip(golden_paths(row), (o, e, str(rc) + '\n')):
            path.write_text(text)
        print('CAPTURE ' + row['name'] + ' rc=' + str(rc))
    if dropped:
        print(xstate_note(dropped))
    return 1 if fails else 0


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
    rows = load_rows(a.only)
    no_core = make_cores([r for r in rows if not r.get('skip')], getattr(a, 'gdb', 'gdb'), a.fixtures, work)
    for row in rows:
        if row.get('skip'):
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        gold = golden_paths(row)
        if not all(p.exists() for p in gold):
            print('FAIL %s no-golden' % row['name'])
            fails += 1
            continue
        if row.get('core', {}).get('of') in no_core:
            print('FAIL %s no-core %s' % (row['name'], row['core']['of']))
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
                script = write_script(core_script(row, a.fixtures), work)
                out, err, rc = run_tool(sniff_argv(a.sniff, row, script, prog_path(a.fixtures, row), a.fixtures), work,
                                        row.get('timeout', 120))
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
    rows = load_rows(a.only)
    no_core = make_cores([r for r in rows if not r.get('skip') and not r.get('golden_of')], a.gdb, a.fixtures, work)
    dropped = {}
    for row in rows:
        if row.get('skip'):
            print('SKIP ' + row['name'] + ' reason=' + row['skip'])
            continue
        if row.get('golden_of'):
            # the golden is another row's, re-derived when that row runs here
            print('SHARED %s golden=%s' % (row['name'], row['golden_of']))
            continue
        if row.get('core', {}).get('of') in no_core:
            print('FAIL oracle-drift %s no-core %s' % (row['name'], row['core']['of']))
            fails += 1
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
                script = write_script(core_script(row, a.fixtures), work)
                out, err, rc = run_tool(gdb_argv(a.gdb, row, script, prog_path(a.fixtures, row), a.fixtures), work, 120)
            kept, lwps, lines = drop_xstate(err)
            excess = xstate_excess(lwps, row_threads(row, a.fixtures))
            if excess:
                print('FAIL oracle-drift %s %s' % (row['name'], excess))
                print('KEPT %s' % keep_drift(row['name'], out, err, core=row_core_facts(row, a.fixtures)).relative_to(ROOT))
                fails += 1
                continue
            if lines:
                dropped[row['name']] = lines
            got = (normalize(out, fired, row), normalize(kept, fired, row), str(rc) + '\n')
        want = tuple(p.read_text() for p in golden_paths(row))
        if got != want:
            names = ('stdout', 'stderr', 'exit')
            why = '; '.join(n + ' ' + first_diff(w, g) for n, g, w in zip(names, got, want) if g != w)
            print('FAIL oracle-drift ' + row['name'] + ' ' + why)
            if not row.get('tty'):
                print('KEPT %s' % keep_drift(row['name'], out, err, core=row_core_facts(row, a.fixtures)).relative_to(ROOT))
            fails += 1
        else:
            print('PASS oracle-stable ' + row['name'])
    if dropped:
        print(xstate_note(dropped))
    return 1 if fails else 0


def cmd_cores(a):
    """Write every core the selected rows read (gcore at each core's stop), as capture, check and oracle do first."""
    rows = [r for r in load_rows(a.only) if not r.get('skip')]
    bad = make_cores(rows, a.gdb, a.fixtures, a.work)
    print('SUMMARY cores=%d failed=%d' % (len({r['core']['of'] for r in rows if r.get('core')}), len(bad)))
    return 1 if bad else 0


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
    probes = load_probes()
    bad = ['%s: %s' % (r['name'], row_form(r)) for r in rows if row_form(r)] + golden_of_problems(rows)
    bad += core_problems(rows, load_cores())
    if PAX_MODE:
        bad += skip_problems(rows, probes)
        bad += difference_problems(probes, load_probe_differences())
        bad += ['probe %s: no source %s' % (n, src) for n, src in sorted(probes.items()) if not (ROOT / src).is_file()]
    if bad:
        print('FAIL session-rows-form: ' + '; '.join(bad))
        return 1
    have = {p.name for p in GOLD.glob('*') if p.is_file() and p.suffix in ('.out', '.err', '.rc')}
    want = {p.name for r in rows if not r.get('skip') for p in golden_paths(r)}
    want |= {p.name for n in probes for p in probe_golden_paths(n)}
    if want - have:
        print('FAIL session-goldens-missing: ' + ', '.join(sorted(want - have)))
        return 1
    # a skipped row may keep its golden, captured on Linux, ready for the day its gap closes
    ready = {p.name for r in rows if r.get('skip') for p in golden_paths(r)}
    if have - want - ready:
        print('FAIL session-goldens-extra: ' + ', '.join(sorted(have - want - ready)))
        return 1
    print('PASS session-rows rows=%d goldens=%d' % (len(rows), len(want)))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--set', choices=('s2', 'pax'), default='s2', help='pax: static builds and their goldens (S4)')
    sub = p.add_subparsers(dest='cmd', required=True)
    for name in ('capture', 'check', 'oracle', 'cores'):
        s = sub.add_parser(name)
        s.add_argument('--work', default='/work')
        s.add_argument('--fixtures', default='/work/target/session-fixtures')
        s.add_argument('--only')
        # check makes the cores its rows read with gdb too (in the oracle image), when no step before it has
        s.add_argument('--gdb', default='gdb')
        if name == 'capture':
            s.add_argument('--include-skipped', action='store_true',
                           help="capture skipped rows' goldens too (on Linux, before a PAX gap closes)")
        if name == 'check':
            s.add_argument('--sniff', default='/work/target/sniff')
    sub.add_parser('verify')
    a = p.parse_args()
    if a.set == 'pax':
        use_pax()
    global FIXTURES
    FIXTURES = getattr(a, 'fixtures', None)
    return {'capture': cmd_capture, 'check': cmd_check, 'oracle': cmd_oracle, 'cores': cmd_cores, 'verify': cmd_verify}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
