#!/usr/bin/env python3
"""S3 session rows on macOS arm64: sniff held to lldb's facts and to sn02's Linux output.

Two kinds of row (tests/macos-rows.json):

  linux  the S2 row of the same name, run by sniff on the Mac and compared with sn02's
         recorded gdb output (tests/evidence/linux-s2) wherever both platforms answer
         the same, after named normalisations:
           prog   the built-fixtures directory and the Linux one are one name
           root   the checkout's fixture directory and the Linux one are one name
           addr   every 0x... number is one name (the load addresses and the code differ)
           off    <fn+N> offsets are one name (arm64 and x86-64 prologues differ)
           pid    process ids
         A row with "stderr": true compares standard error and the exit status as well (the
         list and help refusals are on standard error), after one more:
           script the command file's path in gdb's `FILE:N: Error in sourced command file:`
         Rows whose text legitimately differs on arm64 are not run through this
         comparison; each appears under "excluded" with its reason.
  lldb   a script for sniff and one for Apple's lldb. Each output is reduced to a list of
         facts by a named extraction and the lists must be equal. Extractions: bpset
         (number, address, file, line), frame (level, function, file, line), print and
         retval (value text), var (name, value text), exit (code), signal and died
         (signal name), thread (a row of `info threads` or lldb's `thread list`: number,
         function, file, line, for a frame with a source line) and stopthread (the thread a
         breakpoint or signal stopped, when it is not thread 1: gdb names the thread only
         once a program has more than one and only at those stops, and lldb names it at
         every stop). lldb's text differs from
         gdb's; only these facts are compared.

Attach rows (an lldb or expect row with "attach": {"ticks": N, "form": "script" or "dash-p"}) start the row's
program, the sleeper, as this harness's own child, read its 'ready PID' line, wait until it blocks in its nap
(ps(1)'s state S; tools/session.py says why), put the pid in both scripts for
{pid}, and append how the sleeper ended to the output, '[sleeper exited with code N: LAST LINE]' or
'[sleeper killed by signal N]', which both extractions read as a sleeper fact. An expect row's "sign":
"hardened" runs a copy signed with the hardened runtime and no get-task-allow: macOS refuses its task port
to every debugger.

Core rows (a row's "core": NAME, from the "cores" table of tests/macos-rows.json) read a Mach-O core instead of
starting the program. Each take writes its cores afresh: lldb runs the fixture to the core's stop (or, for a
"crash" core, runs it until it faults) and saves it with `process save-core` in the core's style, under the take's
work directory, with RLIMIT_FSIZE at 64 MiB, SHELL=/bin/sh and the work directory's own HOME and TMPDIR. The take
deletes every core at its end and prints the bytes it left behind. A core row's "form" gives sniff the core as
`-c CORE PROG` (dash-c, the default), `PROG CORE` (positional) or `-c CORE` alone (dash-c-only); a "file" of missing
or truncated gives it no file, or the core's first 4096 bytes. lldb is given `-c CORE PROG` (`-c CORE` for
dash-c-only). Over a core, sniff prints gdb's banner and lldb its `process status`: the stop each prints is a status
block, no frame fact, and the signal that ended the program is a `died` fact on both sides (lldb names it by the
exception class: ESR_EC_BRK_AARCH64 is SIGTRAP, ESR_EC_DABORT_EL0 SIGSEGV). `x` and `memory read` give `mem` facts:
an address and the words read there.

`capture` runs lldb on the lldb rows and stores its raw output in
tests/evidence/macos-s3, so extraction can be replayed without lldb. `check` runs sniff
on every row. `replay` re-extracts facts from the stored lldb output and checks them
against the stored expected facts (no process, any host). `verify` checks inventory.
A row that did not run is reported as SKIP and is never a pass.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / 'tests/macos-rows.json'
LINUX_ROWS = ROOT / 'tests/session-rows.json'
LINUX_GOLD = ROOT / 'tests/evidence/linux-s2'
EVID = ROOT / 'tests/evidence/macos-s3'
SIGNAL_OF_EXC = {'EXC_BAD_ACCESS': 'SIGSEGV', 'EXC_BAD_INSTRUCTION': 'SIGILL', 'EXC_ARITHMETIC': 'SIGFPE',
                 'EXC_BREAKPOINT': 'SIGTRAP'}
# lldb's stop reason over a Mach-O core is the thread's exception class (tests/s7-macho-prediction.json)
SIGNAL_OF_ESR = {'ESR_EC_BRK_AARCH64': 'SIGTRAP', 'ESR_EC_DABORT_EL0': 'SIGSEGV'}
CORE_CAP = 64 << 20
MEM = re.compile(r'^(0x[0-9a-f]+)(?: <[^>]*>)?:\s+((?:0x[0-9a-f]+\s*)+)$')


def load():
    return json.loads(ROWS.read_text())


def linux_rows():
    return {r['name']: r for r in json.loads(LINUX_ROWS.read_text())['rows']}


# ---------- normalisation (linux rows) ----------

def normalize(text, roots, fired):
    out = text
    n = re.sub(r'(?:/[\w.-]+)+/(?:session-fixtures|fx)/', '<SF>/', out)
    if n != out:
        fired.add('prog')
    out = n
    n = re.sub(r'(?:/[\w.-]+)+/fixtures/', '<FX>/', out)
    if n != out:
        fired.add('root')
    out = n
    n = re.sub(r'0x[0-9a-fA-F]+', '0xA', out)
    if n != out:
        fired.add('addr')
    out = n
    n = re.sub(r'(<[\w.$]+)\+\d+>', r'\1+N>', out)
    if n != out:
        fired.add('off')
    out = n
    n = re.sub(r'(\[Inferior \d+ \(process )\d+(\))', r'\1<PID>\2', out)
    n = re.sub(r'(Detaching after fork from child process )\d+', r'\1<PID>', n)
    if n != out:
        fired.add('pid')
    return n


# ---------- fact extraction ----------

def base(path):
    return path.rsplit('/', 1)[-1]


def hexint(text):
    return int(text, 16)


SLEEPER = re.compile(r'^\[sleeper (exited with code \d+: .*|killed by signal \d+)\]$')


def facts_sniff(text):
    """Facts from sniff's (gdb-language) output. The frame `thread N` prints under its switch line is the
    thread's status, not a frame fact: lldb prints `thread select`'s status when it pleases (see facts_lldb)."""
    facts = []
    lines = text.splitlines()
    status = {i + 1 for i, ln in enumerate(lines[:-1])
              if re.match(r'^\[Switching to thread \d+ \(', ln) and re.match(r'^#\d+\s', lines[i + 1])}
    # over a core, the stop gdb's banner prints after the signal is the same kind of status
    status |= {i + 1 for i, ln in enumerate(lines[:-1])
               if re.match(r'^Program terminated with signal SIG\w+,', ln) and re.match(r'^#\d+\s', lines[i + 1])}
    for i, line in enumerate(lines):
        if i in status:
            continue
        m = MEM.match(line)
        if m:
            facts.append(('mem', hexint(m[1]), [hexint(w) for w in m[2].split()]))
            continue
        m = SLEEPER.match(line)
        if m:
            facts.append(('sleeper', m[1]))
            continue
        m = re.match(r'^Breakpoint (\d+) at (0x[0-9a-f]+): file (.*), line (\d+)\.$', line)
        if m:
            facts.append(('bpset', int(m[1]), hexint(m[2]) & 0xffffffffffff, base(m[3]), int(m[4])))
            continue
        m = re.match(r'^#(\d+)\s+(?:0x[0-9a-f]+ in )?([\w.$]+) \(.*\) at (.*):(\d+)$', line)
        if m:
            facts.append(('frame', int(m[1]), m[2], base(m[3]), int(m[4])))
            continue
        m = re.match(r'^pc\s+(0x[0-9a-f]+)\s', line)
        if m:
            facts.append(('pc', hexint(m[1]) & 0xffffffffffff))
            continue
        m = re.match(r'^Value returned is \$\d+ = (.*)$', line)
        if m:
            facts.append(('retval', m[1]))
            continue
        m = re.match(r'^\$\d+ = (.*)$', line)
        if m:
            facts.append(('print', re.sub(r"^-?\d+ ('.*')$", r'\1', m[1])))
            continue
        m = re.match(r'^([A-Za-z_]\w*) = (.*)$', line)
        if m:
            facts.append(('var', m[1], m[2]))
            continue
        m = re.match(r'^Thread (\d+) "[^"]*" (?:hit|received) ', line)
        if m and int(m[1]) != 1:
            facts.append(('stopthread', int(m[1])))
        m = re.match(r'^Thread \d+ "[^"]*" received signal (SIG\w+),', line)
        if m:
            facts.append(('signal', m[1]))
            continue
        m = re.match(r'^[* ] (\d+) +(?:Thread|process|LWP) .*? (?:0x[0-9a-f]+ in )?([\w.$]+) \(.*\) at (.*):(\d+)$', line)
        if m:
            facts.append(('thread', int(m[1]), m[2], base(m[3]), int(m[4])))
            continue
        m = re.match(r'^\[Inferior \d+ \(process \d+\) exited (?:normally|with code (\d+))\]$', line)
        if m:
            facts.append(('exit', int(m[1], 8) if m[1] else 0))
            continue
        m = re.match(r'^Program received signal (SIG\w+),', line)
        if m:
            facts.append(('signal', m[1]))
            continue
        m = re.match(r'^Program terminated with signal (SIG\w+),', line)
        if m:
            facts.append(('died', m[1]))
    return facts


FRAME_CMDS = ('frame', 'bt', 'up', 'down', 'thread backtrace')
STOP_CMDS = ('run', 'continue', 'step', 'next', 'finish', 'thread until', 'process', 'stepi', 'nexti')


def facts_lldb(text):
    """Facts from lldb's output. lldb prints the stop location after every resume and the stop
    reason again under bt; frame facts are taken only from frame/bt output (what sniff's `frame`
    and `bt` print) and signal facts only from the resume that stopped."""
    facts = []
    expect_print = False
    cur = ''
    lines = text.splitlines()
    # A thread's status block (a `* thread #N` header, one unstarred frame line, then its source or its
    # disassembly) is what `thread select` prints, and lldb prints it asynchronously: in one take it came
    # after the next command's own output, under that command's prompt. Its frame is no fact; a backtrace
    # starts the same way but goes on frame after frame.
    status = {i + 1 for i, ln in enumerate(lines[:-2])
              if re.match(r'^\* thread #\d+', ln) and re.match(r'^ {4}frame #\d+: ', lines[i + 1])
              and not re.match(r'^[* ]*\s*frame #\d+: ', lines[i + 2])}
    for i, line in enumerate(lines):
        if i in status:
            continue
        m = SLEEPER.match(line)
        if m:
            facts.append(('sleeper', m[1]))
            continue
        if line.startswith('(lldb) '):
            cur = line[7:]
            expect_print = cur.startswith('print ') or cur.startswith('p ')
            continue
        m = MEM.match(line)
        if m and cur.startswith('memory read'):
            facts.append(('mem', hexint(m[1]), [hexint(w) for w in m[2].split()]))
            continue
        m = re.search(r'stop reason = (ESR_EC_\w+)', line)
        if m and cur.startswith('process status') and m[1] in SIGNAL_OF_ESR and not any(f[0] == 'died' for f in facts):
            facts.append(('died', SIGNAL_OF_ESR[m[1]]))
            continue
        in_frame_cmd = cur.startswith(FRAME_CMDS)
        in_stop_cmd = cur.startswith(STOP_CMDS)
        m = re.match(r'^Breakpoint (\d+): where = .*? at (\S+?):(\d+)(?::\d+)?, address = (0x[0-9a-f]+)$', line)
        if m:
            facts.append(('bpset', int(m[1]), hexint(m[4]) & 0xffffffffffff, base(m[2]), int(m[3])))
            continue
        m = re.match(r'^[* ]*\s*frame #(\d+): 0x[0-9a-f]+ \S+?`([\w.$]+)(?:\(.*\))?(?: \+ \d+)? at (\S+?):(\d+)(?::\d+)?$', line)
        if m:
            if in_frame_cmd:
                facts.append(('frame', int(m[1]), m[2], base(m[3]), int(m[4])))
            continue
        m = re.match(r'^\s+pc = (0x[0-9a-f]+)', line)
        if m:
            facts.append(('pc', hexint(m[1]) & 0xffffffffffff))
            continue
        m = re.match(r'^Return value: \(.+?\) \$\d+ = (.*)$', line)
        if m:
            facts.append(('retval', m[1]))
            continue
        if expect_print:
            m = re.match(r'^\(.+?\) (?:\$\d+ = )?(.*)$', line)
            if m:
                facts.append(('print', m[1]))
                expect_print = False
                continue
        m = re.match(r'^\((?:[^()]|\([^()]*\))+?\) ([A-Za-z_]\w*) = (.*)$', line)
        if m:
            facts.append(('var', m[1], m[2]))
            continue
        m = re.match(r'^Process \d+ exited with status = (\d+) \(0x[0-9a-f]+\)$', line)
        if m:
            facts.append(('exit', int(m[1])))
            continue
        m = re.match(r'^[* ] thread #(\d+): tid = 0x[0-9a-f]+, 0x[0-9a-f]+ \S+?`([\w.$]+)(?:\(.*?\))?(?: \+ \d+)? at (\S+?):(\d+)(?::\d+)?(?:,|$)', line)
        if m:
            facts.append(('thread', int(m[1]), m[2], base(m[3]), int(m[4])))
            continue
        m = re.match(r'^\* thread #(\d+),.*stop reason = (?:breakpoint|signal|EXC_)', line)
        if m and in_stop_cmd and int(m[1]) != 1:
            facts.append(('stopthread', int(m[1])))
        m = re.search(r'stopped and restarted: thread \d+ received signal: (SIG\w+)', line)
        if m:
            if in_stop_cmd:
                facts.append(('signal', m[1]))
            continue
        m = re.search(r'stop reason = (EXC_\w+)', line)
        if m and m[1] in SIGNAL_OF_EXC:
            if in_stop_cmd:
                facts.append(('signal', SIGNAL_OF_EXC[m[1]]))
            continue
        m = re.search(r'stop reason = signal (SIG\w+)', line)
        if m:
            # the SIGSTOP an attach stops the process with is lldb's stop reason, not a signal the program
            # received: gdb prints the place only
            if in_stop_cmd and not (m[1] == 'SIGSTOP' and cur.startswith('process attach')):
                facts.append(('signal', m[1]))
            continue
        m = re.match(r'^Process \d+ exited with signal (SIG\w+)', line)
        if m:
            facts.append(('died', m[1]))
    return facts


# ---------- running ----------

ENV_BASE = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}


def lldb_path(lldb):
    """The lldb a take runs. A bare name is the one the harness's own PATH finds, not the caller's, so on macOS the
    gate's `lldb` is /usr/bin/lldb: the shim that runs the selected developer directory's lldb (xcode-select -p) with
    four variables added to its environment, which the program it starts inherits."""
    import shutil
    if os.sep in lldb:
        return lldb
    return shutil.which(lldb, path=ENV_BASE['PATH']) or '%s (not on %s)' % (lldb, ENV_BASE['PATH'])


class Hung(subprocess.TimeoutExpired):
    """A process this harness started (lldb, sniff) that did not finish in its time. A system prompt (an
    authorization dialog for a debugger) can hold a debugger forever with no CPU: the process is ended by the
    process id this harness started it with, and the row fails by name."""

    def __init__(self, argv, timeout, pid):
        super().__init__(argv, timeout)
        self.pid = pid

    def why(self):
        return '%s did not finish within %d s (a system prompt can hold a debugger); ended its pid %d' % (
            Path(str(self.cmd[0])).name, self.timeout, self.pid)


# the take's deadline (time.time()), set from --deadline: no process starts after it, and each one's time is cut to it
DEADLINE = [None]


def bounded(timeout):
    """A process's time: its own, cut to what is left of the take's."""
    if DEADLINE[0] is None:
        return timeout
    return max(1, min(timeout, int(DEADLINE[0] - time.time())))


def past_deadline():
    return DEADLINE[0] is not None and time.time() >= DEADLINE[0]


def run(argv, cwd, timeout, env=None, preexec=None):
    t = bounded(timeout)
    p = subprocess.Popen(argv, cwd=cwd, env=env or ENV_BASE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         errors='replace', preexec_fn=preexec)
    try:
        out, err = p.communicate(timeout=t)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise Hung(argv, t, p.pid)
    return out, err, p.returncode


def sniff_run(sniff, prog, script, args, work, name, timeout=120, pre=(), post=(), with_prog=True):
    d = Path(work)
    d.mkdir(parents=True, exist_ok=True)
    path = d / (name + '.cmd')
    path.write_text('\n'.join(script) + '\n')
    argv = [sniff, '-batch', '-x', str(path)] + list(pre) + ([prog] if with_prog else []) + list(post) + \
        (['--args'] + args if args else [])
    return run(argv, work, timeout)


def core_argv(row, core):
    """sniff's (pre, post, with_prog) for a core row's form, and lldb's (pre, with_prog)."""
    form = row.get('form', 'dash-c')
    if form == 'positional':
        return ((), (core,), True), (('-c', core), True)
    if form == 'dash-c-only':
        return (('-c', core), (), False), (('-c', core), False)
    return (('-c', core), (), True), (('-c', core), True)


def core_env(work):
    """The environment a core's writer runs in: no shell of the user's, the take's own HOME and TMPDIR."""
    d = Path(work)
    for sub in ('home', 'tmp'):
        (d / sub).mkdir(parents=True, exist_ok=True)
    env = dict(ENV_BASE)
    env.update(SHELL='/bin/sh', HOME=str(d / 'home'), TMPDIR=str(d / 'tmp'))
    return env


def cap_file_size():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (CORE_CAP, CORE_CAP))


def make_cores(rows, lldb, fixtures, work, timeout=120):
    """Write the cores the rows read, afresh: lldb runs the fixture to the core's stop (or until it faults) and saves
    it under WORK/cores, in at most timeout seconds each. Returns {name: path} for the cores written; a core not
    written is FAIL by name."""
    table = load().get('cores', {})
    want = sorted({r['core'] for r in rows if r.get('core')})
    d = Path(work) / 'cores'
    d.mkdir(parents=True, exist_ok=True)
    made = {}
    for name in want:
        if past_deadline():
            print('FAIL core-%s take-deadline: the take passed its deadline before this core' % name)
            continue
        c = table[name]
        prog = str(Path(fixtures) / c['prog'])
        path = d / (name + '.core')
        if path.exists():
            path.unlink()
        save = 'process save-core -s %s %s' % (c.get('style', 'modified-memory'), path)
        argv = [lldb, '-b', '-x']
        if c.get('crash'):
            argv += sum([['-o', x] for x in c['crash']], []) + ['-k', save, '-k', 'process kill']
        else:
            argv += sum([['-o', x] for x in c['stop']], []) + ['-o', save, '-o', 'process kill']
        start = time.time()
        try:
            rc = run(argv + [prog], work, timeout, core_env(work), cap_file_size)[2]
        except Hung as e:
            print('FAIL core-%s %s' % (name, e.why()))
            rc = 'hung'
        size = path.stat().st_size if path.exists() else 0
        if size == 0 or size >= CORE_CAP:
            print('FAIL core-%s save-core exit=%s bytes=%d (a core is under %d)' % (name, rc, size, CORE_CAP))
            if path.exists():
                path.unlink()
            continue
        print('CORE %s bytes=%d secs=%.1f style=%s lldb=%s' % (name, size, time.time() - start, c.get('style', 'modified-memory'),
                                                               lldb_path(lldb)))
        made[name] = path
    for r in rows:
        if r.get('core') in made and r.get('file') == 'truncated':
            (d / (r['core'] + '.truncated.core')).write_bytes(made[r['core']].read_bytes()[:4096])
    return made


def core_file(row, made, work):
    """The path a core row gives sniff and lldb."""
    d = Path(work) / 'cores'
    return str({'missing': d / (row['core'] + '.missing.core'),
                'truncated': d / (row['core'] + '.truncated.core')}.get(row.get('file'), made.get(row['core'], d / 'none')))


def delete_cores(work):
    """Every core of the take deleted; prints the bytes left behind (0, or the take is red)."""
    d = Path(work) / 'cores'
    for c in d.glob('*.core') if d.exists() else []:
        c.unlink()
    left = sum(c.stat().st_size for c in d.glob('*.core')) if d.exists() else 0
    print('cores left behind: %d bytes' % left)
    return left


S2 = []


def s2mod():
    """tools/session.py, loaded once: its pty runner and its compare modes."""
    if not S2:
        import importlib.util
        spec = importlib.util.spec_from_file_location('s2_session', ROOT / 'tools/session.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        S2.append(mod)
    return S2[0]


def tty_run(sniff, prog, script, args, work):
    """Run sniff in a pty (the S2 harness's own runner) the way a terminal user does."""
    s2 = s2mod()
    s2.ENV_BASE = dict(ENV_BASE)
    Path(work).mkdir(parents=True, exist_ok=True)
    argv = [sniff, prog] + (['--args'] + args if args else [])
    out, err, rc = s2.run_pty(argv, script, '(sniff) ', work)
    return s2.normalize_tty(out, set()), err, rc


def lldb_run(lldb, prog, script, work, name, timeout=120, pre=(), with_prog=True):
    d = Path(work)
    d.mkdir(parents=True, exist_ok=True)
    path = d / (name + '.lldb')
    path.write_text('\n'.join(script) + '\n')
    return run([lldb, '-b', '-s', str(path)] + list(pre) + ([prog] if with_prog else []), work, timeout)


def ps_letter(text):
    """The state letter of `ps -o stat=` output (ps(1)), or ''."""
    t = text.strip()
    return t[0] if t else ''


def ps_state(pid):
    r = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True, env=dict(ENV_BASE))
    return ps_letter(r.stdout)


def wait_blocked(pid, state=ps_state, tries=400, nap=0.005):
    """Wait until the sleeper blocks (S) in its nap, as tools/session.py does on Linux: its ready line is
    written by a system call it may not have returned from yet. Bounded; no wait where no state is read."""
    for _ in range(tries):
        st = state(pid)
        if st == 'S':
            return True
        if st == '':
            return False
        time.sleep(nap)
    return False


def sleeper_start(prog, ticks):
    s = subprocess.Popen([prog, str(ticks)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=dict(ENV_BASE))
    m = re.match(r'ready (\d+)$', s.stdout.readline().strip())
    if not m:
        s.kill()
        s.communicate()
        raise SystemExit('FAIL the sleeper %s did not say ready' % prog)
    wait_blocked(m.group(1))
    return s, m.group(1)


def sleeper_line(s, timeout=60):
    try:
        out, _ = s.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        s.kill()
        s.communicate()
        return '[sleeper did not end in %d s]\n' % timeout
    if s.returncode < 0:
        return '[sleeper killed by signal %d]\n' % -s.returncode
    return '[sleeper exited with code %d: %s]\n' % (s.returncode, (out.strip().splitlines() or [''])[-1])


def with_sleeper(r, prog, run_one):
    """Run run_one(script_substitution, extra_argv) for an attach row with its sleeper; else run it plainly."""
    a = r.get('attach')
    if not a:
        return run_one(lambda lines: lines, [])
    s, pid = sleeper_start(prog, a.get('ticks', 100))
    try:
        out, err, rc = run_one(lambda lines: [x.replace('{pid}', pid) for x in lines], ['-p', pid] if a.get('form') == 'dash-p' else [])
    finally:
        tail = sleeper_line(s)
    return out + tail, err, rc


def comparable(row, facts):
    """Facts as a row compares them. A process attached to was mapped where macOS chose (address-space
    randomisation, which a debugger turns off only for a program it starts), so an attach row's breakpoint
    addresses differ from take to take; its breakpoint number, file and line are compared.

    A core row's stack sits where what lldb gave the program above the stack put it, and the core is written afresh
    in each take: the /usr/bin/lldb shim's four variables move it 352 bytes from where the stored evidence's lldb put
    it. A row whose "frame" names the stack words it reads compares those as their distance from the address read
    (frame_relative), and every other word as it is; the row says why in its own text."""
    out = [list(f) for f in facts]
    if row.get('attach'):
        out = [f[:2] + f[3:] if f[0] == 'bpset' else f for f in out]
    if row.get('frame'):
        out = [frame_relative(f, row['frame']) if f[0] == 'mem' else f for f in out]
    return out


def frame_relative(fact, frame):
    """A memory fact read at a frame: the address is the frame's register, each word the frame names is its distance
    from that address ('$fp+32'), and each other word stays as read."""
    at, addr = frame['at'], fact[1]
    return ['mem', at, ['%s%+d' % (at, w - addr) if i in frame['offsets'] else None for i, w in enumerate(fact[2])]]


def frame_note(row, stored, read):
    """A frame row's PASS line says where each side read, so a take shows how far its stack moved."""
    at = [[f[1] for f in facts if f[0] == 'mem'] for facts in (stored, read)]
    if not row.get('frame') or len(at[0]) != 1 or len(at[1]) != 1:
        return ''
    return ' [%s read at: lldb 0x%x, sniff 0x%x, sniff-lldb %+d]' % (row['frame']['at'], at[0][0], at[1][0], at[1][0] - at[0][0])


XG = re.compile(r'^x/(\d+)xg (\$\w+)$')
LLDB_READ = re.compile(r'^memory read -s8 -fx -c(\d+) (\$\w+)$')


def frame_problems(row):
    """What the inventory refuses in a row's "frame": no reason in the row's own text; sniff (x/Nxg) and lldb
    (memory read -s8 -fx -cN) not reading the same count of words once each at the frame's register; an offset
    outside the words read."""
    fr = row.get('frame')
    if fr is None:
        return []
    name, bad = row.get('name', '?'), []
    if not str(fr.get('why', '')).strip():
        bad.append('%s: its frame gives no reason' % name)
    s = [m.groups() for m in map(XG.match, row.get('script', [])) if m]
    l = [m.groups() for m in map(LLDB_READ.match, row.get('lldb', [])) if m]
    if len(s) != 1 or len(l) != 1:
        return bad + ['%s: a frame row reads memory once on each side (x/Nxg REG, memory read -s8 -fx -cN REG)' % name]
    (sn, sat), (ln, lat) = s[0], l[0]
    if sn != ln or not sat == lat == fr.get('at'):
        bad.append('%s: sniff reads %s words at %s, lldb %s at %s, its frame is at %s' % (name, sn, sat, ln, lat, fr.get('at')))
    offs = fr.get('offsets')
    if not offs or not all(isinstance(i, int) and 0 <= i < int(sn) for i in offs):
        bad.append('%s: frame offsets %r are not among the %s words read' % (name, offs, sn))
    return bad


def lldb_script_rows(rows):
    return [r for r in rows if r['kind'] == 'lldb']


def select(rows, only):
    return [r for r in rows if not only or re.search(only, r['name'])]


def cmd_capture(a):
    spec = load()
    EVID.mkdir(parents=True, exist_ok=True)
    rows = select(lldb_script_rows(spec['rows']), a.only)
    DEADLINE[0] = time.time() + a.deadline
    made = make_cores(rows, a.lldb, a.fixtures, a.work, a.lldb_timeout)
    try:
        fails = capture_rows(a, rows, made)
    finally:
        # every core goes, however the rows ended
        left = delete_cores(a.work)
    return 1 if fails or left else 0


def capture_rows(a, rows, made):
    fails = 0
    for r in rows:
        if past_deadline():
            print('FAIL %s take-deadline: the take passed its %d s' % (r['name'], a.deadline))
            fails += 1
            continue
        prog = str(Path(a.fixtures) / r['prog'])
        try:
            if r.get('core'):
                if r['core'] not in made:
                    print('FAIL %s no-core %s' % (r['name'], r['core']))
                    fails += 1
                    continue
                (lpre, lprog) = core_argv(r, core_file(r, made, a.work))[1]
                out, err, rc = lldb_run(a.lldb, prog, r['lldb'], a.work, r['name'], a.lldb_timeout, pre=lpre, with_prog=lprog)
            else:
                out, err, rc = with_sleeper(r, prog, lambda sub, pre: lldb_run(a.lldb, prog, sub(r['lldb']), a.work, r['name'],
                                                                               a.lldb_timeout, pre=pre))
        except Hung as e:
            print('FAIL %s %s' % (r['name'], e.why()))
            fails += 1
            continue
        (EVID / (r['name'] + '.lldb.txt')).write_text(out)
        facts = facts_lldb(out)
        (EVID / (r['name'] + '.facts.json')).write_text(json.dumps(facts) + '\n')
        print('CAPTURE %s facts=%d' % (r['name'], len(facts)))
    return fails


SCRIPT = re.compile(r'(?m)^\S*/([\w.-]+)\.cmd:(\d+): Error in sourced command file:$')


def stderr_verdict(row, err, rc, roots, fired):
    """'' when sniff's stderr and status match the golden's (or an own row's), after the normalisation."""
    if row.get('compare') == 'own':
        want_e = ''.join(x + '\n' for x in row.get('expect_err', []))
        want_rc = str(row.get('expect_rc', 0))
    else:
        want_e = (LINUX_GOLD / (row['name'] + '.err')).read_text()
        want_rc = (LINUX_GOLD / (row['name'] + '.rc')).read_text().strip()
    got = SCRIPT.sub(r'<SCRIPT>:\2: Error in sourced command file:', err)
    want = SCRIPT.sub(r'<SCRIPT>:\2: Error in sourced command file:', want_e)
    if got != err:
        fired.add('script')
    got, want = normalize(got, roots, fired), normalize(want, roots, fired)
    if got != want:
        gl, wl = got.splitlines(), want.splitlines()
        i = next((i for i in range(max(len(gl), len(wl))) if (gl[i] if i < len(gl) else '<end>') != (wl[i] if i < len(wl) else '<end>')), 0)
        return 'stderr line %d: want %r got %r' % (i + 1, wl[i] if i < len(wl) else '<end>', gl[i] if i < len(gl) else '<end>')
    if str(rc) != want_rc:
        return 'exit want %s got %s' % (want_rc, rc)
    return ''


def prepare_target(kind, src, dst):
    """A copy of a fixture with a hostile signature state: 'adhoc' (signed, no get-task-allow), 'hardened' (signed with
    the hardened runtime, no get-task-allow) or 'unsigned'."""
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cp', src, dst], check=True)
    if kind == 'adhoc':
        subprocess.run(['codesign', '--force', '--sign', '-', dst], check=True, capture_output=True)
    elif kind == 'hardened':
        subprocess.run(['codesign', '--force', '--sign', '-', '-o', 'runtime', dst], check=True, capture_output=True)
    else:
        subprocess.run(['codesign', '--remove-signature', dst], check=True, capture_output=True)


def sniff_core_run(a, r, prog, script, args, made, timeout):
    """sniff over a core row's core, in the row's form."""
    pre, post, with_prog = core_argv(r, core_file(r, made, a.work))[0]
    return sniff_run(a.sniff, prog, script, args, a.work, r['name'], timeout, pre, post, with_prog)


def apply_drops(drops, wl, gl):
    """A linux row's named drops, applied to gdb's golden lines (wl) and sniff's (gl) alike: a "line" drop removes
    that line of the golden (and the same line of sniff's) when it is the drop's text; a "match" drop removes every
    line its pattern finds on either side. Returns the lines, one note per drop with the lines it removed from each
    side, and the reason a line drop is stale ('' when none is)."""
    notes = []
    bad = ''
    for d in sorted(drops, key=lambda d: -d.get('line', 0)):
        if 'line' in d:
            i = d['line'] - 1
            if i >= len(wl) or wl[i] != d['text']:
                bad = 'stale drop of line %d: %r' % (d['line'], wl[i] if i < len(wl) else '<end>')
                break
            del wl[i]
            if i < len(gl):
                del gl[i]
            notes.append('%s (1 golden line)' % d['why'])
    for d in drops:
        if 'match' in d:
            rx = re.compile(d['match'])
            g2 = [x for x in gl if not rx.search(x)]
            w2 = [x for x in wl if not rx.search(x)]
            notes.append('%s (%d golden, %d sniff)' % (d['why'], len(wl) - len(w2), len(gl) - len(g2)))
            gl, wl = g2, w2
    return wl, gl, notes, bad


def cmd_check(a):
    spec = load()
    lin = linux_rows()
    roots = [str(ROOT), '/work', str(Path(a.fixtures).parent)]
    fails = ran = 0
    rows = select(spec['rows'], a.only)
    DEADLINE[0] = time.time() + a.deadline
    made = make_cores([r for r in rows if r.get('core')], a.lldb, a.fixtures, a.work, a.lldb_timeout)
    try:
        ran, fails = check_rows(a, rows, made, lin, roots)
    finally:
        # every core goes, however the rows ended
        left = delete_cores(a.work) if made else 0
    if left:
        fails += 1
    print('SUMMARY ran=%d failed=%d' % (ran, fails))
    return 1 if fails else 0


def check_rows(a, rows, made, lin, roots):
    fails = ran = 0
    for r in rows:
        if past_deadline():
            print('FAIL %s take-deadline: the take passed its %d s' % (r['name'], a.deadline))
            fails += 1
            continue
        if r.get('core') and r['core'] not in made:
            print('FAIL %s no-core %s' % (r['name'], r['core']))
            fails += 1
            continue
        if r['kind'] == 'expect':
            prog = str(Path(a.work) / 'hostile' / r['name'])
            if 'sign' in r:
                prepare_target(r['sign'], str(Path(a.fixtures) / r['prog']), prog)
            else:
                prog = str(Path(a.fixtures) / r['prog'])
            try:
                if r.get('core'):
                    out, err, rc = sniff_core_run(a, r, prog, r['script'], r.get('args', []), made, r.get('timeout', 60))
                else:
                    out, err, rc = with_sleeper(r, prog, lambda sub, pre: sniff_run(a.sniff, prog, sub(r['script']), r.get('args', []), a.work,
                                                                                    r['name'], r.get('timeout', 60), pre))
            except subprocess.TimeoutExpired as e:
                print('FAIL %s %s' % (r['name'], e.why() if isinstance(e, Hung) else 'timeout (sniff hung)'))
                fails += 1
                continue
            ran += 1
            both = out + err
            miss = [x for x in r['contains'] if x not in both]
            if miss:
                print('FAIL %s missing %r in %r' % (r['name'], miss, both[-300:]))
                fails += 1
            else:
                print('PASS %s [refusal text: %s]' % (r['name'], r['contains'][0]))
            continue
        row_prog = r['prog'] if r['kind'] == 'lldb' else lin[r['name']]['prog'].replace('gcc-O0', 'clang-O0')
        script = r['script'] if 'script' in r else lin[r['name']]['script']
        args = r.get('args', [])
        prog = str(Path(a.fixtures) / row_prog)
        try:
            if r['kind'] == 'linux' and lin[r['name']].get('tty'):
                out, err, rc = tty_run(a.sniff, prog, script, args, a.work)
            elif r.get('core'):
                out, err, rc = sniff_core_run(a, r, prog, script, args, made, r.get('timeout', 120))
            else:
                out, err, rc = with_sleeper(r, prog, lambda sub, pre: sniff_run(a.sniff, prog, sub(script), args, a.work, r['name'],
                                                                                r.get('timeout', 120), pre))
        except subprocess.TimeoutExpired as e:
            print('FAIL %s %s' % (r['name'], e.why() if isinstance(e, Hung) else 'timeout'))
            fails += 1
            continue
        ran += 1
        (Path(a.work) / (r['name'] + '.got')).write_text(out)
        (Path(a.work) / (r['name'] + '.err')).write_text(err)
        if r['kind'] == 'linux':
            fired = set()
            want = (LINUX_GOLD / (r['name'] + '.out')).read_text()
            gl = normalize(out, roots, fired).splitlines()
            wl = normalize(want, roots, fired).splitlines()
            wl, gl, dropped, bad = apply_drops(r.get('drop', []), wl, gl)
            # the row's compare mode (tools/session.py): bytes, or the head, subset and own forms of the help rows
            mode_row = lin[r['name']]
            if mode_row.get('compare') == 'own':
                wl = normalize(''.join(x + '\n' for x in mode_row['expect']), roots, fired).splitlines()
                mode_row = {}
            why = '' if not bad and gl == wl else (bad or s2mod().lines_verdict(mode_row, wl, gl))
            if not why and r.get('stderr'):
                why = stderr_verdict(lin[r['name']], err, rc, roots, fired)
            if not why:
                print('PASS %s [normalised: %s]%s' % (r['name'], ','.join(sorted(fired)), ' [dropped lines: %s]' % ' | '.join(dropped) if dropped else ''))
            else:
                i = next((i for i in range(max(len(gl), len(wl))) if (gl[i] if i < len(gl) else '<end>') != (wl[i] if i < len(wl) else '<end>')), 0)
                if mode_row.get('compare', 'bytes') == 'bytes' and not bad:
                    why = 'line %d: want %r got %r' % (i + 1, wl[i] if i < len(wl) else '<end>', gl[i] if i < len(gl) else '<end>')
                print('FAIL %s %s' % (r['name'], why))
                fails += 1
        else:
            stored, read = json.loads((EVID / (r['name'] + '.facts.json')).read_text()), facts_sniff(out)
            want, got = comparable(r, stored), comparable(r, read)
            if got == want:
                print('PASS %s facts=%d%s' % (r['name'], len(got), frame_note(r, stored, read)))
            else:
                i = next((i for i in range(max(len(got), len(want))) if (got[i] if i < len(got) else None) != (want[i] if i < len(want) else None)), 0)
                print('FAIL %s fact %d: lldb %r sniff %r' % (r['name'], i + 1, want[i] if i < len(want) else None, got[i] if i < len(got) else None))
                fails += 1
    return ran, fails


def cmd_reextract(a):
    """Rewrite the stored expected facts from the stored lldb output (after an extraction change)."""
    for r in lldb_script_rows(load()['rows']):
        txt = EVID / (r['name'] + '.lldb.txt')
        (EVID / (r['name'] + '.facts.json')).write_text(json.dumps(facts_lldb(txt.read_text())) + '\n')
        print('REEXTRACT %s' % r['name'])
    return 0


def cmd_replay(a):
    """Re-extract facts from the stored lldb output; no process, any host."""
    spec = load()
    fails = n = 0
    for r in lldb_script_rows(spec['rows']):
        txt = EVID / (r['name'] + '.lldb.txt')
        fj = EVID / (r['name'] + '.facts.json')
        if not txt.exists() or not fj.exists():
            print('FAIL %s no-evidence' % r['name'])
            fails += 1
            continue
        got = [list(f) for f in facts_lldb(txt.read_text())]
        want = json.loads(fj.read_text())
        n += 1
        if got != want or not got:
            print('FAIL %s replay-facts' % r['name'])
            fails += 1
        else:
            print('PASS %s replay facts=%d' % (r['name'], len(got)))
    print('SUMMARY replayed=%d failed=%d' % (n, fails))
    return 1 if fails else 0


def cmd_verify(a):
    spec = load()
    lin = linux_rows()
    names = [r['name'] for r in spec['rows']]
    if len(set(names)) != len(names):
        print('FAIL macos-rows: duplicate row names')
        return 1
    bad = []
    for r in spec['rows']:
        if r['kind'] == 'linux' and (r['name'] not in lin or not (LINUX_GOLD / (r['name'] + '.out')).exists()):
            bad.append('no linux golden for ' + r['name'])
        if r['kind'] == 'lldb' and not all((EVID / (r['name'] + e)).exists() for e in ('.lldb.txt', '.facts.json')):
            bad.append('no lldb evidence for ' + r['name'])
    cores = spec.get('cores', {})
    for name, c in sorted(cores.items()):
        if not c.get('prog') or not (c.get('stop') or c.get('crash')) or c.get('style', 'modified-memory') not in ('modified-memory', 'stack'):
            bad.append('core %s needs a prog, its stop or crash commands and a style of modified-memory or stack' % name)
    used = {r['core'] for r in spec['rows'] if r.get('core')}
    for r in spec['rows']:
        if r.get('core') and r['core'] not in cores:
            bad.append('%s reads core %s, not in the cores table' % (r['name'], r['core']))
        if r.get('form', 'dash-c') not in ('dash-c', 'positional', 'dash-c-only') or r.get('file', 'core') not in ('core', 'missing', 'truncated'):
            bad.append('%s: a core row\'s form is dash-c, positional or dash-c-only and its file core, missing or truncated' % r['name'])
        bad += frame_problems(r)
    bad += ['core %s: no row reads it' % n for n in sorted(set(cores) - used)]
    covered = set(names) | set(spec['excluded'])
    for name in lin:
        mac_relevant = '-gcc-' not in name and not name.startswith('tty-gcc')
        if mac_relevant and name not in covered:
            bad.append('linux row neither run nor excluded: ' + name)
    for name, why in spec['excluded'].items():
        if not why.strip():
            bad.append('excluded without a reason: ' + name)
    if bad:
        print('FAIL macos-rows-inventory: ' + '; '.join(bad[:10]))
        return 1
    print('PASS macos-rows rows=%d excluded=%d' % (len(names), len(spec['excluded'])))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    for name in ('capture', 'check'):
        s = sub.add_parser(name)
        s.add_argument('--work', default=str(ROOT / 'target/s3'))
        s.add_argument('--fixtures', default=str(ROOT / 'target/session-fixtures'))
        s.add_argument('--only')
        s.add_argument('--lldb', default='lldb')
        s.add_argument('--lldb-timeout', type=int, default=120, help='seconds each lldb may take before it is ended')
        s.add_argument('--deadline', type=int, default=2400, help="seconds the take may take: no process starts after")
        if name == 'check':
            s.add_argument('--sniff', default=str(ROOT / 'target/sniff'))
    sub.add_parser('replay')
    sub.add_parser('reextract')
    sub.add_parser('verify')
    a = p.parse_args()
    return {'capture': cmd_capture, 'check': cmd_check, 'replay': cmd_replay, 'reextract': cmd_reextract, 'verify': cmd_verify}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
