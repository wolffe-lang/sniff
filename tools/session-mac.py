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
         Rows whose text legitimately differs on arm64 are not run through this
         comparison; each appears under "excluded" with its reason.
  lldb   a script for sniff and one for Apple's lldb. Each output is reduced to a list of
         facts by a named extraction and the lists must be equal. Extractions: bpset
         (number, address, file, line), frame (level, function, file, line), print and
         retval (value text), var (name, value text), exit (code), signal and died
         (signal name). lldb's text differs from gdb's; only these facts are compared.

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

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / 'tests/macos-rows.json'
LINUX_ROWS = ROOT / 'tests/session-rows.json'
LINUX_GOLD = ROOT / 'tests/evidence/linux-s2'
EVID = ROOT / 'tests/evidence/macos-s3'
SIGNAL_OF_EXC = {'EXC_BAD_ACCESS': 'SIGSEGV', 'EXC_BAD_INSTRUCTION': 'SIGILL', 'EXC_ARITHMETIC': 'SIGFPE',
                 'EXC_BREAKPOINT': 'SIGTRAP'}


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


def facts_sniff(text):
    """Facts from sniff's (gdb-language) output."""
    facts = []
    for line in text.splitlines():
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
    for line in text.splitlines():
        if line.startswith('(lldb) '):
            cur = line[7:]
            expect_print = cur.startswith('print ') or cur.startswith('p ')
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
        m = re.search(r'stop reason = (EXC_\w+)', line)
        if m and m[1] in SIGNAL_OF_EXC:
            if in_stop_cmd:
                facts.append(('signal', SIGNAL_OF_EXC[m[1]]))
            continue
        m = re.search(r'stop reason = signal (SIG\w+)', line)
        if m:
            if in_stop_cmd:
                facts.append(('signal', m[1]))
            continue
        m = re.match(r'^Process \d+ exited with signal (SIG\w+)', line)
        if m:
            facts.append(('died', m[1]))
    return facts


# ---------- running ----------

ENV_BASE = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}


def run(argv, cwd, timeout, env=None):
    p = subprocess.run(argv, cwd=cwd, env=env or ENV_BASE, capture_output=True, timeout=timeout, text=True, errors='replace')
    return p.stdout, p.stderr, p.returncode


def sniff_run(sniff, prog, script, args, work, name, timeout=120):
    d = Path(work)
    d.mkdir(parents=True, exist_ok=True)
    path = d / (name + '.cmd')
    path.write_text('\n'.join(script) + '\n')
    argv = [sniff, '-batch', '-x', str(path), prog] + (['--args'] + args if args else [])
    return run(argv, work, timeout)


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


def lldb_run(lldb, prog, script, work, name, timeout=120):
    d = Path(work)
    d.mkdir(parents=True, exist_ok=True)
    path = d / (name + '.lldb')
    path.write_text('\n'.join(script) + '\n')
    return run([lldb, '-b', '-s', str(path), prog], work, timeout)


def lldb_script_rows(rows):
    return [r for r in rows if r['kind'] == 'lldb']


def select(rows, only):
    return [r for r in rows if not only or re.search(only, r['name'])]


def cmd_capture(a):
    spec = load()
    EVID.mkdir(parents=True, exist_ok=True)
    for r in select(lldb_script_rows(spec['rows']), a.only):
        prog = str(Path(a.fixtures) / r['prog'])
        out, err, rc = lldb_run(a.lldb, prog, r['lldb'], a.work, r['name'])
        text = re.sub(r'\bProcess \d+\b', 'Process N', out)
        (EVID / (r['name'] + '.lldb.txt')).write_text(out)
        facts = facts_lldb(out)
        (EVID / (r['name'] + '.facts.json')).write_text(json.dumps(facts) + '\n')
        print('CAPTURE %s facts=%d' % (r['name'], len(facts)))
    return 0


def prepare_target(kind, src, dst):
    """A copy of a fixture with a hostile signature state: 'adhoc' (signed, no get-task-allow) or 'unsigned'."""
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cp', src, dst], check=True)
    if kind == 'adhoc':
        subprocess.run(['codesign', '--force', '--sign', '-', dst], check=True, capture_output=True)
    else:
        subprocess.run(['codesign', '--remove-signature', dst], check=True, capture_output=True)


def cmd_check(a):
    spec = load()
    lin = linux_rows()
    roots = [str(ROOT), '/work', str(Path(a.fixtures).parent)]
    fails = ran = 0
    for r in select(spec['rows'], a.only):
        if r['kind'] == 'expect':
            prog = str(Path(a.work) / 'hostile' / r['name'])
            if 'sign' in r:
                prepare_target(r['sign'], str(Path(a.fixtures) / r['prog']), prog)
            else:
                prog = str(Path(a.fixtures) / r['prog'])
            try:
                out, err, rc = sniff_run(a.sniff, prog, r['script'], r.get('args', []), a.work, r['name'], r.get('timeout', 60))
            except subprocess.TimeoutExpired:
                print('FAIL %s timeout (sniff hung)' % r['name'])
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
            else:
                out, err, rc = sniff_run(a.sniff, prog, script, args, a.work, r['name'], r.get('timeout', 120))
        except subprocess.TimeoutExpired:
            print('FAIL %s timeout' % r['name'])
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
            dropped = []
            bad = None
            for d in sorted(r.get('drop', []), key=lambda d: -d.get('line', 0)):
                if 'line' in d:
                    i = d['line'] - 1
                    if i >= len(wl) or wl[i] != d['text']:
                        bad = 'stale drop of line %d: %r' % (d['line'], wl[i] if i < len(wl) else '<end>')
                        break
                    del wl[i]
                    if i < len(gl):
                        del gl[i]
                    dropped.append(d['why'])
            for d in r.get('drop', []):
                if 'match' in d:
                    rx = re.compile(d['match'])
                    gl = [x for x in gl if not rx.search(x)]
                    wl = [x for x in wl if not rx.search(x)]
                    dropped.append(d['why'])
            # the row's compare mode (tools/session.py): bytes, or the head, subset and own forms of the help rows
            mode_row = lin[r['name']]
            if mode_row.get('compare') == 'own':
                wl = normalize(''.join(x + '\n' for x in mode_row['expect']), roots, fired).splitlines()
                mode_row = {}
            why = '' if bad is None and gl == wl else (bad or s2mod().lines_verdict(mode_row, wl, gl))
            if not why:
                print('PASS %s [normalised: %s]%s' % (r['name'], ','.join(sorted(fired)), ' [dropped lines: %s]' % ' | '.join(dropped) if dropped else ''))
            else:
                i = next((i for i in range(max(len(gl), len(wl))) if (gl[i] if i < len(gl) else '<end>') != (wl[i] if i < len(wl) else '<end>')), 0)
                if mode_row.get('compare', 'bytes') == 'bytes' and not bad:
                    why = 'line %d: want %r got %r' % (i + 1, wl[i] if i < len(wl) else '<end>', gl[i] if i < len(gl) else '<end>')
                print('FAIL %s %s' % (r['name'], why))
                fails += 1
        else:
            want = json.loads((EVID / (r['name'] + '.facts.json')).read_text())
            got = [list(f) for f in facts_sniff(out)]
            if got == want:
                print('PASS %s facts=%d' % (r['name'], len(got)))
            else:
                i = next((i for i in range(max(len(got), len(want))) if (got[i] if i < len(got) else None) != (want[i] if i < len(want) else None)), 0)
                print('FAIL %s fact %d: lldb %r sniff %r' % (r['name'], i + 1, want[i] if i < len(want) else None, got[i] if i < len(got) else None))
                fails += 1
    print('SUMMARY ran=%d failed=%d' % (ran, fails))
    return 1 if fails else 0


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
        if name == 'capture':
            s.add_argument('--lldb', default='lldb')
        else:
            s.add_argument('--sniff', default=str(ROOT / 'target/sniff'))
    sub.add_parser('replay')
    sub.add_parser('reextract')
    sub.add_parser('verify')
    a = p.parse_args()
    return {'capture': cmd_capture, 'check': cmd_check, 'replay': cmd_replay, 'reextract': cmd_reextract, 'verify': cmd_verify}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
