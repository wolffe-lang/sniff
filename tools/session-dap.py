#!/usr/bin/env python3
"""The DAP rows (S9): a scripted Debug Adapter Protocol client that drives an adapter over its standard input and
output, records every message both ways, and holds what the adapter answers to the row's expectations.

  session-dap.py check (--sniff PATH | --adapter 'CMD ARGS…') --rows FILE --out DIR [--only REGEX]
                       [--fixtures DIR --sources DIR --cc gcc|clang] [--golden DIR]
  session-dap.py capture --adapter 'CMD ARGS…' --rows FILE --out DIR --golden DIR [--only REGEX]
                       [--fixtures DIR --sources DIR --cc gcc|clang] [--identity TEXT]
  session-dap.py skip --rows FILE --reason TEXT --expect N [--program yes|no]
  session-dap.py selftest

The framing and the envelope are the specification's base protocol (a Content-Length header, a UTF-8 JSON body; seq,
type, request_seq, success, command). Each row starts the adapter afresh (`--sniff PATH` runs `PATH --dap`), runs its
steps in order and writes every message to OUT/ROW.jsonl, one object a line: {"i", "t" (ms), "dir" (c2a, a2c or
note), "msg"}.

Steps (lists in the rows file):
  ["send", COMMAND, ARGS, EXPECT?]   a request, then its response (other messages are kept in order)
  ["post", COMMAND, ARGS]            a request without waiting (an adapter may answer launch after configurationDone)
  ["reply", COMMAND, EXPECT?]        the response to the last posted COMMAND
  ["wait", EVENT, FIELDS?]           the next unconsumed EVENT whose body has FIELDS
  ["raw", TEXT]                      TEXT written as it is (a broken frame, a body that is not a message)
  ["close"]                          the adapter's standard input closed
  ["exit", CODE]                     the adapter ends within 10 s, with CODE
  ["stderr", TEXT]                   after the end, a line of the adapter's standard error holds TEXT
  ["sleep", SECONDS]
EXPECT: {"success": bool, "message": text, "body_true": [names]: exactly these body members are true and no other
member is}.
Placeholders, resolved when a step is sent: "@PROG@", "@SRC@" and "@CWD@" inside strings (from the row's prog and
src); "@THREAD@" (the last consumed stopped event's threadId, else the first thread of the last threads response,
else the first thread a thread event reported started); "@FRAMEk@", "@SCOPEk@", "@VARk@" (the k-th frame id, scope
variablesReference or nonzero variable reference of the last stackTrace, scopes or variables response); "@MEMREF@"
(the last successful evaluate's memoryReference, else the first 0x… address in its result).

`--program no` takes only the rows that run no program, `yes` only those that do (a host with no fixtures or no
Linux process runs the first; `skip` names the second, each `SKIP dap ROW reason=TEXT`, and fails unless there are N).

A row passes when every expectation holds: `PASS dap ROW`. An expectation that does not hold is a red by comparison:
`FAIL dap ROW WHAT: …`. A timeout, an adapter that ends while a response is awaited, a body that is not JSON, or a
placeholder with nothing to name is a fault, never a red: `FAIL dap ROW fault: …`. A request from the adapter
(runInTerminal, startDebugging) is answered success: false and noted. The last line is
`dap rows (check): P pass, F fail, S skip`; the exit is 1 when any row failed.

A row with "compare": "gdb" is also held to the pinned gdb's transcript of the same steps, its golden
(GOLDEN/ROW.CC.json, or GOLDEN/ROW.json for a row whose program is not built per compiler; GOLDEN defaults to
tests/evidence/dap). `capture` takes the transcript twice, each take on a fresh adapter, and writes the golden only
when the two agree after normalising (`CAPTURED dap ROW`; else `UNSTABLE dap ROW` with the first difference, or `FAULT
dap ROW`; the last line `dap rows (capture): C captured, U unstable, F fault`). A take's expectations are not applied:
they are sniff's. `check` normalises sniff's transcript the same way, applies the row's named differences to both
sides, and compares; the first difference is a red (`FAIL dap ROW golden: …`). A golden that is missing, or whose
requests differ from the row's, is a fault. Normalising:
  seq / request_seq          dropped (the client numbers its requests; the adapter its own messages)
  thread, frame, variables, breakpoint, source and memory references, systemProcessId   each renamed by first
                             appearance (T1, F1, V1, B1, S1, M1, P1; a scope's own id V)
  the repository's root      @ROOT@ (a golden taken in one checkout holds in another)
  0x… in text                <ADDR>; a process id in text ("process N", "pid N", "ready N", "thread N", "LWP N") <PID>
  module and loadedSource events   left out (the system's libraries, loaded in an order of their own)
  the interleaving of events with responses   not compared: responses in request order, events in their own order
  the initialize response's body   not compared: sniff's capabilities are its own declared set, which dap-initialize
                             holds
Named differences (a row's "differences"), applied to both sides:
  launch-start      gdb starts the program at launch and answers configurationDone notStopped; sniff starts it at
                    configurationDone, which it answers success: true
  registers-scope   the Registers scope holds the general registers `info registers` prints: its count is not
                    compared"""
import argparse
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / 'tests/evidence/dap'
TIMEOUT = float(os.environ.get('SESSION_DAP_TIMEOUT', '30'))


class Fault(Exception):
    pass


class Red(Exception):
    pass


class Adapter:
    def __init__(self, argv, cwd, stderr_path):
        self.err_path = stderr_path
        self.err = open(stderr_path, 'wb')
        self.p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                  env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C', 'TZ': 'UTC',
                                       'TERM': 'dumb', 'SHELL': '/bin/sh', 'HOME': os.path.dirname(stderr_path)})
        self.q = queue.Queue()
        self.t = threading.Thread(target=self.read, daemon=True)
        self.t.start()

    def read(self):
        out = self.p.stdout
        try:
            while True:
                length = None
                while True:
                    line = out.readline()
                    if not line:
                        self.q.put(('eof', None))
                        return
                    if line in (b'\r\n', b'\n'):
                        break
                    k, _, v = line.decode('ascii', 'replace').partition(':')
                    if k.strip().lower() == 'content-length':
                        length = int(v.strip())
                if length is None:
                    self.q.put(('bad', 'a header part without Content-Length'))
                    return
                body = out.read(length)
                if len(body) < length:
                    self.q.put(('eof', None))
                    return
                try:
                    self.q.put(('msg', json.loads(body.decode('utf-8'))))
                except ValueError:
                    self.q.put(('bad', 'a body that is not JSON'))
                    return
        except Exception as e:  # noqa: BLE001 - the row's fault, named
            self.q.put(('bad', 'the reader: %r' % (e,)))

    def write(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def send(self, msg):
        body = json.dumps(msg).encode('utf-8')
        self.write(b'Content-Length: %d\r\n\r\n' % len(body) + body)

    def close_input(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass

    def end(self):
        self.close_input()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.err.close()


# the repository's root as given and as resolved: the fixtures and their sources are under it
ROOTS = sorted({str(ROOT), os.path.realpath(str(ROOT))}, key=len, reverse=True)
IDKEYS = {'threadId': 'T', 'frameId': 'F', 'variablesReference': 'V', 'memoryReference': 'M', 'breakpointId': 'B',
          'sourceReference': 'S', 'systemProcessId': 'P'}
ID_IN = {'stackFrames': 'F', 'threads': 'T', 'breakpoints': 'B', 'breakpoint': 'B', 'scopes': 'V'}
UNCOMPARED = ('module', 'loadedSource')


def normalise(records, differences):
    """A transcript (the records of OUT/ROW.jsonl) as compared: {'sent', 'responses', 'events'}, with the named
    differences applied."""
    maps = {}

    def name(kind, v):
        if v in (0, None, '') or isinstance(v, bool):
            return v
        m = maps.setdefault(kind, {})
        if v not in m:
            m[v] = '%s%d' % (kind, len(m) + 1)
        return m[v]

    def walk(v, ctx):
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                if k in ('seq', 'request_seq'):
                    continue
                if k == 'id' and ctx in ID_IN:
                    out[k] = name(ID_IN[ctx], x)
                elif k == 'hitBreakpointIds' and isinstance(x, list):
                    out[k] = [name('B', y) for y in x]
                elif k in IDKEYS:
                    out[k] = name(IDKEYS[k], x)
                else:
                    out[k] = walk(x, k)
            return out
        if isinstance(v, list):
            return [walk(x, ctx) for x in v]
        if isinstance(v, str):
            for r in ROOTS:
                v = v.replace(r, '@ROOT@')
            v = re.sub(r'0x[0-9a-fA-F]+', '<ADDR>', v)
            v = re.sub(r'\b(process|pid|ready|thread) \d+', r'\1 <PID>', v, flags=re.I)
            return re.sub(r'\bLWP \d+', 'LWP <PID>', v)
        return v

    msgs = [(r['dir'], walk(r['msg'], None)) for r in records if r['dir'] != 'note']
    side = {'sent': [m for d, m in msgs if d == 'c2a'],
            'responses': [m for d, m in msgs if d == 'a2c' and m.get('type') == 'response'],
            'events': [m for d, m in msgs if d == 'a2c' and m.get('type') == 'event' and m.get('event') not in UNCOMPARED]}
    for r in side['responses']:
        if r.get('command') == 'initialize':
            r.pop('body', None)
    return differ(side, differences)


def launch_start(side):
    for r in side['responses']:
        if r.get('command') == 'configurationDone' and not r.get('success') and r.get('message') == 'notStopped':
            r['success'] = True
            del r['message']


def registers_scope(side):
    for r in side['responses']:
        if r.get('command') == 'scopes':
            for s in (r.get('body') or {}).get('scopes', []):
                if s.get('name') == 'Registers' and 'namedVariables' in s:
                    s['namedVariables'] = '<registers>'


DIFFERENCES = {'launch-start': launch_start, 'registers-scope': registers_scope}


def differ(side, names):
    """SIDE (a normalised transcript) with the named differences applied, as a copy."""
    out = json.loads(json.dumps(side))
    for n in names:
        if n not in DIFFERENCES:
            raise Fault('no named difference %r' % n)
        DIFFERENCES[n](out)
    return out


def first_difference(want, got):
    """The first place two normalised transcripts differ, as text, or None."""
    for part in ('sent', 'responses', 'events'):
        a, b = want[part], got[part]
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                what = x.get('command') or x.get('event') or ''
                return part, '%s[%d] %s differs: want %s got %s' % (part, i, what, json.dumps(x, sort_keys=True)[:300],
                                                                    json.dumps(y, sort_keys=True)[:300])
        if len(a) != len(b):
            return part, '%s: %d, the golden has %d' % (part, len(b), len(a))
    return None


def golden_path(row, cc, golden):
    stem = row['name'] + ('.' + cc if '@CC@' in row.get('prog', '') else '')
    return Path(golden) / (stem + '.json')


def records_of(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def run_row(row, argv, fixtures, sources, cc, out):
    """Run one row: returns (status, reds). status is 'ok' or 'fault: …'; reds lists each comparison that failed."""
    name = row['name']
    if row.get('prog', '-') == '-':
        prog, src, cwd = '', '', out
    else:
        prog = os.path.join(fixtures, row['prog'].replace('@CC@', cc))
        src = os.path.join(sources, row.get('src', ''))
        cwd = os.path.dirname(prog)
    log = open(os.path.join(out, name + '.jsonl'), 'w')
    t0 = time.monotonic()
    count = [0]
    reds = []

    def rec(direction, msg):
        log.write(json.dumps({'i': count[0], 't': int((time.monotonic() - t0) * 1000), 'dir': direction, 'msg': msg}) + '\n')
        log.flush()
        count[0] += 1

    state = {'thread': None, 'frames': [], 'scopes': [], 'vars': [], 'threads': [], 'started': [], 'memref': None}
    pending, posted, seq = [], {}, [0]
    a = Adapter(argv, cwd, os.path.join(out, name + '.stderr'))

    def subst(v):
        if isinstance(v, str):
            if v == '@THREAD@':
                drain()
                for pick in (state['thread'],) + tuple(state['threads'][:1]) + tuple(state['started'][:1]):
                    if pick is not None:
                        return pick
                raise Fault('no thread id for @THREAD@')
            if v == '@MEMREF@':
                drain()
                if state['memref'] is None:
                    raise Fault('no address for @MEMREF@')
                return state['memref']
            m = re.fullmatch(r'@(FRAME|SCOPE|VAR)(\d+)@', v)
            if m:
                lst = {'FRAME': state['frames'], 'SCOPE': state['scopes'], 'VAR': state['vars']}[m.group(1)]
                k = int(m.group(2))
                if k >= len(lst):
                    raise Fault('nothing for %s' % v)
                return lst[k]
            return v.replace('@PROG@', prog).replace('@SRC@', src).replace('@CWD@', cwd)
        if isinstance(v, list):
            return [subst(x) for x in v]
        if isinstance(v, dict):
            return {k: subst(x) for k, x in v.items()}
        return v

    def learn(msg):
        if msg.get('type') == 'event' and msg.get('event') == 'thread':
            body = msg.get('body') or {}
            if body.get('reason') == 'started' and body.get('threadId') not in state['started']:
                state['started'].append(body.get('threadId'))
        if msg.get('type') == 'response' and msg.get('success'):
            body = msg.get('body') or {}
            if msg.get('command') == 'stackTrace':
                state['frames'] = [f.get('id') for f in body.get('stackFrames', [])]
            elif msg.get('command') == 'scopes':
                state['scopes'] = [s.get('variablesReference') for s in body.get('scopes', [])]
            elif msg.get('command') == 'variables':
                state['vars'] = [x.get('variablesReference') for x in body.get('variables', []) if x.get('variablesReference')]
            elif msg.get('command') == 'threads':
                state['threads'] = [t.get('id') for t in body.get('threads', [])]
            elif msg.get('command') == 'evaluate':
                at = re.search(r'0x[0-9a-fA-F]+', body.get('result', '') or '')
                state['memref'] = body.get('memoryReference') or (at.group(0) if at else None)

    def take_in(deadline):
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                kind, msg = a.q.get(timeout=left)
            except queue.Empty:
                return None
            if kind == 'eof':
                raise Fault('the adapter closed its output')
            if kind == 'bad':
                raise Fault(msg)
            rec('a2c', msg)
            if msg.get('type') == 'request':
                seq[0] += 1
                answer = {'seq': seq[0], 'type': 'response', 'request_seq': msg.get('seq'), 'success': False,
                          'command': msg.get('command'), 'message': 'the rows client runs no such request'}
                a.send(answer)
                rec('c2a', answer)
                rec('note', {'reverse-request': msg.get('command')})
                continue
            learn(msg)
            return msg

    def drain():
        # what has already arrived is read (and learnt from) before a placeholder is resolved
        while True:
            m = take_in(time.monotonic() + 0.05)
            if m is None:
                return
            pending.append(m)

    def response_for(s, what):
        for k, m in enumerate(pending):
            if m.get('type') == 'response' and m.get('request_seq') == s:
                return pending.pop(k)
        deadline = time.monotonic() + TIMEOUT
        while True:
            m = take_in(deadline)
            if m is None:
                raise Fault('no response to %s within %gs' % (what, TIMEOUT))
            if m.get('type') == 'response' and m.get('request_seq') == s:
                return m
            pending.append(m)

    def event_for(ev, fields):
        def fits(m):
            body = m.get('body') or {}
            return m.get('type') == 'event' and m.get('event') == ev and all(body.get(f) == x for f, x in (fields or {}).items())
        for k, m in enumerate(pending):
            if fits(m):
                return pending.pop(k)
        deadline = time.monotonic() + TIMEOUT
        while True:
            m = take_in(deadline)
            if m is None:
                raise Fault('no %s event%s within %gs' % (ev, ' ' + json.dumps(fields) if fields else '', TIMEOUT))
            if fits(m):
                return m
            pending.append(m)

    def request(command, args):
        seq[0] += 1
        msg = {'seq': seq[0], 'type': 'request', 'command': command}
        if args is not None:
            msg['arguments'] = subst(args)
        a.send(msg)
        rec('c2a', msg)
        return seq[0]

    def expect(command, r, want):
        if not want:
            return
        if 'success' in want and bool(r.get('success')) != want['success']:
            reds.append('%s: success is %s, not %s' % (command, str(bool(r.get('success'))).lower(), str(want['success']).lower()))
        if 'message' in want and r.get('message') != want['message']:
            reds.append('%s: message %r, not %r' % (command, r.get('message'), want['message']))
        if 'body_true' in want:
            body = r.get('body') or {}
            true = sorted(k for k, v in body.items() if v is True)
            extra = [k for k in true if k not in want['body_true']]
            missing = [k for k in want['body_true'] if k not in true]
            other = sorted(k for k, v in body.items() if v is not True)
            if extra:
                reds.append('%s: the body declares %s, which the row does not' % (command, ', '.join(extra)))
            if missing:
                reds.append('%s: the body does not declare %s' % (command, ', '.join(missing)))
            if other:
                reds.append('%s: the body has other members %s' % (command, ', '.join(other)))

    status = 'ok'
    try:
        for step in row['steps']:
            op = step[0]
            if op == 'send':
                r = response_for(request(step[1], step[2] if len(step) > 2 else None), step[1])
                expect(step[1], r, step[3] if len(step) > 3 else None)
            elif op == 'post':
                posted[step[1]] = request(step[1], step[2] if len(step) > 2 else None)
            elif op == 'reply':
                if step[1] not in posted:
                    raise Fault('reply to %s, which was never posted' % step[1])
                r = response_for(posted.pop(step[1]), step[1])
                expect(step[1], r, step[2] if len(step) > 2 else None)
            elif op == 'wait':
                e = event_for(step[1], step[2] if len(step) > 2 else None)
                if step[1] == 'stopped':
                    state['thread'] = (e.get('body') or {}).get('threadId', state['thread'])
            elif op == 'raw':
                data = step[1].encode('utf-8')
                a.write(data)
                rec('c2a', {'raw': step[1]})
            elif op == 'close':
                a.close_input()
                rec('note', {'closed': 'standard input'})
            elif op == 'sleep':
                end = time.monotonic() + float(step[1])
                while time.monotonic() < end:
                    m = take_in(end)
                    if m is not None:
                        pending.append(m)
            elif op == 'exit':
                deadline = time.monotonic() + 10
                while a.p.poll() is None and time.monotonic() < deadline:
                    try:
                        kind, m = a.q.get(timeout=0.2)
                    except queue.Empty:
                        continue
                    if kind == 'msg':
                        rec('a2c', m)
                if a.p.poll() is None:
                    raise Fault('the adapter did not end within 10s')
                if a.p.returncode != step[1]:
                    reds.append('exit: %d, not %d' % (a.p.returncode, step[1]))
            elif op == 'stderr':
                a.err.flush()
                text = Path(a.err_path).read_text(errors='replace')
                if not any(step[1] in ln for ln in text.splitlines()):
                    reds.append('stderr: no line holds %r' % step[1])
            else:
                raise Fault('no step %r' % (op,))
    except Fault as f:
        status = 'fault: %s' % f
    except (BrokenPipeError, OSError) as e:
        status = 'fault: the adapter pipe: %s' % e
    while True:
        try:
            kind, m = a.q.get(timeout=0.2)
        except queue.Empty:
            break
        if kind != 'msg':
            break
        rec('a2c', m)
    a.end()
    rec('note', {'status': status, 'reds': reds, 'adapter_exit': a.p.returncode})
    log.close()
    return status, reds


def selected(row, args):
    if args.only and not re.search(args.only, row['name']):
        return False
    has = row.get('prog', '-') != '-'
    return args.program == 'any' or (args.program == 'yes') == has


def skip(args):
    rows = [r for r in json.loads(Path(args.rows).read_text())['rows'] if selected(r, args)]
    for r in rows:
        print('SKIP dap %s reason=%s' % (r['name'], args.reason))
    print('dap rows (skip): %d skip' % len(rows))
    if len(rows) != args.expect:
        print('FAIL dap skip count: %d, not %d' % (len(rows), args.expect))
        return 1
    return 0


def check(args):
    # each row runs the adapter from its own directory: a path given relative to here is made whole first
    argv = [os.path.abspath(args.sniff), '--dap'] if args.sniff else args.adapter.split()
    rows = json.loads(Path(args.rows).read_text())['rows']
    args.out = os.path.abspath(args.out)
    os.makedirs(args.out, exist_ok=True)
    npass = nfail = nskip = 0
    for row in rows:
        if not selected(row, args):
            continue
        if row.get('skip'):
            print('SKIP dap %s reason=%s' % (row['name'], row['skip']))
            nskip += 1
            continue
        golden = None
        if row.get('compare') == 'gdb':
            gp = golden_path(row, args.cc, args.golden)
            if not gp.exists():
                print('FAIL dap %s fault: no golden %s' % (row['name'], gp))
                nfail += 1
                continue
            golden = json.loads(gp.read_text())
        status, reds = run_row(row, argv, args.fixtures or '', args.sources or '', args.cc, args.out)
        if status == 'ok' and golden is not None:
            try:
                names = row.get('differences', [])
                mine = normalise(records_of(os.path.join(args.out, row['name'] + '.jsonl')), names)
                d = first_difference(differ(golden, names), mine)
                if d and d[0] == 'sent':
                    status = 'fault: the golden is stale: ' + d[1]
                elif d:
                    reds.append('golden: ' + d[1])
            except Fault as f:
                status = 'fault: %s' % f
        if status != 'ok':
            print('FAIL dap %s %s' % (row['name'], status))
            nfail += 1
        elif reds:
            for r in reds:
                print('FAIL dap %s %s' % (row['name'], r))
            nfail += 1
        else:
            print('PASS dap %s' % row['name'])
            npass += 1
    print('dap rows (check): %d pass, %d fail, %d skip' % (npass, nfail, nskip))
    return 1 if nfail else 0


def capture(args):
    rows = json.loads(Path(args.rows).read_text())['rows']
    args.out = os.path.abspath(args.out)
    os.makedirs(args.golden, exist_ok=True)
    argv = args.adapter.split()
    ncap = nuns = nfault = 0
    for row in rows:
        if row.get('compare') != 'gdb' or (args.only and not re.search(args.only, row['name'])):
            continue
        takes, why = [], ''
        for n in (1, 2):
            out = os.path.join(args.out, 'take%d' % n)
            os.makedirs(out, exist_ok=True)
            status, _ = run_row(row, argv, args.fixtures or '', args.sources or '', args.cc, out)
            if status != 'ok':
                why = 'take %d %s' % (n, status)
                break
            takes.append(normalise(records_of(os.path.join(out, row['name'] + '.jsonl')), []))
        if why:
            print('FAULT dap %s %s' % (row['name'], why))
            nfault += 1
            continue
        d = first_difference(takes[0], takes[1])
        if d:
            print('UNSTABLE dap %s %s' % (row['name'], d[1]))
            nuns += 1
            continue
        gp = golden_path(row, args.cc, args.golden)
        body = dict({'schema': 1, 'row': row['name'], 'cc': args.cc if '@CC@' in row.get('prog', '') else None,
                     'identity': args.identity}, **takes[0])
        gp.write_text(json.dumps(body, indent=1, sort_keys=True) + '\n')
        print('CAPTURED dap %s' % row['name'])
        ncap += 1
    print('dap rows (capture): %d captured, %d unstable, %d fault' % (ncap, nuns, nfault))
    return 1 if nuns or nfault else 0


def selftest():
    """The client over the stand-in adapter: a plain session passes, each fault is named, and a red is a comparison."""
    standin = '%s -I %s' % (sys.executable, ROOT / 'tests/standin_dap.py')
    init = ['send', 'initialize', {'adapterID': 'selftest'}]
    cases = [
        ('plain', ['send', 'disconnect', {}, {'success': True}], 'PASS'),
        ('hang', ['post', 'launch', {}], None),
        ('eof', ['send', 'threads', {}], 'FAIL dap s fault: the adapter closed its output'),
        ('garbage', None, 'FAIL dap s fault: a body that is not JSON'),
        ('badcaps', None, 'FAIL dap s initialize: the body declares supportsStepBack'),
    ]
    ok = True
    global TIMEOUT
    TIMEOUT = 2.0
    with tempfile.TemporaryDirectory() as d:
        for mode, step, want in cases:
            steps = [init if mode != 'badcaps' else ['send', 'initialize', {}, {'body_true': ['supportsConfigurationDoneRequest']}]]
            if mode == 'hang':
                steps += [['post', 'launch', {}], ['wait', 'initialized'], ['send', 'pause', {'threadId': '@THREAD@'}],
                          ['wait', 'stopped'], ['send', 'stackTrace', {'threadId': '@THREAD@'}]]
                want = 'FAIL dap s fault: no response to stackTrace within 2s'
            elif step is not None:
                steps.append(step)
            out = os.path.join(d, mode)
            os.makedirs(out)
            status, reds = run_row({'name': 's', 'prog': '-', 'steps': steps}, (standin + ' ' + mode).split(), '', '', 'gcc', out)
            said = ['FAIL dap s %s' % status] if status != 'ok' else ['FAIL dap s %s' % r for r in reds] or ['PASS']
            hit = any(s.startswith(want) for s in said)
            print('%s session-dap-selftest %s: %s' % ('PASS' if hit else 'FAIL', mode, said[0]))
            ok = ok and hit
    print('%s session-dap-selftest rows=%d' % ('PASS' if ok else 'FAIL', len(cases)))
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest='mode', required=True)
    c = sub.add_parser('check')
    g = c.add_mutually_exclusive_group(required=True)
    g.add_argument('--sniff')
    g.add_argument('--adapter')
    c.add_argument('--rows', required=True)
    c.add_argument('--out', required=True)
    c.add_argument('--only', default='')
    c.add_argument('--fixtures', default='')
    c.add_argument('--sources', default='')
    c.add_argument('--cc', default='gcc')
    c.add_argument('--golden', default=str(GOLDEN))
    c.add_argument('--program', choices=('yes', 'no', 'any'), default='any')
    s = sub.add_parser('skip')
    s.add_argument('--rows', required=True)
    s.add_argument('--reason', required=True)
    s.add_argument('--expect', type=int, required=True)
    s.add_argument('--program', choices=('yes', 'no', 'any'), default='any')
    s.add_argument('--only', default='')
    k = sub.add_parser('capture')
    k.add_argument('--adapter', required=True)
    k.add_argument('--rows', required=True)
    k.add_argument('--out', required=True)
    k.add_argument('--golden', required=True)
    k.add_argument('--only', default='')
    k.add_argument('--fixtures', default='')
    k.add_argument('--sources', default='')
    k.add_argument('--cc', default='gcc')
    k.add_argument('--identity', default='')
    sub.add_parser('selftest')
    args = p.parse_args()
    if args.mode == 'selftest':
        return selftest()
    if args.mode == 'capture':
        return capture(args)
    if args.mode == 'skip':
        return skip(args)
    return check(args)


if __name__ == '__main__':
    sys.exit(main())
