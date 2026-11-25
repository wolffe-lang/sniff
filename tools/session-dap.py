#!/usr/bin/env python3
"""The DAP rows (S9): a scripted Debug Adapter Protocol client that drives an adapter over its standard input and
output, records every message both ways, and holds what the adapter answers to the row's expectations.

  session-dap.py check (--sniff PATH | --adapter 'CMD ARGS…') --rows FILE --out DIR [--only REGEX]
                       [--fixtures DIR --sources DIR --cc gcc|clang]
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
variablesReference or nonzero variable reference of the last stackTrace, scopes or variables response).

A row passes when every expectation holds: `PASS dap ROW`. An expectation that does not hold is a red by comparison:
`FAIL dap ROW WHAT: …`. A timeout, an adapter that has gone away (one fault, `the adapter went away`, whether a write
or a read finds out first), a body that is not JSON, or a placeholder with nothing to name is a fault, never a red:
`FAIL dap ROW fault: …`. A request from the adapter
(runInTerminal, startDebugging) is answered success: false and noted. The last line is
`dap rows (check): P pass, F fail, S skip`; the exit is 1 when any row failed."""
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
# An adapter that has gone away is one fault, whichever of a write (a broken pipe) or a read (the end of its output)
# finds out first.
GONE = 'the adapter went away'
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
        try:
            self.p.stdin.write(data)
            self.p.stdin.flush()
        except (BrokenPipeError, ConnectionResetError):
            raise Fault(GONE)

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

    state = {'thread': None, 'frames': [], 'scopes': [], 'vars': [], 'threads': [], 'started': []}
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
                raise Fault(GONE)
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
    except OSError as e:
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


def check(args):
    # each row runs the adapter from its own directory: a path given relative to here is made whole first
    argv = [os.path.abspath(args.sniff), '--dap'] if args.sniff else args.adapter.split()
    rows = json.loads(Path(args.rows).read_text())['rows']
    args.out = os.path.abspath(args.out)
    os.makedirs(args.out, exist_ok=True)
    npass = nfail = nskip = 0
    for row in rows:
        if args.only and not re.search(args.only, row['name']):
            continue
        if row.get('skip'):
            print('SKIP dap %s reason=%s' % (row['name'], row['skip']))
            nskip += 1
            continue
        status, reds = run_row(row, argv, args.fixtures or '', args.sources or '', args.cc, args.out)
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


def selftest():
    """The client over the stand-in adapter: a plain session passes, each fault is named, and a red is a comparison."""
    standin = '%s -I %s' % (sys.executable, ROOT / 'tests/standin_dap.py')
    init = ['send', 'initialize', {'adapterID': 'selftest'}]
    cases = [
        ('plain', ['send', 'disconnect', {}, {'success': True}], 'PASS'),
        ('hang', ['post', 'launch', {}], None),
        ('eof', ['send', 'threads', {}], 'FAIL dap s fault: ' + GONE),
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
    sub.add_parser('selftest')
    args = p.parse_args()
    if args.mode == 'selftest':
        return selftest()
    return check(args)


if __name__ == '__main__':
    sys.exit(main())
