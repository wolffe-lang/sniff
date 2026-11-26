#!/usr/bin/env python3
"""A stand-in debug adapter for session-dap.py's units, never a debugger: standin_dap.py MODE

It speaks the Debug Adapter Protocol's base protocol on standard input and output and debugs nothing. MODE:
  plain    initialize answers capabilities {supportsConfigurationDoneRequest: true}; launch is answered at once and a
           thread event reports thread 7 started; configurationDone is answered; threads is refused notStopped until a
           pause, which stops thread 7 (reason pause); stackTrace answers three frames; disconnect ends with exit 0
  hang     as plain, but never answers stackTrace
  eof      closes its output after answering initialize
  garbage  answers initialize with a body that is not JSON
  reverse  sends a runInTerminal request before answering initialize
  badcaps  as plain, but initialize declares supportsStepBack too
  exit3    on disconnect, exits 3 and writes `stand-in: exit 3` on standard error
  deaf     closes its standard input before it answers initialize, then stays (its output open) for 5 s: the client's
           next write finds it gone, before any read could
  mute     closes its standard output after it answers initialize, then stays (its input open) for 5 s: the client's
           next write succeeds and its read finds it gone
  gdbish   as plain, but answers configurationDone notStopped (as the pinned gdb, which starts the program at launch),
           and its thread id and addresses are its own process id's
  jitter   as plain, but the first frame's line is its own process id's: two takes differ
  otherline  as plain, but the second frame's line is 99
In every mode evaluate answers `(int *) 0x1234` and readMemory four bytes at the reference it is given, and attach
(whatever its arguments) is answered, then initialized and a stop of thread 7 with reason attach."""
import json
import os
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else 'plain'
inp, out = sys.stdin.buffer, sys.stdout.buffer
seq = 0


def send_raw(body):
    out.write(b'Content-Length: %d\r\n\r\n' % len(body) + body)
    out.flush()


def send(msg):
    global seq
    seq += 1
    send_raw(json.dumps(dict(msg, seq=seq)).encode())


def reply(req, body=None, ok=True, message=None):
    m = {'type': 'response', 'request_seq': req['seq'], 'command': req['command'], 'success': ok}
    if body is not None:
        m['body'] = body
    if message:
        m['message'] = message
    send(m)


def event(name, body=None):
    send({'type': 'event', 'event': name, **({'body': body} if body is not None else {})})


def read():
    n = None
    while True:
        line = inp.readline()
        if not line:
            return None
        if line == b'\r\n':
            break
        k, _, v = line.decode().partition(':')
        if k.lower() == 'content-length':
            n = int(v)
    return json.loads(inp.read(n))


running = False
tid = os.getpid() if mode == 'gdbish' else 7
base = os.getpid() * 16 if mode == 'gdbish' else 4096
while True:
    r = read()
    if r is None:
        break
    if r.get('type') == 'response':
        continue
    c = r['command']
    if c == 'initialize':
        if mode == 'reverse':
            send({'type': 'request', 'command': 'runInTerminal', 'arguments': {'args': ['x']}})
        if mode == 'garbage':
            send_raw(b'{not json')
            continue
        caps = {'supportsConfigurationDoneRequest': True}
        if mode == 'badcaps':
            caps['supportsStepBack'] = True
        if mode == 'deaf':
            os.close(0)
        reply(r, caps)
        if mode == 'eof':
            sys.exit(0)
        if mode == 'deaf':
            time.sleep(5)
            sys.exit(0)
        if mode == 'mute':
            os.close(1)
            time.sleep(5)
            sys.exit(0)
    elif c == 'launch':
        reply(r)
        event('initialized')
        event('thread', {'reason': 'started', 'threadId': tid})
        running = True
    elif c == 'attach':
        # whatever it is given (a pid, a core), the stand-in attaches nothing: it answers, and stops its thread
        reply(r)
        event('initialized')
        event('stopped', {'reason': 'attach', 'threadId': tid, 'allThreadsStopped': True})
        running = False
    elif c == 'configurationDone':
        if mode == 'gdbish':
            reply(r, ok=False, message='notStopped')
        else:
            reply(r)
    elif c == 'threads':
        if running:
            reply(r, ok=False, message='notStopped')
        else:
            reply(r, {'threads': [{'id': tid, 'name': 'main'}]})
    elif c == 'pause':
        reply(r)
        running = False
        event('stopped', {'reason': 'pause', 'threadId': tid, 'allThreadsStopped': True})
    elif c == 'stackTrace':
        if mode == 'hang':
            continue
        frames = [{'id': 100 + i, 'name': 'f%d' % i, 'line': i + 1, 'column': 1,
                   'instructionPointerReference': '0x%x' % (base + i)} for i in range(3)]
        if mode == 'jitter':
            frames[0]['line'] = os.getpid()
        if mode == 'otherline':
            frames[1]['line'] = 99
        reply(r, {'stackFrames': frames})
    elif c == 'evaluate':
        reply(r, {'result': '(int *) 0x1234', 'variablesReference': 0})
    elif c == 'readMemory':
        reply(r, {'address': r['arguments']['memoryReference'], 'data': '+f///w=='})
    elif c == 'disconnect':
        reply(r)
        event('terminated')
        if mode == 'exit3':
            sys.stderr.write('stand-in: exit 3\n')
            sys.stderr.flush()
            sys.exit(3)
        sys.exit(0)
    else:
        reply(r, ok=False, message='unknown request ' + c)
