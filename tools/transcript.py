#!/usr/bin/env python3
"""Binary oracle capture and explicit semantic session assertions.

Raw bytes are retained separately from normalized display text. Observations
are not a claim that LLDB and GDB have the same command or output language.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

NORMALIZATIONS = {
    'addresses': 'Debugger frame PCs and breakpoint insertion addresses only; scalar hex values are preserved.',
    'pids': 'Process N, process N and pid=N debugger fields only; scalar integers are preserved.',
    'timestamps': 'Explicit timestamp=ISO-8601 fields only; normally no timestamps are emitted.',
    'paths': 'Exact configured root prefix followed by / only; filenames and source coordinates are preserved.'}


def normalize(text, root):
    text = text.replace(str(Path(root).absolute()).rstrip('/') + '/', '<ROOT>/')
    text = re.sub(r'(frame #\d+: )0x[0-9a-fA-F]+', r'\1<ADDRESS>', text)
    text = re.sub(r'(^#\d+\s+)0x[0-9a-fA-F]+', r'\1<ADDRESS>', text, flags=re.M)
    text = re.sub(r'(Breakpoint \d+(?:\.\d+)? at )0x[0-9a-fA-F]+', r'\1<ADDRESS>', text)
    text = re.sub(r'\b(Process |process |pid=)\d+', r'\1<PID>', text)
    return re.sub(r'timestamp=\d{4}-\d\d-\d\dT[0-9:.]+Z', 'timestamp=<TIMESTAMP>', text)


def compare(expected, actual):
    if expected.get('schema') != 1 or actual.get('schema') != 1:
        raise ValueError('unsupported session schema')
    want, got = expected.get('events'), actual.get('events')
    if not isinstance(want, list) or not want or not isinstance(got, list):
        raise ValueError('a session must have nonempty expected events and actual event list')
    if [e['name'] for e in want] != [e['name'] for e in got]:
        print('FAIL event-order expected=' + repr([e['name'] for e in want]) +
              ' actual=' + repr([e['name'] for e in got]))
        return 1
    failures = []
    for w, g in zip(want, got):
        if 'line' in w and w['line'] != g.get('line'):
            failures.append(f"FAIL wrong-line-order event={w['name']} expected={w['line']} actual={g.get('line')}")
        for name, value in w.get('locals', {}).items():
            if g.get('locals', {}).get(name) != value:
                failures.append(f"FAIL wrong-value event={w['name']} local={name} expected={value} actual={g.get('locals', {}).get(name)}")
        prefix = w.get('frame_prefix', [])
        if g.get('frames', [])[:len(prefix)] != prefix:
            failures.append(f"FAIL missing-frame event={w['name']} expected_prefix={prefix!r} actual={g.get('frames', [])!r}")
        for snippet in w.get('contains', []):
            if snippet not in g.get('text', ''):
                failures.append(f"FAIL transcript-text event={w['name']} missing={snippet!r}")
    for failure in failures:
        print(failure)
    if not failures:
        print('PASS session events=' + str(len(want)))
    return int(bool(failures))


def parse_event(name, text, source):
    frames = []
    for line in text.splitlines():
        m = re.search(r'frame #\d+:.*?`([^\s(+:]+)', line)
        if not m:
            m = re.match(r'^#\d+\s+(?:0x[0-9a-fA-F]+ in )?([^\s(]+)', line)
        if m:
            frames.append(m[1])
    # The stop display and subsequent bt repeat frames. Keep the first trace,
    # ending on a repeated frame 0, rather than deleting duplicate function names
    # (which would destroy recursion). Parse bt frames preferentially.
    traces = re.split(r'(?=^\s*(?:\*\s*)?frame #0:|^#0\s)', text, flags=re.M)
    if len(traces) > 1:
        last = traces[-1]
        frames = []
        for line in last.splitlines():
            m = re.search(r'frame #\d+:.*?`([^\s(+:]+)', line)
            if not m:
                m = re.match(r'^#\d+\s+(?:0x[0-9a-fA-F]+ in )?([^\s(]+)', line)
            if m:
                frames.append(m[1])
    values = {}
    for line in text.splitlines():
        m = re.match(r'^\([^\n]+?\)\s+([A-Za-z_][A-Za-z_0-9]*) = (.+)$', line)
        if not m:
            m = re.match(r'^SNIFF_VALUE ([A-Za-z_][A-Za-z_0-9]*)=(.+)$', line)
        if m:
            values[m[1]] = m[2].strip()
    location = re.search(r'\bat [^\n]*?' + re.escape(source) + r':(\d+)', text)
    if not location:
        location = re.search(r'^\s*(?:->\s*)?(\d+)\s+\S', text, re.M)
    return {'name': name, 'line': int(location[1]) if location else None,
            'locals': values, 'frames': frames, 'text': text}


def capture(args):
    spec = json.loads(Path(args.spec).read_text())
    commands = []
    if args.oracle == 'gdb':
        commands += ['set confirm off', 'set pagination off', 'set print frame-arguments all']
    def marker(value):
        return 'script print("' + value + '")' if args.oracle == 'lldb' else 'echo ' + value + r'\n'
    for event in spec['events']:
        commands.append(marker('SNIFF_ROW ' + event['name']))
        commands.extend(event['commands'][args.oracle])
        commands.append(marker('SNIFF_END ' + event['name']))
    commands.append('quit')
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    script = out / ('session.' + args.oracle)
    script.write_text('\n'.join(commands) + '\n')
    cmd = ([args.debugger, '-b', '-s', str(script), args.binary] if args.oracle == 'lldb'
           else [args.debugger, '--batch', '-nx', '-x', str(script), args.binary])
    env = dict(os.environ, LC_ALL='C', TZ='UTC', TERM='dumb')
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env, timeout=90)
    (out / 'stdout.txt').write_bytes(p.stdout)
    (out / 'stderr.txt').write_bytes(p.stderr)
    text = p.stdout.decode('utf-8', 'replace')
    events = []
    for event in spec['events']:
        # Match emitted lines, never the debugger's echoed script/echo command.
        pattern = r'^SNIFF_ROW ' + re.escape(event['name']) + r'\n(.*?)^SNIFF_END ' + re.escape(event['name']) + r'\s*$'
        m = re.search(pattern, text, re.M | re.S)
        if not m:
            raise ValueError('missing event delimiter: ' + event['name'] + '; inspect raw transcript')
        events.append(parse_event(event['name'], m[1], spec['source']))
    version = subprocess.check_output([args.debugger, '--version'], text=True).strip()
    record = {'schema': 1, 'oracle': args.oracle, 'version': version,
              'exit': p.returncode, 'normalizations': NORMALIZATIONS,
              'events': events,
              'normalized_stdout': normalize(text, args.root),
              'normalized_stderr': normalize(p.stderr.decode('utf-8', 'replace'), args.root)}
    (out / 'record.json').write_text(json.dumps(record, indent=2) + '\n')
    expected = {'schema': 1, 'events': [{k: v for k, v in e.items() if k != 'commands'} for e in spec['events']]}
    (out / 'expected.json').write_text(json.dumps(expected, indent=2) + '\n')
    if p.returncode:
        print('FAIL oracle-exit code=' + str(p.returncode))
        return 1
    return compare(expected, record)


def mutate(args):
    record = json.loads(Path(args.actual).read_text())
    expected = json.loads(Path(args.expected).read_text())
    for row in ('wrong-value', 'wrong-line-order', 'missing-frame'):
        bad = copy.deepcopy(record)
        if row == 'wrong-value':
            event = next(e for e in bad['events'] if e.get('locals'))
            key = next(iter(event['locals']))
            event['locals'][key] += '-injected-wrong-value'
        elif row == 'wrong-line-order':
            have = [e for e in bad['events'] if e.get('line') is not None]
            if len(have) < 2 or have[0]['line'] == have[1]['line']:
                raise ValueError('line-order selftest needs two distinct measured lines')
            have[0]['line'], have[1]['line'] = have[1]['line'], have[0]['line']
        else:
            event = next(e for e in bad['events'] if len(e.get('frames', [])) >= 2)
            event['frames'].pop(1)
        if compare(expected, bad) != 1:
            print('FAIL mutation-not-detected row=' + row)
            return 1
        print('PASS rejected-' + row)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    c = sub.add_parser('compare'); c.add_argument('expected'); c.add_argument('actual')
    n = sub.add_parser('normalize'); n.add_argument('--root', required=True)
    c = sub.add_parser('capture')
    for key in ('spec', 'oracle', 'debugger', 'binary', 'out', 'root'):
        c.add_argument('--' + key, required=True)
    m = sub.add_parser('selftest'); m.add_argument('expected'); m.add_argument('actual')
    args = parser.parse_args()
    try:
        if args.mode == 'normalize':
            sys.stdout.write(normalize(sys.stdin.read(), args.root)); return 0
        if args.mode == 'capture': return capture(args)
        if args.mode == 'selftest': return mutate(args)
        return compare(json.loads(Path(args.expected).read_text()), json.loads(Path(args.actual).read_text()))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print('FAIL harness-input ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
