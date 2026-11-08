#!/usr/bin/env python3
"""Join sniff's live locals with lupin's true values for wolf programs.

lupin records the state AFTER each statement; a debugger stopped on a line
shows the state BEFORE that line. For each wolf function the join steps sniff
with `next` from the function's first line, prints `info args` and `info
locals` at every stop, and requires that stop's values to equal the values of
a lupin row of the same function for every variable lupin reports live. Rows
are taken in order: a stop never matches an earlier row than its predecessor.
Variables sniff prints that lupin does not yet report live (declared later in
the function, so only the frame's memory) are counted as `unverified`, never
as agreement. A one-byte integer agrees through its number: gdb's form
`255 '\\377'` shows the character too. Since wolf 0.2.38 the unsigned types are
unsigned in the DWARF (R-sn00-1), so no value is reinterpreted any more: a signed
reading of an unsigned value is a disagreement.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

CASES = [
    ('wolf/scalars', 'helper', 3),
    ('wolf/nested', 'inner', 2),
    ('wolf/nested', 'outer', 2),
    ('wolf/loops', 'sum', 14),
    ('wolf/types', 'scalars', 6),
]
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
CWD = '/work'


def sniff_stops(sniff, fixtures, case, function, count, work):
    program = Path(fixtures) / case.split('/')[0] / case.split('/')[1] / 'wolf-debug' / 'prog'
    lines = ['break ' + function, 'run']
    for _ in range(count + 1):
        lines += ['echo @@STOP\\n', 'frame', 'echo @@ARGS\\n', 'info args', 'echo @@LOCALS\\n', 'info locals', 'next']
    script = Path(work) / ('values-' + case.replace('/', '-') + '-' + function + '.cmd')
    script.write_text('\n'.join(lines) + '\n')
    run = subprocess.run([sniff, '-batch', '-x', str(script), str(program)], cwd=CWD, env=ENV,
                         capture_output=True, text=True, timeout=60)
    stops = []
    for chunk in run.stdout.split('@@STOP\n')[1:]:
        head, _, rest = chunk.partition('@@ARGS\n')
        arg_text, _, local_text = rest.partition('@@LOCALS\n')
        m = re.match(r'^#0\s+(?:0x[0-9a-f]+ in )?(\S+) \(', head)
        stop = {'function': m.group(1) if m else '', 'args': {}, 'locals': {}}
        for key, text in (('args', arg_text), ('locals', local_text)):
            for line in text.splitlines():
                m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*) = (.*)$', line)
                if m:
                    stop[key][m.group(1)] = m.group(2)
        stops.append(stop)
    return stops


def number(text):
    m = re.match(r"^(-?\d+)( '.*')?$", text)
    return int(m.group(1)) if m else None


def agree(sniff_text, row, name):
    """Whether sniff's text is lupin's value."""
    live = row['locals'][name]
    if sniff_text == live:
        return True
    n = number(sniff_text)
    return n is not None and str(n) == live


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--values', required=True, type=Path)
    p.add_argument('--fixtures', required=True, type=Path)
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--out', type=Path)
    p.add_argument('--cwd', default='/work')
    a = p.parse_args()
    global CWD
    CWD = a.cwd
    if a.cwd != '/work':
        ENV.update({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': a.cwd})
    Path(a.work).mkdir(parents=True, exist_ok=True)
    values = json.loads(a.values.read_text())
    record = []
    failures = 0
    for case, function, count in CASES:
        rows = [r for f in values['fixtures'] if f['id'] == case for r in f['rows'] if r['function'] == function]
        stops = sniff_stops(a.sniff, a.fixtures, case, function, count, a.work)
        pointer = 0
        agreed = unverified = matched = 0
        stops = [st for st in stops if st['function'] == function]
        for k, whole in enumerate(stops):
            stop = dict(whole['args'])
            stop.update(whole['locals'])
            first_match = None
            if k == 0:
                for j in range(len(rows)):
                    ok = True
                    for name in rows[j]['locals']:
                        if name not in stop or not agree(stop[name], rows[j], name):
                            ok = False
                            break
                    if ok:
                        first_match = j
                        break
            if k == 0 and first_match is not None:
                # the breakpoint is already past every statement lupin names before it
                pointer = first_match
                matched += 1
                agreed += len(rows[first_match]['locals'])
                unverified += len([n for n in stop if n not in rows[first_match]['locals']])
                continue
            if k == 0:
                # entry stop: only the arguments are live, and lupin's first row names them
                first = rows[0]['locals']
                bad = [n for n in whole['args'] if n in first and not agree(whole['args'][n], rows[0], n)]
                if bad:
                    print('FAIL value-join-entry %s %s %s' % (case, function, bad))
                    failures += 1
                continue
            found = None
            for j in range(pointer, len(rows)):
                ok = True
                for name in rows[j]['locals']:
                    if name not in stop or not agree(stop[name], rows[j], name):
                        ok = False
                        break
                if ok:
                    found = j
                    break
            if found is None:
                print('FAIL value-join-stop %s %s stop=%d values=%r' % (case, function, k, stop))
                failures += 1
                continue
            pointer = found
            matched += 1
            agreed += len(rows[found]['locals'])
            unverified += len([n for n in stop if n not in rows[found]['locals']])
        if matched < 1:
            print('FAIL value-join-%s-%s: no stop matched a lupin row (stops=%d rows=%d)' % (case.replace('/', '-'), function, len(stops), len(rows)))
            failures += 1
        else:
            print('PASS value-join %s %s stops=%d matched=%d agreed_values=%d unverified=%d' %
                  (case, function, len(stops), matched, agreed, unverified))
        record.append({'case': case, 'function': function, 'stops': stops, 'matched': matched})
    if a.out:
        a.out.write_text(json.dumps(record, indent=1) + '\n')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
