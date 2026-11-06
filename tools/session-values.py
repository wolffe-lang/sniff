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
as agreement. A one-byte or wide integer whose DWARF encoding is signed while
the source type is unsigned is accepted only through its unsigned
reinterpretation and is counted under gap R-sn00-1.
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
BITS = {'u8': 8, 'u16': 16, 'u32': 32, 'u64': 64, 'uint': 64}
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}


def sniff_stops(sniff, fixtures, case, function, count, work):
    program = Path(fixtures) / case.split('/')[0] / case.split('/')[1] / 'wolf-debug' / 'prog'
    lines = ['break ' + function, 'run']
    for _ in range(count + 1):
        lines += ['echo @@STOP\\n', 'frame', 'echo @@ARGS\\n', 'info args', 'echo @@LOCALS\\n', 'info locals', 'next']
    script = Path(work) / ('values-' + case.replace('/', '-') + '-' + function + '.cmd')
    script.write_text('\n'.join(lines) + '\n')
    run = subprocess.run([sniff, '-batch', '-x', str(script), str(program)], cwd='/work', env=ENV,
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
    """True, 'gap' or False."""
    live = row['locals'][name]
    if sniff_text == live:
        return True
    kind = next((p['type'] for p in row['places'] if p['path'] == name), '')
    bits = BITS.get(kind)
    n = number(sniff_text)
    if bits and n is not None and n < 0 and str(n + (1 << bits)) == live:
        return 'gap'
    return False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--values', required=True, type=Path)
    p.add_argument('--fixtures', required=True, type=Path)
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    Path(a.work).mkdir(parents=True, exist_ok=True)
    values = json.loads(a.values.read_text())
    record = []
    failures = 0
    for case, function, count in CASES:
        rows = [r for f in values['fixtures'] if f['id'] == case for r in f['rows'] if r['function'] == function]
        stops = sniff_stops(a.sniff, a.fixtures, case, function, count, a.work)
        pointer = 0
        agreed = unverified = gaps = matched = 0
        stops = [st for st in stops if st['function'] == function]
        for k, whole in enumerate(stops):
            stop = dict(whole['args'])
            stop.update(whole['locals'])
            first_match = None
            if k == 0:
                for j in range(len(rows)):
                    ok = True
                    for name in rows[j]['locals']:
                        if name not in stop or agree(stop[name], rows[j], name) is False:
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
                bad = [n for n in whole['args'] if n in first and agree(whole['args'][n], rows[0], n) is False]
                if bad:
                    print('FAIL value-join-entry %s %s %s' % (case, function, bad))
                    failures += 1
                continue
            found = None
            for j in range(pointer, len(rows)):
                ok = True
                gap = 0
                for name in rows[j]['locals']:
                    if name not in stop:
                        ok = False
                        break
                    r = agree(stop[name], rows[j], name)
                    if r is False:
                        ok = False
                        break
                    gap += 1 if r == 'gap' else 0
                if ok:
                    found = (j, gap)
                    break
            if found is None:
                print('FAIL value-join-stop %s %s stop=%d values=%r' % (case, function, k, stop))
                failures += 1
                continue
            pointer = found[0]
            matched += 1
            agreed += len(rows[found[0]]['locals'])
            gaps += found[1]
            unverified += len([n for n in stop if n not in rows[found[0]]['locals']])
        if matched < 1:
            print('FAIL value-join-%s-%s: no stop matched a lupin row (stops=%d rows=%d)' % (case.replace('/', '-'), function, len(stops), len(rows)))
            failures += 1
        else:
            print('PASS value-join %s %s stops=%d matched=%d agreed_values=%d unverified=%d gap_R-sn00-1=%d' %
                  (case, function, len(stops), matched, agreed, unverified, gaps))
        record.append({'case': case, 'function': function, 'stops': stops, 'matched': matched})
    if a.out:
        a.out.write_text(json.dumps(record, indent=1) + '\n')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
