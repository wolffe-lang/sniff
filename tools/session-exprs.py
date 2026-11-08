#!/usr/bin/env python3
"""Wolf expressions held to lupin's values (S5).

lupin's place trace names every place a statement touched by its path (`p.x`, `p.hist[2]`) with its
value after that statement. A debugger stopped before the next statement must print the same value
for the same path: the path is a wolf expression (field access, indexing through a List's header),
evaluated by sniff's wolf mode. Arithmetic and comparisons over those places are held to the values
the wolf spec's rules give (integer arithmetic on the places' values; a comparison is a bool).
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}

# fixture, the stop (file:line), lupin's row whose state is the stop's (the statement just before),
# the function, and derived expressions with how their value follows from the places' values.
# The stop is inside bump, whose `mut p: Point` is a reference: wolf 0.2.38 places main's own struct
# local at a frame slot that does not hold it (gdb and lldb read the same wrong bytes there), so the
# struct is reached where its location is right (notes/sn05-the-repin-and-s5.md).
CASES = [
    ('wolf/aggregates', 'main.lu:10', '9:', 'bump', [
        ('p.x + by', lambda v: str(int(v['p.x']) + int(v['by']))),
        ('p.hist[2] * 2 - p.y', lambda v: str(int(v['p.hist[2]']) * 2 - int(v['p.y']))),
        ('(p.x + p.y) % by', lambda v: str((int(v['p.x']) + int(v['p.y'])) % int(v['by']))),
        ('p.x == 4', lambda v: 'true' if int(v['p.x']) == 4 else 'false'),
        ('p.hist[2] > by && p.y < 10', lambda v: 'true' if int(v['p.hist[2]']) > int(v['by']) and int(v['p.y']) < 10 else 'false'),
    ]),
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--values', required=True, type=Path)
    p.add_argument('--fixtures', required=True, type=Path)
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--cwd', default='/work')
    a = p.parse_args()
    env = dict(ENV)
    if a.cwd != '/work':
        env.update({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': a.cwd})
    Path(a.work).mkdir(parents=True, exist_ok=True)
    values = json.loads(a.values.read_text())
    bad = 0
    for case, where, at, function, derived in CASES:
        rows = [r for f in values['fixtures'] if f['id'] == case for r in f['rows']
                if r['function'] == function and r['at'].startswith(at)]
        if not rows:
            print('FAIL expr-join-%s no lupin row at %s' % (case.replace('/', '-'), at))
            bad += 1
            continue
        live = rows[-1]['locals']
        exprs = [(path, val) for path, val in live.items()]
        exprs += [(e, f(live)) for e, f in derived]
        lines = ['break ' + where, 'run']
        for e, _ in exprs:
            lines += ['echo @@E\\n', 'print ' + e]
        script = Path(a.work) / ('exprs-' + case.replace('/', '-') + '.cmd')
        script.write_text('\n'.join(lines) + '\n')
        prog = a.fixtures / case.split('/')[0] / case.split('/')[1] / 'wolf-debug' / 'prog'
        run = subprocess.run([a.sniff, '-batch', '-x', str(script), str(prog)], cwd=a.cwd, env=env,
                             capture_output=True, text=True, timeout=60)
        chunks = run.stdout.split('@@E\n')
        if 'at ' not in chunks[0] or (':' + where.split(':')[1]) not in chunks[0]:
            print('FAIL expr-join-%s the stop is not %s: %r' % (case.replace('/', '-'), where, chunks[0][-200:]))
            bad += 1
            continue
        agreed = 0
        for (e, want), got_text in zip(exprs, chunks[1:]):
            m = re.match(r'^\$\d+ = (.*)$', got_text.strip())
            got = m.group(1) if m else got_text.strip() or run.stderr.strip()
            if got != want:
                print('FAIL expr-join %s `%s` lupin=%s sniff=%s' % (case, e, want, got))
                bad += 1
            else:
                agreed += 1
        if len(chunks) - 1 < len(exprs):
            print('FAIL expr-join %s printed %d of %d (%s)' % (case, len(chunks) - 1, len(exprs), run.stderr.strip()))
            bad += 1
        print('%s expr-join %s at %s places=%d derived=%d agreed=%d' % ('PASS' if bad == 0 else 'INFO', case, where,
              len(live), len(derived), agreed))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
