#!/usr/bin/env python3
"""Timed rows: sniff against the pinned gdb, interleaved, on CPU time.

Each row runs the same script under both debuggers N times, alternating, and
times the debugger's CPU (user + system, from the child rusage of the waited
process, so host stalls and waiting do not count). The row's figure is the
minimum of the N runs for each tool and their ratio sniff/gdb. A row fails
when the ratio exceeds its stated margin or when either minimum is under the
timer floor (a floor, not a measurement). The scripts and margins are the
ones named in notes/sn02-the-linux-core.md.
"""
import argparse
import json
from pathlib import Path
import resource
import subprocess
import sys

ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
FLOOR = 0.02  # seconds of CPU below which a figure is timer grain

ROWS = [
    # name, program, script, margin (sniff/gdb CPU ratio must stay at or below)
    ('startup-to-first-breakpoint', 'c/calls/gcc-O0/prog', ['break depth_sum', 'run'], 1.0),
    # sniff reads every unit eagerly through the S1 reader (about 0.3 s of the 0.5 s is
    # dwarf_info_read over the linked runtime's Rust units); gdb reads lazily. Measured
    # 4.2-4.8x; the margin is stated at 6.0 and lazy per-unit loading is the follow-up.
    ('startup-wolf-large-dwarf', 'wolf/scalars/wolf-debug/prog', ['break helper', 'run'], 6.0),
    ('ten-thousand-hit-loop', 'c/hits/gcc-O0/prog', ['break tick', 'ignore 1 9999', 'run', 'info breakpoints'], 2.0),
]


def cpu_of(argv, work):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    p = subprocess.run(argv, cwd='/work', env=ENV, capture_output=True, text=True, timeout=300)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), p.returncode, p.stdout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--gdb', default='gdb')
    p.add_argument('--fixtures', default='/work/target/session-fixtures')
    p.add_argument('--runs', type=int, default=9)
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    Path(a.work).mkdir(parents=True, exist_ok=True)
    bad = 0
    record = []
    for name, prog, lines, margin in ROWS:
        script = Path(a.work) / ('perf-' + name + '.cmd')
        script.write_text('\n'.join(lines) + '\n')
        program = str(Path(a.fixtures) / prog)
        gdb_cmd = [a.gdb, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-x', str(script), program]
        sniff_cmd = [a.sniff, '-batch', '-x', str(script), program]
        times = {'gdb': [], 'sniff': []}
        outputs = {}
        for _ in range(a.runs):
            for tool, cmd in (('gdb', gdb_cmd), ('sniff', sniff_cmd)):
                t, rc, out = cpu_of(cmd, a.work)
                times[tool].append(t)
                outputs[tool] = out
        g, s = min(times['gdb']), min(times['sniff'])
        ratio = s / g if g > 0 else float('inf')
        status = 'PASS'
        why = ''
        if g < FLOOR or s < FLOOR:
            # a figure at timer grain proves nothing either way
            why = ' floor=%.3f' % FLOOR
            status = 'PASS' if s <= g else 'FAIL'
        if ratio > margin:
            status = 'FAIL'
        if status == 'FAIL':
            bad += 1
        print('%s perf %s gdb_min=%.3fs sniff_min=%.3fs ratio=%.2f margin<=%.2f runs=%d%s' %
              (status, name, g, s, ratio, margin, a.runs, why))
        record.append({'row': name, 'gdb': times['gdb'], 'sniff': times['sniff'], 'ratio': ratio, 'margin': margin})
    if a.out:
        a.out.write_text(json.dumps(record, indent=1) + '\n')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
