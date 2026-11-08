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
CWD = '/work'
# macOS (S3): the oracle is Apple's lldb and the C fixtures are clang's. Same three rows,
# each as lldb commands. lldb's ignore count is set with `breakpoint modify -i`.
MAC_ROWS = [
    ('startup-to-first-breakpoint', 'c/calls/clang-O0/prog', ['break depth_sum', 'run'],
     ['breakpoint set -n depth_sum', 'run', 'process kill'], 1.0),
    ('startup-wolf-large-dwarf', 'wolf/scalars/wolf-debug/prog', ['break helper', 'run'],
     ['breakpoint set -n helper', 'run', 'process kill'], 6.0),
    ('ten-thousand-hit-loop', 'c/hits/clang-O0/prog', ['break tick', 'ignore 1 9999', 'run', 'info breakpoints'],
     ['breakpoint set -n tick', 'breakpoint modify -i 9999 1', 'run', 'breakpoint list', 'process kill'], 2.0),
]
FLOOR = 0.02  # seconds of CPU below which a figure is timer grain

ROWS = [
    # name, program, script, margin (sniff/gdb CPU ratio must stay at or below)
    ('startup-to-first-breakpoint', 'c/calls/gcc-O0/prog', ['break depth_sum', 'run'], 1.0),
    # sniff reads every unit eagerly through the S1 reader; gdb reads lazily. Measured 1.90x
    # locally after sniff#10's cuts (from 4.75x). The margin is that local ratio times 1.43,
    # the worst hosted-to-local factor seen, times 1.25 headroom, rounded up to a half: 3.5
    # (notes/sn05-the-repin-and-s5.md).
    ('startup-wolf-large-dwarf', 'wolf/scalars/wolf-debug/prog', ['break helper', 'run'], 3.5),
    ('ten-thousand-hit-loop', 'c/hits/gcc-O0/prog', ['break tick', 'ignore 1 9999', 'run', 'info breakpoints'], 2.0),
]


def cpu_of(argv, work):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    p = subprocess.run(argv, cwd=CWD, env=ENV, capture_output=True, text=True, timeout=300)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), p.returncode, p.stdout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--gdb', default='gdb')
    p.add_argument('--lldb', help='macOS: time against this lldb instead of gdb')
    p.add_argument('--cwd', default='/work')
    p.add_argument('--fixtures', default='/work/target/session-fixtures')
    p.add_argument('--runs', type=int, default=9)
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    global CWD
    CWD = a.cwd
    if a.lldb:
        ENV.update({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': a.cwd})
    Path(a.work).mkdir(parents=True, exist_ok=True)
    bad = 0
    record = []
    rows = [(n, p_, l, None, m) for n, p_, l, m in ROWS] if not a.lldb else MAC_ROWS
    for name, prog, lines, lldb_lines, margin in rows:
        script = Path(a.work) / ('perf-' + name + '.cmd')
        script.write_text('\n'.join(lines) + '\n')
        program = str(Path(a.fixtures) / prog)
        gdb_cmd = [a.gdb, '-nx', '-q', '-batch', '-iex', 'set confirm off', '-iex', 'set pagination off', '-x', str(script), program]
        if a.lldb:
            lscript = Path(a.work) / ('perf-' + name + '.lldb')
            lscript.write_text('\n'.join(lldb_lines) + '\n')
            gdb_cmd = [a.lldb, '-b', '-s', str(lscript), program]
        sniff_cmd = [a.sniff, '-batch', '-x', str(script), program]
        times = {'gdb': [], 'sniff': []}  # 'gdb' holds the oracle's figures (lldb on macOS)
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
        print('%s perf %s oracle_min=%.3fs sniff_min=%.3fs ratio=%.2f margin<=%.2f runs=%d%s' %
              (status, name, g, s, ratio, margin, a.runs, why))
        record.append({'row': name, 'gdb': times['gdb'], 'sniff': times['sniff'], 'ratio': ratio, 'margin': margin})
    if a.out:
        a.out.write_text(json.dumps(record, indent=1) + '\n')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
