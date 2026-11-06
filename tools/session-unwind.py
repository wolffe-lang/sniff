#!/usr/bin/env python3
"""Which frames unwind through CFI and which through the frame-pointer fallback.

`maint frames` is sniff's own command. The claims checked here are the ones
notes/sn02-the-linux-core.md states: C programs built by gcc and clang unwind
every frame through .eh_frame; wolf 0.2.37 emits no CFI for its own functions
and none for the runtime's `main` shim either, so every wolf frame that is
unwound uses the fallback. The row goes red by name the day s283 lands, rather
than letting the note go stale.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys

ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/target/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}

ROWS = [
    # name, program, break location, expected (function, basis) per frame, innermost first
    ('c-gcc-recursion', 'c/calls/gcc-O0/prog', 'main.c:6', [('depth_sum', 'cfi'), ('main', 'outermost')], True),
    ('c-clang-recursion', 'c/calls/clang-O0/prog', 'main.c:6', [('depth_sum', 'cfi'), ('main', 'outermost')], True),
    ('wolf-recursion', 'wolf/recursion/wolf-debug/prog', 'depth', [('depth', 'frame-pointer'), ('main', 'frame-pointer'), ('main', 'outermost')], True),
    ('wolf-nested', 'wolf/nested/wolf-debug/prog', 'inner', [('inner', 'frame-pointer'), ('outer', 'frame-pointer'), ('main', 'frame-pointer'), ('main', 'outermost')], True),
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--fixtures', default='/work/target/session-fixtures')
    p.add_argument('--work', default='/work/target/s2')
    a = p.parse_args()
    Path(a.work).mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, prog, where, expect, _ in ROWS:
        script = Path(a.work) / ('unwind-' + name + '.cmd')
        script.write_text('\n'.join(['break ' + where, 'run', 'maint frames']) + '\n')
        run = subprocess.run([a.sniff, '-batch', '-x', str(script), str(Path(a.fixtures) / prog)], cwd='/work', env=ENV,
                             capture_output=True, text=True, timeout=60)
        got = re.findall(r'^#\d+ (\S+) unwind=(\S+)$', run.stdout, re.M)
        if got[:len(expect)] != expect or len(got) < len(expect):
            print('FAIL unwind-basis-%s expected %r got %r' % (name, expect, got))
            bad += 1
        else:
            print('PASS unwind-basis %s %s' % (name, ' '.join('%s:%s' % x for x in got)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
