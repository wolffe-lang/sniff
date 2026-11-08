#!/usr/bin/env python3
"""Which frames unwind through CFI and which through the frame-pointer fallback.

`maint frames` is sniff's own command. C programs built by gcc and clang unwind
every frame through .eh_frame (notes/sn02-the-linux-core.md). wolf 0.2.38 built
with -g writes a .debug_frame FDE for every wolf function and for the entry shim
(notes/sn05-the-repin-and-s5.md), so every wolf frame now unwinds through CFI on
both platforms; until 0.2.37 each used the frame-pointer fallback, and this row
went red by name when the producer changed, as it was written to.
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
    ('wolf-recursion', 'wolf/recursion/wolf-debug/prog', 'depth', [('depth', 'cfi'), ('main', 'cfi'), ('main', 'outermost')], True),
    ('wolf-nested', 'wolf/nested/wolf-debug/prog', 'inner', [('inner', 'cfi'), ('outer', 'cfi'), ('main', 'cfi'), ('main', 'outermost')], True),
]

# macOS arm64: the C binaries carry compact unwind and no DWARF CFI (R-sn00-2); wolf's dSYM carries
# the .debug_frame that -g writes.
ROWS_MAC = [
    ('c-clang-recursion', 'c/calls/clang-O0/prog', 'main.c:6', [('depth_sum', 'compact'), ('main', 'outermost')], True),
    ('wolf-recursion', 'wolf/recursion/wolf-debug/prog', 'depth', [('depth', 'cfi'), ('main', 'cfi'), ('main', 'outermost')], True),
    ('wolf-nested', 'wolf/nested/wolf-debug/prog', 'inner', [('inner', 'cfi'), ('outer', 'cfi'), ('main', 'cfi'), ('main', 'outermost')], True),
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sniff', required=True)
    p.add_argument('--fixtures', default='/work/target/session-fixtures')
    p.add_argument('--work', default='/work/target/s2')
    p.add_argument('--platform', default='linux', choices=['linux', 'macos'])
    p.add_argument('--cwd', default='/work')
    a = p.parse_args()
    Path(a.work).mkdir(parents=True, exist_ok=True)
    bad = 0
    rows = ROWS if a.platform == 'linux' else ROWS_MAC
    env = ENV if a.platform == 'linux' else {'PATH': '/usr/bin:/bin', 'HOME': a.work, 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    for name, prog, where, expect, _ in rows:
        script = Path(a.work) / ('unwind-' + name + '.cmd')
        script.write_text('\n'.join(['break ' + where, 'run', 'maint frames']) + '\n')
        run = subprocess.run([a.sniff, '-batch', '-x', str(script), str(Path(a.fixtures) / prog)], cwd=a.cwd, env=env,
                             capture_output=True, text=True, timeout=60)
        got = re.findall(r'^#\d+ (\S+) unwind=(\S+)$', run.stdout, re.M)
        if expect is None:
            print('OBSERVE unwind-basis %s %r' % (name, got))
            continue
        if got[:len(expect)] != expect or len(got) < len(expect):
            print('FAIL unwind-basis-%s expected %r got %r' % (name, expect, got))
            bad += 1
        else:
            print('PASS unwind-basis %s %s' % (name, ' '.join('%s:%s' % x for x in got)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
