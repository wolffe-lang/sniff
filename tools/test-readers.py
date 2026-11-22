#!/usr/bin/env python3
"""Run every named Wolf reader unit on native and the checked machine."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def check_checked(record, native):
    if record.get('verdict') != 'exit(0)':
        raise ValueError('reader-checked-verdict: ' + str(record.get('verdict')))
    if record.get('stdout_inline') != native:
        raise ValueError('reader-checked-output: differs from native')


def check_rows(stdout, expected):
    lines = stdout.splitlines()
    for row in expected:
        count = lines.count('PASS ' + row)
        if count == 0:
            raise ValueError('reader-row-missing: ' + row)
        if count != 1:
            raise ValueError('reader-row-count: ' + row)
    if any(line.startswith(('FAIL ', 'SKIP ')) for line in lines):
        raise ValueError('reader-row-failure: failure or skip in output')


def stopped_at(stdout, expected):
    """The first named row a unit program printed no PASS line for: where it stopped."""
    lines = stdout.splitlines()
    for row in expected:
        if 'PASS ' + row not in lines:
            return row
    return ''


def command(args):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True,
                            text=True, timeout=180)
    if result.returncode:
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        raise ValueError('reader-command-exit: ' + str(result.returncode))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wolf', required=True, type=Path)
    args = parser.parse_args()
    wolf = args.wolf.resolve()
    expected = json.loads((ROOT / 'tests/reader-unit-rows.json').read_text())
    sources = sorted((ROOT / 'src').glob('*_test.lu'))
    if {p.name for p in sources} != set(expected):
        raise ValueError('reader-test-inventory: tests and named rows differ')
    target = ROOT / 'target/reader-unit'
    target.mkdir(parents=True, exist_ok=True)
    for source in sources:
        name = source.stem
        binary = target / name
        command([wolf, 'build', source, '--no-cache', '-o', binary])
        ran = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, timeout=180)
        if ran.returncode:
            print(ran.stdout, end='')
            print(ran.stderr, end='', file=sys.stderr)
            # a unit program stops at its first failing assertion: the row it stopped in is named
            row = stopped_at(ran.stdout, expected[source.name])
            if row:
                print('FAIL %s (the unit stopped in this row: exit %d)' % (row, ran.returncode))
            raise ValueError('reader-command-exit: ' + str(ran.returncode))
        native = ran
        check_rows(native.stdout, expected[source.name])
        checked = command([wolf, 'conform-run', source, '--json', '--checked', '--deny-warnings'])
        (target / (name + '-native.txt')).write_text(native.stdout)
        (target / (name + '-checked.json')).write_text(checked.stdout)
        check_checked(json.loads(checked.stdout), native.stdout)
        print(native.stdout, end='')
        print('PASS reader-checked ' + name)
    print('PASS reader-unit-all programs=' + str(len(sources)))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL ' + str(error))
        sys.exit(1)
