#!/usr/bin/env python3
"""Explicit pre-next-statement / post-previous-statement join for scalars."""
import argparse
import json
from pathlib import Path
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session', required=True, type=Path)
    p.add_argument('--values', required=True, type=Path)
    args = p.parse_args()
    session = json.loads(args.session.read_text())
    values = json.loads(args.values.read_text())
    if session.get('schema') != 1 or values.get('schema') != 1:
        raise ValueError('unknown value schema')
    event = next(e for e in session['events'] if e['name'] == 'local')
    fixture = next(f for f in values['fixtures'] if f['id'] == 'wolf/scalars')
    rows = [r for r in fixture['rows'] if r['function'] == 'helper' and r['at'] == '2:5'
            and r['phase'] == 'after-statement-or-tail' and not r['tail']]
    if event['line'] != 3 or len(rows) != 1 or event['locals'] != rows[0]['locals']:
        print('FAIL true-value-join debugger_before=3 lupin_after=2 locals=' + repr(event['locals']))
        return 1
    print('PASS true-value-join debugger_before=3 lupin_after=2 locals=' + str(len(event['locals'])))
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, KeyError, StopIteration, OSError) as error:
        print('FAIL true-value-join ' + str(error), file=sys.stderr)
        sys.exit(1)
