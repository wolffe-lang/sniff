#!/usr/bin/env python3
"""Record lupin's statement-boundary value side channel, never native --checked."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lupin', required=True)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.lupin, '--version'], text=True).strip()
    results = []
    for source in sorted((ROOT / 'fixtures/wolf').glob('*/main.lu')):
        case = source.parent.name
        trace = (args.out / (case + '.jsonl')).resolve()
        run = subprocess.run([args.lupin, '--trace-places=' + str(trace), str(source)],
            capture_output=True, env=dict(os.environ, LC_ALL='C', TZ='UTC'), timeout=60)
        (args.out / (case + '.stdout')).write_bytes(run.stdout)
        (args.out / (case + '.stderr')).write_bytes(run.stderr)
        if run.returncode:
            raise ValueError('lupin fixture ' + case + ' exit=' + str(run.returncode))
        rows = []
        for line in trace.read_text().splitlines():
            row = json.loads(line)
            if row.get('trace') != 1: raise ValueError('unknown lupin trace schema')
            rows.append({'function': row['fn'], 'task': row['task'], 'depth': row['depth'],
                         'at': row['at'], 'phase': 'after-statement-or-tail',
                         'locals': {v['path']: v['value'] for v in row['places']
                                    if v['state'] == 'live' and 'value' in v},
                         'places': row['places'], 'tail': row.get('tail', False)})
        if not rows: raise ValueError('empty lupin value trace: ' + case)
        if case == 'scalars':
            if not any(r['function'] == 'helper' and r['at'].split(':')[0] == '2' and
                       r['locals'] == {'a': '3', 'b': '4', 's': '7'} for r in rows):
                raise ValueError('scalar true-value row did not execute')
        results.append({'id': 'wolf/' + case, 'rows': rows})
        print('PASS lupin-values ' + case + ' rows=' + str(len(rows)), flush=True)
    (args.out / 'values.json').write_text(json.dumps({'schema': 1, 'version': version,
        'boundary': 'Trace entries describe state AFTER the named statement/tail. A debugger stops BEFORE the next statement; join points must be specified, never globally shifted by one line.',
        'fixtures': results}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('FAIL lupin-values ' + str(error), file=sys.stderr)
        sys.exit(1)
