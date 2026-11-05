#!/usr/bin/env python3
"""Cheap local-evidence PRs; opt-in PR/full gates, nightly and release gates."""
import argparse
import json
import os
from pathlib import Path
import sys

JOBS = ['plan-test', 'linux', 'macos']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan')
    plan.add_argument('--event', default=os.environ.get('EVENT', ''))
    plan.add_argument('--labels', default=os.environ.get('LABELS', ''))
    plan.add_argument('--jobs', default=os.environ.get('IN_JOBS', ''))
    plan.add_argument('--github-output')
    sub.add_parser('verdict')
    args = p.parse_args()
    if args.command == 'verdict':
        needs = json.loads(os.environ['NEEDS'])
        if needs['plan']['result'] != 'success':
            raise ValueError('plan did not succeed')
        chosen = json.loads(needs['plan']['outputs']['jobs'])
        if not isinstance(chosen, list) or set(chosen) - set(JOBS):
            raise ValueError('invalid planned jobs')
        for job in chosen:
            if needs.get(job, {}).get('result') != 'success':
                raise ValueError('selected job did not succeed: ' + job)
        for job in JOBS:
            if job not in chosen and needs.get(job, {}).get('result', 'skipped') != 'skipped':
                raise ValueError('unselected job ran: ' + job)
        print('PASS tier ' + needs['plan']['outputs']['tier'])
        return 0
    labels = set(filter(None, args.labels.split(',')))
    if args.event == 'workflow_dispatch' and args.jobs:
        selected = args.jobs.split()
        if set(selected) - set(JOBS) or len(selected) != len(set(selected)):
            raise ValueError('unknown or duplicate dispatch job')
        result = {'tier': 'partial', 'jobs': selected}
    elif args.event in ('push', 'schedule', 'workflow_dispatch') or labels & {'full-matrix', 'release-matrix'}:
        result = {'tier': 'full', 'jobs': JOBS}
    elif args.event == 'pull_request' and 'ci' in labels:
        result = {'tier': 'pr', 'jobs': ['plan-test', 'linux']}
    elif args.event == 'pull_request':
        result = {'tier': 'local', 'jobs': ['plan-test']}
    else:
        raise ValueError('unknown event: ' + args.event)
    print(json.dumps(result))
    if args.github_output:
        with Path(args.github_output).open('a') as f:
            f.write('tier=' + result['tier'] + '\n')
            f.write('jobs=' + json.dumps(result['jobs']) + '\n')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, KeyError, OSError) as error:
        print('FAIL tier ' + str(error), file=sys.stderr)
        sys.exit(1)
