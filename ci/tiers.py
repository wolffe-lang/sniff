#!/usr/bin/env python3
"""Cheap local-evidence PRs; opt-in PR/full gates, nightly and release gates.

A trunk push leaves `macos` when its commit already has it green. Merges are
fast-forwards, so a push to trunk runs the commit its pull request's run has just
passed. On the runner's own push to trunk (GITHUB_EVENT_NAME, GITHUB_REF; the
plan's event push too) the plan asks the REST API, with the workflow's own
read-only token (PLAN_TOKEN), for this workflow's runs at GITHUB_SHA, and leaves
`macos` only when a completed, successful pull_request or workflow_dispatch run
there tested the same tree (its `plan` job's step `the tree under test is
<tree>`: a pull request's run tests its merge with the base, which is this tree
only when the base is already in the commit) and has, at its latest attempt, the
`macos` job once, green, on its macOS runner. Anything else runs it: no such
run, a lookup that fails, times out, redirects or answers oddly, a jobs listing
short of its count, no token, a checkout that is not the pushed commit. The plan
writes `covered=` (the jobs it left, each with the run, event, commit and tree it
relied on; `{}` otherwise) and one line per macOS job; the verdict accepts a
covered `macos` in place of a green one and names the run."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

JOBS = ['plan-test', 'linux', 'macos']
# The macOS jobs a trunk push may leave, each with its runner's label.
MACOS = {'macos': 'macos-15'}
WORKFLOW = '.github/workflows/ci.yml'
EVIDENCE_EVENTS = ('pull_request', 'workflow_dispatch')
TREE_STEP = re.compile(r'^the tree under test is ([0-9a-f]{40}|[0-9a-f]{64})$')
MAX_RUNS = 10
MAX_PAGES = 5


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The plan follows no redirect: the token goes to the API alone."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'a redirect, not followed', headers, fp)


class Api:
    def __init__(self, base, repo, token, timeout):
        self.base, self.repo, self.token, self.timeout = base.rstrip('/'), repo, token, timeout
        self.opener = urllib.request.build_opener(NoRedirect)

    def get(self, path, **query):
        url = '%s/repos/%s/%s?%s' % (self.base, self.repo, path, urllib.parse.urlencode(query))
        req = urllib.request.Request(url, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'sniff-ci-plan',
        })
        with self.opener.open(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode('utf-8'))


def run_jobs(api, run_id):
    """A run's jobs at its latest attempt, every page; None when the listing
    falls short of its own count."""
    jobs = []
    for page in range(1, MAX_PAGES + 1):
        d = api.get('actions/runs/%d/jobs' % run_id, filter='latest', per_page=100, page=page)
        got, total = d['jobs'], int(d['total_count'])
        jobs += got
        if len(jobs) >= total:
            return jobs if len(jobs) == total else None
        if not got:
            return None
    return None


def tested_tree(jobs):
    """The tree a run's `plan` job named, or None."""
    plan = [j for j in jobs if j.get('name') == 'plan']
    if len(plan) != 1 or plan[0].get('conclusion') != 'success':
        return None
    trees = [m.group(1) for s in (plan[0].get('steps') or []) if s.get('conclusion') == 'success'
             for m in [TREE_STEP.match(s.get('name') or '')] if m]
    return trees[0] if len(trees) == 1 else None


def green_kind(jobs, names, label):
    """Whether every job named is in the run once, green, on its macOS runner."""
    found = [[j for j in jobs if j.get('name') == n] for n in names]
    return all(len(f) == 1 and f[0].get('conclusion') == 'success' and label in (f[0].get('labels') or []) for f in found)


def git(*args):
    return subprocess.run(['git'] + list(args), capture_output=True, text=True, check=True).stdout.strip()


def trunk_push(event):
    """Whether this is the runner's own push to trunk, and the plan's."""
    return (event == 'push' and os.environ.get('GITHUB_EVENT_NAME') == 'push'
            and os.environ.get('GITHUB_REF') == 'refs/heads/trunk')


def cover(say):
    """-> {macOS job: the run, event, commit and tree it is green in}; {} on any doubt."""
    env = os.environ
    token = env.get('PLAN_TOKEN') or ''
    hide = lambda s: s.replace(token, '<token>') if token else s
    sha, repo = env.get('GITHUB_SHA') or '', env.get('GITHUB_REPOSITORY') or ''
    if not token:
        say('no token for the lookup: every macOS job runs')
        return {}
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', sha) or not repo:
        say('no pushed commit or repository named: every macOS job runs')
        return {}
    try:
        head, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    except (OSError, subprocess.CalledProcessError) as e:
        say('git could not name the checkout (%s): every macOS job runs' % type(e).__name__)
        return {}
    if head != sha:
        say('the checkout %s is not the pushed commit %s: every macOS job runs' % (head, sha))
        return {}
    say('the pushed commit %s, tree %s' % (sha, tree))
    try:
        api = Api(env.get('GITHUB_API_URL') or 'https://api.github.com', repo, token,
                  float(env.get('PLAN_API_TIMEOUT') or 20))
        listing = api.get('actions/workflows/%s/runs' % os.path.basename(WORKFLOW), head_sha=sha, per_page=100)
        runs = [r for r in listing['workflow_runs']
                if r.get('head_sha') == sha and r.get('path') == WORKFLOW and r.get('status') == 'completed'
                and r.get('conclusion') == 'success' and r.get('event') in EVIDENCE_EVENTS]
        runs.sort(key=lambda r: -int(r['id']))
        found = {}
        for r in runs[:MAX_RUNS]:
            rid = int(r['id'])
            jobs = run_jobs(api, rid)
            if jobs is None:
                say('%s run %d: its jobs listing falls short of its count, not relied on' % (r['event'], rid))
                continue
            t = tested_tree(jobs)
            if t != tree:
                say('%s run %d tested tree %s, not %s: not relied on' % (r['event'], rid, t or '(not named)', tree))
                continue
            for job, label in MACOS.items():
                if job not in found and green_kind(jobs, [job], label):
                    found[job] = {'run': rid, 'event': r['event'], 'sha': sha, 'tree': tree}
        return found
    except Exception as e:  # any failure of the lookup runs every macOS job
        say('the lookup failed (%s: %s): every macOS job runs' % (type(e).__name__, hide(str(e))))
        return {}


def covered_lines(covered, server, repo):
    lines = []
    for job in MACOS:
        c = covered.get(job)
        if c:
            lines.append('skip %s: green in %s run %d at %s, tree %s (%s/%s/actions/runs/%d)' % (
                job, c['event'], c['run'], c['sha'], c['tree'], server, repo, c['run']))
        else:
            lines.append('keep %s: no completed, successful pull_request or workflow_dispatch run of %s at this '
                         'commit tested this tree with it green on %s' % (job, os.path.basename(WORKFLOW), MACOS[job]))
    return lines


def read_covered(out, tier, chosen):
    """The plan's `covered`, checked: only a macOS job, only in tier full, never
    also chosen, each with the run, event, commit and tree it relied on."""
    covered = json.loads(out.get('covered') or '{}')
    if not isinstance(covered, dict):
        raise ValueError('the plan\'s covered is not an object: %r' % out.get('covered'))
    for job, c in covered.items():
        if job not in MACOS:
            raise ValueError('covered names %s, which is no macOS job' % job)
        if tier != 'full':
            raise ValueError('covered %s in tier %s: only a full tier leaves a macOS job' % (job, tier))
        if job in chosen:
            raise ValueError('covered %s and chose it too' % job)
        if not (isinstance(c, dict) and isinstance(c.get('run'), int) and c.get('event') in EVIDENCE_EVENTS
                and all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', str(c.get(k) or '')) for k in ('sha', 'tree'))):
            raise ValueError('covered %s names no run it relied on: %r' % (job, c))
    return covered


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
        tier = needs['plan']['outputs']['tier']
        covered = read_covered(needs['plan']['outputs'], tier, chosen)
        if tier == 'full':
            left = [j for j in JOBS if j not in chosen and j not in covered]
            if left:
                raise ValueError('tier full left %s, neither chosen nor covered' % ' '.join(left))
        for job in chosen:
            if needs.get(job, {}).get('result') != 'success':
                raise ValueError('selected job did not succeed: ' + job)
        for job in JOBS:
            if job not in chosen and needs.get(job, {}).get('result', 'skipped') != 'skipped':
                raise ValueError('unselected job ran: ' + job)
        for job, c in sorted(covered.items()):
            print('covered %s: green in %s run %d at %s, tree %s' % (job, c['event'], c['run'], c['sha'], c['tree']))
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
    covered, lines = {}, []
    if trunk_push(args.event):
        found = cover(lambda s: lines.append(s))
        covered = {j: c for j, c in found.items() if j in result['jobs']} if result['tier'] == 'full' else {}
        result['jobs'] = [j for j in result['jobs'] if j not in covered]
        env = os.environ
        lines += covered_lines(covered, env.get('GITHUB_SERVER_URL') or 'https://github.com', env.get('GITHUB_REPOSITORY') or '')
    elif args.event == 'push':
        lines.append('not the runner\'s own push to trunk: nothing asked, every macOS job runs')
    if covered:
        result['covered'] = covered
    # The lookup's lines go to standard error: standard output is the plan, as JSON.
    for line in lines:
        print('tiers: ' + line, file=sys.stderr)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary and lines:
        try:
            with Path(summary).open('a') as f:
                f.write('### The trunk push\'s macOS jobs\n\n' + ''.join('- %s\n' % l for l in lines) + '\n')
        except OSError as e:
            print('tiers: the step summary could not be written (%s)' % e, file=sys.stderr)
    print(json.dumps(result))
    if args.github_output:
        with Path(args.github_output).open('a') as f:
            f.write('tier=' + result['tier'] + '\n')
            f.write('jobs=' + json.dumps(result['jobs']) + '\n')
            f.write('covered=' + json.dumps(covered, separators=(',', ':')) + '\n')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, KeyError, OSError) as error:
        print('FAIL tier ' + str(error), file=sys.stderr)
        sys.exit(1)
