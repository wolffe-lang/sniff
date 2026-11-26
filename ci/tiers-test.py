#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

# The runner's own GITHUB_* and any token stay out of every planner and verdict
# this file runs: only the trunk push rows give the planner a push, an API and a
# token, so a test run inside a trunk push's job sees what any other run sees.
SCRUB = ('PLAN_TOKEN', 'PLAN_API_TIMEOUT', 'GH_TOKEN', 'GITHUB_TOKEN', 'GITHUB_EVENT_NAME', 'GITHUB_REF',
         'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_API_URL', 'GITHUB_SERVER_URL', 'GITHUB_STEP_SUMMARY',
         'GITHUB_OUTPUT', 'EVENT', 'LABELS', 'ACTION', 'LABEL', 'IN_JOBS', 'NEEDS')


def clean_env(**more):
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env.update(more)
    return env


def tiers_module():
    sys.path.insert(0, str(ROOT / 'ci'))
    try:
        import tiers
    finally:
        sys.path.pop(0)
    return tiers

def tiers_module():
    sys.path.insert(0, str(ROOT / 'ci'))
    try:
        import tiers
    finally:
        sys.path.pop(0)
    return tiers




class Tiers(unittest.TestCase):
    def plan(self, event, labels='', jobs=''):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'ci/tiers.py'), 'plan',
            '--event', event, '--labels', labels, '--jobs', jobs], capture_output=True, text=True, env=clean_env())

    def test_unlabelled_is_local_only(self):
        p = self.plan('pull_request')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {'tier': 'local', 'jobs': ['plan-test']})

    def test_pr_and_full(self):
        p = self.plan('pull_request', 'ci')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {'tier': 'pr', 'jobs': ['plan-test', 'linux']})
        p = self.plan('pull_request', 'full-matrix')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {'tier': 'full', 'jobs': ['plan-test', 'linux', 'macos']})

    def test_nightly_and_release(self):
        for event in ('schedule', 'push', 'workflow_dispatch'):
            p = self.plan(event)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)['tier'], 'full')

    def test_unknown_dispatch_job_refused(self):
        self.assertNotEqual(self.plan('workflow_dispatch', jobs='not-a-job').returncode, 0)

    def test_partial_dispatch(self):
        p = self.plan('workflow_dispatch', jobs='macos')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {'tier': 'partial', 'jobs': ['macos']})

    def test_verdict_rejects_skipped_selected_job(self):
        needs = {'plan': {'result': 'success', 'outputs': {'tier': 'pr', 'jobs': '["linux"]'}},
                 'linux': {'result': 'skipped'}, 'macos': {'result': 'skipped'},
                 'plan-test': {'result': 'success'}}
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'ci/tiers.py'), 'verdict'],
            env=clean_env(NEEDS=json.dumps(needs)), capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('linux', p.stdout + p.stderr)


# --- A trunk push leaves the macOS job already green at its commit ----------------
# Merges are fast-forwards, so a trunk push runs the commit its pull request's run
# has just passed. On the runner's own push to trunk the plan asks the REST API for
# this workflow's runs at the commit and leaves `macos` only on positive evidence.
# These rows run the planner as the workflow does, in a scratch git repository,
# against a stand-in API on 127.0.0.1.
import http.server
import re
import shutil
import tempfile
import threading
import time
import urllib.parse

REPO = 'wolffe-lang/sniff'
TOKEN = 'tiers-test-stand-in-token-3b9d'
MAC = 'macos'
MAC_LABEL = 'macos-15'
LINUX_JOBS = ['plan-test', 'linux', 'tier full']


class QuietServer(http.server.ThreadingHTTPServer):
    # A client that timed out leaves a handler writing to a closed socket.
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class FakeAPI:
    """The REST API's two answers the plan reads: the runs of ci.yml at a commit,
    and a run's jobs (paged). `fault` is (path prefix, kind)."""

    def __init__(self, runs=(), jobs=None, fault=None, page_cap=100, ignore_filter=False, totals=None):
        self.runs, self.jobs = list(runs), dict(jobs or {})
        self.fault, self.page_cap, self.ignore_filter = fault, page_cap, ignore_filter
        self.totals = dict(totals or {})
        self.requests = []
        self.redirect_to = None
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                api.requests.append((self.path, self.headers.get('Authorization')))
                status, body, extra = api.answer(self.path)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = QuietServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def answer(self, path):
        u = urllib.parse.urlsplit(path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if self.fault and u.path.startswith(self.fault[0]):
            kind = self.fault[1]
            if kind in (500, 403, 404):
                return kind, {'message': 'stand-in error %d' % kind}, {}
            if kind == 'html':
                return 200, b'<html>not json</html>', {}
            if kind == 'keys':
                return 200, {'message': 'an answer without the expected keys'}, {}
            if kind == 'slow':
                time.sleep(4)
            if kind == 'redirect':
                return 302, {}, {'Location': self.redirect_to + path}
        if u.path == '/repos/%s/actions/workflows/ci.yml/runs' % REPO:
            rs = [r for r in self.runs if self.ignore_filter or r['head_sha'] == q.get('head_sha')]
            return 200, {'total_count': len(rs), 'workflow_runs': rs}, {}
        m = re.fullmatch(r'/repos/%s/actions/runs/(\d+)/jobs' % re.escape(REPO), u.path)
        if m:
            rid = int(m.group(1))
            js = self.jobs.get(rid, [])
            per = min(int(q.get('per_page', 30)), self.page_cap)
            page = int(q.get('page', 1))
            return 200, {'total_count': self.totals.get(rid, len(js)), 'jobs': js[(page - 1) * per:page * per]}, {}
        return 404, {'message': 'Not Found'}, {}


STAND_IN_GIT = '''#!/bin/sh
# A stand-in for git: the plan's two questions, the pushed commit and its tree,
# and nothing else (any other call fails, so a plan that asks another fails too).
if [ "$*" = "rev-parse HEAD" ]; then echo "$STAND_IN_HEAD"; exit 0; fi
if [ "$*" = "rev-parse HEAD^{tree}" ]; then echo "$STAND_IN_TREE"; exit 0; fi
echo "stand-in git: not answered: $*" >&2
exit 1
'''


def scratch_repo():
    """A directory whose `git` answers for a pushed commit and its tree. The
    Linux gate runs this file in a container that has no git, so the plan's
    calls are answered here and never need one."""
    d = tempfile.mkdtemp(prefix='tiers-test-git-')
    Path(d, 'git').write_text(STAND_IN_GIT)
    os.chmod(Path(d, 'git'), 0o755)
    return d, 'a1' * 20, 'b2' * 20


def wrun(rid, sha, event='pull_request', conclusion='success', status='completed', path='.github/workflows/ci.yml'):
    return {'id': rid, 'event': event, 'status': status, 'conclusion': conclusion, 'head_sha': sha, 'path': path,
            'run_attempt': 1, 'html_url': 'https://github.com/%s/actions/runs/%d' % (REPO, rid)}


def wjob(name, conclusion='success', labels=None, steps=None):
    if labels is None:
        labels = [MAC_LABEL] if name == MAC else ['ubuntu-24.04']
    return {'name': name, 'status': 'completed', 'conclusion': conclusion, 'labels': labels, 'steps': steps or []}


def plan_job(tree, step=True):
    steps = [{'name': 'Set up job', 'conclusion': 'success'}]
    if step:
        steps.append({'name': 'the tree under test is %s' % tree, 'conclusion': 'success'})
    return wjob('plan', steps=steps)


class TrunkPushCover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir, cls.sha, cls.tree = scratch_repo()
        cls.seen = []

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def green(self, tree=None, step=True, mac=True, swap=None, extra=()):
        js = [plan_job(tree or self.tree, step)] + [wjob(n) for n in LINUX_JOBS]
        if mac:
            js.append(swap or wjob(MAC))
        return js + list(extra)

    def run_plan(self, api, event='push', event_name='push', ref='refs/heads/trunk', sha=None, token=TOKEN,
                 timeout=None, summary=None):
        out = Path(tempfile.mkdtemp(prefix='tiers-test-out-')) / 'output'
        out.write_text('')
        env = clean_env(GITHUB_EVENT_NAME=event_name, GITHUB_REF=ref, GITHUB_SHA=sha or self.sha,
                        GITHUB_REPOSITORY=REPO, GITHUB_API_URL=api.url, GITHUB_SERVER_URL='https://github.com',
                        STAND_IN_HEAD=self.sha, STAND_IN_TREE=self.tree)
        env['PATH'] = self.dir + os.pathsep + env.get('PATH', '')
        if token:
            env['PLAN_TOKEN'] = token
        if timeout:
            env['PLAN_API_TIMEOUT'] = str(timeout)
        if summary:
            env['GITHUB_STEP_SUMMARY'] = summary
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'ci/tiers.py'), 'plan', '--event', event,
                            '--github-output', str(out)], capture_output=True, text=True, env=env, cwd=self.dir, timeout=120)
        self.seen.append(p.stdout + p.stderr + out.read_text())
        self.assertEqual(p.returncode, 0, p.stderr)
        outputs = dict(l.split('=', 1) for l in out.read_text().splitlines() if '=' in l)
        shutil.rmtree(out.parent, ignore_errors=True)
        return json.loads(outputs.get('jobs', 'null')), json.loads(outputs.get('covered', 'null')), p.stdout + p.stderr

    def assert_runs_macos(self, api, **kw):
        jobs, covered, text = self.run_plan(api, **kw)
        self.assertEqual(jobs, ['plan-test', 'linux', 'macos'], text)
        self.assertEqual(covered, {}, text)
        self.assertRegex(text, r'(?m)^tiers: keep macos: ', text)
        return text

    def assert_leaves_macos(self, api, rid, event='pull_request', **kw):
        jobs, covered, text = self.run_plan(api, **kw)
        self.assertEqual(jobs, ['plan-test', 'linux'], text)
        self.assertEqual(sorted(covered), [MAC], text)
        self.assertEqual((covered[MAC]['run'], covered[MAC]['event'], covered[MAC]['sha'], covered[MAC]['tree']),
                         (rid, event, self.sha, self.tree), text)
        self.assertRegex(text, r'(?m)^tiers: skip macos: green in %s run %d at %s, tree %s' % (event, rid, self.sha, self.tree))
        return text

    def test_green_pull_request_run_leaves_macos(self):
        summary = Path(tempfile.mkdtemp(prefix='tiers-test-sum-')) / 'summary.md'
        api = FakeAPI([wrun(7001, self.sha)], {7001: self.green()})
        try:
            self.assert_leaves_macos(api, 7001, summary=str(summary))
            self.assertIn('7001', summary.read_text())
            jobs_q = [urllib.parse.parse_qs(urllib.parse.urlsplit(p).query) for p, _ in api.requests if '/jobs' in p]
            self.assertTrue(jobs_q and all(q.get('filter') == ['latest'] for q in jobs_q), api.requests)
            self.assertTrue(api.requests and all(a == 'Bearer ' + TOKEN for _, a in api.requests), api.requests)
        finally:
            api.close()
            shutil.rmtree(summary.parent, ignore_errors=True)

    def test_green_dispatch_run_counts(self):
        api = FakeAPI([wrun(7002, self.sha, event='workflow_dispatch')], {7002: self.green()})
        try:
            self.assert_leaves_macos(api, 7002, event='workflow_dispatch')
        finally:
            api.close()

    def test_other_events_and_unfinished_runs_do_not_count(self):
        runs = [wrun(7003, self.sha, event='schedule'), wrun(7004, self.sha, event='push'),
                wrun(7005, self.sha, conclusion='failure'), wrun(7006, self.sha, conclusion='cancelled'),
                wrun(7007, self.sha, status='in_progress', conclusion=None)]
        api = FakeAPI(runs, {r['id']: self.green() for r in runs})
        try:
            self.assert_runs_macos(api)
        finally:
            api.close()

    def test_another_tree_or_no_tree_does_not_count(self):
        for jobs in (self.green(tree='0' * 40), self.green(step=False)):
            api = FakeAPI([wrun(7008, self.sha)], {7008: jobs})
            try:
                self.assert_runs_macos(api)
            finally:
                api.close()

    def test_no_green_macos_job_runs_it(self):
        # The plant's target: a green run at the commit with no macOS job at all.
        for jobs in (self.green(mac=False), self.green(swap=wjob(MAC, conclusion='skipped')),
                     self.green(swap=wjob(MAC, conclusion='cancelled')), self.green(swap=wjob(MAC, labels=['ubuntu-24.04'])),
                     self.green(extra=[wjob(MAC, conclusion='failure')])):
            api = FakeAPI([wrun(7009, self.sha)], {7009: jobs})
            try:
                self.assert_runs_macos(api)
            finally:
                api.close()

    def test_the_green_run_among_red_ones_counts(self):
        api = FakeAPI([wrun(7010, self.sha, conclusion='failure'), wrun(7011, self.sha), wrun(7012, self.sha)],
                      {7010: self.green(), 7011: self.green(), 7012: self.green(mac=False)})
        try:
            self.assert_leaves_macos(api, 7011)
        finally:
            api.close()

    def test_paged_and_short_listings(self):
        api = FakeAPI([wrun(7013, self.sha)], {7013: self.green()}, page_cap=2)
        try:
            self.assert_leaves_macos(api, 7013)
            self.assertGreaterEqual(len([p for p, _ in api.requests if '/jobs' in p]), 3)
        finally:
            api.close()
        api = FakeAPI([wrun(7014, self.sha)], {7014: self.green()}, totals={7014: 99})
        try:
            self.assert_runs_macos(api)
        finally:
            api.close()

    def test_runs_of_another_commit_or_workflow_do_not_count(self):
        api = FakeAPI([wrun(7015, '1' * 40), wrun(7016, self.sha, path='.github/workflows/other.yml')],
                      {7015: self.green(), 7016: self.green()}, ignore_filter=True)
        try:
            self.assert_runs_macos(api)
        finally:
            api.close()

    def test_a_failed_lookup_runs_macos(self):
        for where, kind in (('/repos/%s/actions/workflows' % REPO, 500), ('/repos/%s/actions/runs' % REPO, 403),
                            ('/repos/%s/actions/workflows' % REPO, 'html'), ('/repos/%s/actions/runs' % REPO, 'keys'),
                            ('/repos/%s/actions/workflows' % REPO, 404)):
            with self.subTest(kind=kind):
                api = FakeAPI([wrun(7017, self.sha)], {7017: self.green()}, fault=(where, kind))
                try:
                    self.assert_runs_macos(api)
                finally:
                    api.close()

    def test_a_slow_lookup_runs_macos(self):
        api = FakeAPI([wrun(7018, self.sha)], {7018: self.green()}, fault=('/repos/%s/actions/workflows' % REPO, 'slow'))
        try:
            t0 = time.time()
            self.assert_runs_macos(api, timeout=1)
            self.assertLess(time.time() - t0, 30)
        finally:
            api.close()

    def test_a_redirect_is_not_followed(self):
        elsewhere = FakeAPI([wrun(7019, self.sha)], {7019: self.green()})
        api = FakeAPI([wrun(7019, self.sha)], {7019: self.green()}, fault=('/repos/%s/actions/workflows' % REPO, 'redirect'))
        api.redirect_to = elsewhere.url
        try:
            self.assert_runs_macos(api)
            self.assertEqual(elsewhere.requests, [])
        finally:
            api.close()
            elsewhere.close()

    def test_nothing_is_asked_without_a_trunk_push(self):
        # The plan's own event and the runner's must both be a push to trunk; a
        # pull request's run never asks, whatever event its plan is handed.
        cases = [dict(token=None), dict(sha='2' * 40), dict(event_name='pull_request'),
                 dict(ref='refs/heads/a-lane'), dict(event='pull_request', event_name='pull_request'),
                 dict(event='schedule', event_name='schedule'), dict(event='workflow_dispatch', event_name='workflow_dispatch')]
        for kw in cases:
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                api = FakeAPI([wrun(7020, self.sha)], {7020: self.green()})
                try:
                    jobs, covered, text = self.run_plan(api, **kw)
                    self.assertEqual(api.requests, [], text)
                    self.assertEqual(covered, {}, text)
                    if kw.get('event', 'push') != 'pull_request':
                        self.assertIn('macos', jobs, text)
                finally:
                    api.close()

    def test_the_token_is_never_printed(self):
        api = FakeAPI([wrun(7021, self.sha)], {7021: self.green()}, fault=('/repos/%s/actions/runs' % REPO, 403))
        try:
            self.run_plan(api)
        finally:
            api.close()
        self.assertTrue(self.seen)
        self.assertFalse([s for s in self.seen if TOKEN in s])


class CoveredVerdict(unittest.TestCase):
    COVER = {'run': 7001, 'event': 'pull_request', 'sha': 'a' * 40, 'tree': 'b' * 40}

    def verdict(self, tier, jobs, covered, results):
        outputs = {'tier': tier, 'jobs': json.dumps(jobs)}
        if covered is not None:
            outputs['covered'] = json.dumps(covered)
        needs = {'plan': {'result': 'success', 'outputs': outputs}}
        needs.update({j: {'result': r} for j, r in results.items()})
        return subprocess.run([sys.executable, '-I', str(ROOT / 'ci/tiers.py'), 'verdict'],
            env=clean_env(NEEDS=json.dumps(needs)), capture_output=True, text=True)

    def test_a_covered_macos_job_reads_success_and_names_its_run(self):
        p = self.verdict('full', ['plan-test', 'linux'], {'macos': self.COVER},
                         {'plan-test': 'success', 'linux': 'success', 'macos': 'skipped'})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('covered macos: green in pull_request run 7001 at %s, tree %s' % ('a' * 40, 'b' * 40), p.stdout)
        self.assertIn('PASS tier full', p.stdout)

    def test_a_full_tier_without_macos_or_its_cover_fails(self):
        for covered in (None, {}):
            p = self.verdict('full', ['plan-test', 'linux'], covered,
                             {'plan-test': 'success', 'linux': 'success', 'macos': 'skipped'})
            self.assertNotEqual(p.returncode, 0, p.stdout)

    def test_a_cover_the_rule_does_not_allow_fails(self):
        bad = [('full', ['plan-test', 'macos'], {'linux': self.COVER}, {'linux': 'skipped', 'macos': 'success'}),
               ('full', ['plan-test', 'linux', 'macos'], {'macos': self.COVER}, {'linux': 'success', 'macos': 'success'}),
               ('pr', ['plan-test', 'linux'], {'macos': self.COVER}, {'linux': 'success', 'macos': 'skipped'}),
               ('full', ['plan-test', 'linux'], {'macos': dict(self.COVER, event='push')}, {'linux': 'success', 'macos': 'skipped'}),
               ('full', ['plan-test', 'linux'], {'macos': {'run': 'x'}}, {'linux': 'success', 'macos': 'skipped'}),
               ('full', ['plan-test', 'linux'], ['macos'], {'linux': 'success', 'macos': 'skipped'})]
        for tier, jobs, covered, results in bad:
            with self.subTest(tier=tier, covered=str(covered)):
                results = dict({'plan-test': 'success'}, **results)
                p = self.verdict(tier, jobs, covered, results)
                self.assertNotEqual(p.returncode, 0, p.stdout)


class TrunkPushWiring(unittest.TestCase):
    def block(self, job):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        return re.search(r'^  %s:\n(.*?)(?=^  [a-z-]+:\n|\Z)' % re.escape(job), text, re.M | re.S).group(1)

    def test_the_plan_job_reads_runs_and_names_its_tree(self):
        plan = self.block('plan')
        self.assertRegex(plan, r'(?m)^    permissions:\n      contents: read\n      actions: read\n(?!      \S)')
        tree = '      - name: the tree under test is ${{ steps.tree.outputs.tree }}\n'
        self.assertIn('        id: tree\n', plan)
        self.assertIn(tree, plan)
        self.assertLess(plan.index('        id: tree\n'), plan.index(tree))
        self.assertLess(plan.index(tree), plan.index('      - id: plan\n'))
        self.assertIn("test \"$(git rev-parse 'HEAD^{tree}')\" = \"${{ steps.tree.outputs.tree }}\"", plan)
        self.assertIn('      covered: ${{ steps.plan.outputs.covered }}\n', plan)

    def test_only_the_plan_step_gets_the_token(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        plan = self.block('plan')
        self.assertEqual(text.count('github.token'), 1)
        self.assertEqual(text.count('PLAN_TOKEN'), 1)
        self.assertRegex(plan, r'(?m)^      - id: plan\n        env:\n(          .*\n)*          PLAN_TOKEN: \$\{\{ github\.token \}\}\n')

    def test_the_macos_job_is_the_one_the_lookup_names(self):
        mac = self.block('macos')
        self.assertIn('    runs-on: %s\n' % MAC_LABEL, mac)
        self.assertNotRegex(mac, r'(?m)^    name: ')
        self.assertEqual(tiers_module().MACOS, {MAC: MAC_LABEL})


if __name__ == '__main__': unittest.main()
