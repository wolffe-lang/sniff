#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Tiers(unittest.TestCase):
    def plan(self, event, labels='', jobs=''):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'ci/tiers.py'), 'plan',
            '--event', event, '--labels', labels, '--jobs', jobs], capture_output=True, text=True)

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
            env=dict(os.environ, NEEDS=json.dumps(needs)), capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('linux', p.stdout + p.stderr)


if __name__ == '__main__': unittest.main()
