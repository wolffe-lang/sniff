#!/usr/bin/env python3
"""Host-layout reports are explicit, narrowly listed, and never enabled in hosted CI."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HostDependentGate(unittest.TestCase):
    def run_step(self, names='', code=1, hosted=False, step='session-oracle-stable'):
        root = Path(os.environ.get('TMPDIR', ROOT / 'target/test-tmp'))
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as d:
            p = Path(d)
            (p / 'target/gate').mkdir(parents=True)
            env = dict(os.environ, HOME=d, SHELL='/bin/sh', SNIFF_UNJUDGED_STEPS=names,
                       GITHUB_ACTIONS='true' if hosted else 'false', BASH_ENV='', ENV='')
            script = ('set -euo pipefail\nsource ' + shlex.quote(str(ROOT / 'tools/gate-steps.sh')) + '\n'
                      'source ' + shlex.quote(str(ROOT / 'tools/host-dependent-steps.sh')) + '\n'
                      'host_dependent_validate\n'
                      'host_dependent_step ' + shlex.quote(step) +
                      " sh -c 'printf \"FAIL oracle-drift standin\\n\"; exit " + str(code) + "'\n"
                      'printf "AFTER\\n"\n')
            return subprocess.run(['bash', '-c', script], cwd=p, env=env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    def test_default_still_judges_the_leaf(self):
        r = self.run_step()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn('END session-oracle-stable exit=1', r.stdout)
        self.assertNotIn('AFTER', r.stdout)
        self.assertNotIn('UNJUDGED', r.stdout)

    def test_explicit_report_retains_result_and_continues(self):
        r = self.run_step('session-oracle-stable')
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('UNJUDGED session-oracle-stable command-exit=1', r.stdout)
        self.assertIn('END report-session-oracle-stable exit=0', r.stdout)
        self.assertNotIn('\nFAIL oracle-drift', r.stdout)
        self.assertIn('  FAIL oracle-drift standin', r.stdout)
        self.assertIn('AFTER', r.stdout)

    def test_list_does_not_cover_an_unlisted_leaf(self):
        r = self.run_step('session-oracle-stable', step='session-rows')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertNotIn('UNJUDGED', r.stdout)

    def test_both_measured_host_dependent_leaves_can_be_listed(self):
        r = self.run_step('session-oracle-stable,session-rows', step='session-rows')
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('UNJUDGED session-rows command-exit=1', r.stdout)

    def test_unknown_or_malformed_lists_are_refused(self):
        for names in ('all', '*', 'remote-smp-kvm', 'reader-unit', ',session-rows',
                      'session-rows,', 'session-rows,,session-oracle-stable', 'session-rows,session-rows'):
            with self.subTest(names=names):
                r = self.run_step(names)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn('FAIL host-dependent-switch', r.stdout)
                self.assertNotIn('START ', r.stdout)

    def test_hosted_ci_cannot_enable_reporting(self):
        r = self.run_step('session-oracle-stable', hosted=True)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn('FAIL host-dependent-switch', r.stdout)
        self.assertNotIn('START ', r.stdout)

    def test_noncomparison_process_failure_is_not_reported_as_success(self):
        r = self.run_step('session-oracle-stable', code=2)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn('END report-session-oracle-stable exit=2', r.stdout)
        self.assertNotIn('AFTER', r.stdout)


if __name__ == '__main__':
    unittest.main()
