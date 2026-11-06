#!/usr/bin/env python3
"""The hosted-CI switch skips oracle rows by name and never weakens a refusal.

Without SNIFF_HOSTED_MACOS_CI=1 every oracle step runs, so a missing,
mismatched or wrong-digest symbol oracle is still refused by name. With it, on
macOS only, the step prints a SKIP line with its reason and runs nothing. The
switch is an explicit variable; nothing detects a runner or reads the pins'
outcome to decide.
"""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / 'tools/gate-steps.sh'
WRONG = 'llvm-nm, compatible with GNU nm\nApple LLVM version 17.0.0\n  Optimized build.'
RIGHT = 'llvm-nm, compatible with GNU nm\nApple LLVM version 21.0.0\n  Optimized build.'
ORACLE = ['symbol-oracle-pin', 'dump-matrix', 'dwarf-census', 'live-transcript']
DEPENDENT = ['target-sign', 'live-mutations', 'true-value-join']
RUNS = ['reader-unit', 'sniff-build', 'fixture-builds', 'hostile-inputs', 'lupin-values', 'toolchain']


class GateSwitch(unittest.TestCase):
    def run_step(self, mode, switch, tool_version=None, sentinel=False, digest_bytes=None):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'target/gate').mkdir(parents=True)
            stubs = d / 'stubs'
            stubs.mkdir()
            # A failing xcrun keeps the host SDK out: only the stub can answer.
            xcrun = stubs / 'xcrun'
            xcrun.write_text('#!/bin/sh\nexit 1\n')
            xcrun.chmod(0o755)
            # PATH is the stub directory alone: no host oracle can answer.
            for tool in ('sed', 'awk', 'touch', 'mkdir'):
                (stubs / tool).symlink_to(shutil.which(tool))
            (stubs / 'python3').symlink_to(Path(sys.executable).resolve())
            if tool_version is not None:
                nm = stubs / 'llvm-nm'
                body = '#!/bin/sh\nprintf \'%s\\n\' \'' + tool_version + '\'\n'
                if digest_bytes:
                    body += '# ' + digest_bytes + '\n'
                nm.write_text(body)
                nm.chmod(0o755)
            env = {'PATH': str(stubs), 'LC_ALL': 'C'}
            if switch is not None:
                env['SNIFF_HOSTED_MACOS_CI'] = switch
            if sentinel:
                command = 'touch ' + str(d / 'ran')
            else:
                command = 'python3 -I ' + str(ROOT / 'tools/check-symbol-oracle.py') + ' --platform macos'
            script = ('set -euo pipefail\nmode=' + mode + '\nsource ' + str(LIB) +
                      '\noracle_step symbol-oracle-pin ' + command + '\n')
            result = subprocess.run([shutil.which('bash'), '-c', script], cwd=d, env=env, capture_output=True,
                                    text=True, timeout=60)
            return result, (d / 'ran').exists()

    def test_no_switch_still_refuses_by_name(self):
        for version, digest, row in ((WRONG, None, 'symbol-oracle-version-mismatch'),
                                     (RIGHT, 'not-the-pinned-bytes', 'symbol-oracle-digest-mismatch'),
                                     (None, None, 'symbol-oracle-not-found')):
            result, _ = self.run_step('macos', None, version, digest_bytes=digest)
            self.assertNotEqual(result.returncode, 0, row)
            self.assertIn('START symbol-oracle-pin', result.stdout)
            self.assertRegex(result.stdout, r'(?m)^FAIL ' + row)
            self.assertRegex(result.stdout, r'(?m)^END symbol-oracle-pin exit=1 ')
            self.assertNotIn('SKIP', result.stdout)

    def test_switch_skips_by_name_on_macos_only(self):
        result, ran = self.run_step('macos', '1', sentinel=True)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(ran)
        self.assertNotIn('START', result.stdout)
        skip = re.fullmatch(r'SKIP symbol-oracle-pin reason=(\S.*)\n', result.stdout)
        self.assertIsNotNone(skip, result.stdout)
        self.assertIn('Apple LLVM 21.0.0', skip[1])
        self.assertIn('sha256', skip[1])
        self.assertIn('local gauntlet record', skip[1])
        # The switch never skips a Linux row, and only the exact value 1 counts.
        for mode, value in (('linux', '1'), ('macos', 'yes'), ('macos', '0'), ('macos', '')):
            result, ran = self.run_step(mode, value, sentinel=True)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(ran, (mode, value))
            self.assertIn('START symbol-oracle-pin', result.stdout)

    def test_gate_routes_exactly_the_oracle_rows(self):
        gate = (ROOT / 'tools/gate').read_text()
        self.assertIn('source "$root/tools/gate-steps.sh"', gate)
        for name in ORACLE:
            self.assertRegex(gate, r'(?m)^\s*oracle_step ' + re.escape(name) + ' ', name)
        for name in DEPENDENT:
            self.assertRegex(gate, r'(?m)^\s*oracle_dependent_step ' + re.escape(name) + ' ', name)
        for name in RUNS:
            self.assertRegex(gate, r'(?m)^\s*step ' + re.escape(name) + ' ', name)
        lib = LIB.read_text()
        # An explicit switch only: no runner detection, no reading of pin results.
        for probe in ('RUNNER_', 'GITHUB_', 'ImageOS', 'ImageVersion', 'sw_vers', 'xcrun', 'sniff-oracle'):
            self.assertNotIn(probe, lib, probe)
        self.assertNotIn('SNIFF_HOSTED_MACOS_CI', gate)


if __name__ == '__main__':
    unittest.main(verbosity=2)
