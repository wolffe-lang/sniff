#!/usr/bin/env python3
"""Pin guards execute binaries only; injected PATH tools prove named refusals."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAC_VERSION = 'llvm-nm, compatible with GNU nm\nApple LLVM version 21.0.0\n  Optimized build.'
LINUX_VERSION = 'GNU readelf (GNU Binutils for Ubuntu) 2.42'


class SymbolOracle(unittest.TestCase):
    def run_guard(self, platform='macos', version=MAC_VERSION, wrong_digest=False,
                  child_exit=0, absent=False):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            name = 'llvm-nm' if platform == 'macos' else 'readelf'
            binary = d / name
            binary.write_text('#!/bin/sh\nif [ "$1" != --version ]; then exit 99; fi\n'
                              + "printf '%s\\n' " + "'" + version + "'\n"
                              + 'exit ' + str(child_exit) + '\n')
            binary.chmod(0o755)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            section = 'llvm_nm_macos' if platform == 'macos' else 'readelf'
            expected = 'Apple LLVM version 21.0.0' if platform == 'macos' else LINUX_VERSION
            pin = d / 'pins.toml'
            pin.write_text('[' + section + ']\ncommand = ' + json.dumps(name)
                           + '\nversion_line = ' + json.dumps(expected)
                           + '\nsha256 = "' + ('0' * 64 if wrong_digest else digest) + '"\n')
            if absent:
                binary.unlink()
            env = dict(os.environ, PATH=str(d))
            return subprocess.run([sys.executable, '-I', str(ROOT / 'tools/check-symbol-oracle.py'),
                                   '--platform', platform, '--pins', str(pin)],
                                  env=env, capture_output=True, text=True, timeout=10)

    def test_path_binary_version_mismatch_refused_by_name(self):
        result = self.run_guard(version=MAC_VERSION.replace('21.0.0', '22.0.0'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL symbol-oracle-version-mismatch', result.stdout)
        self.assertNotIn('PASS', result.stdout)

    def test_correct_version_and_digest_accepted(self):
        for platform, version in [('macos', MAC_VERSION), ('linux', LINUX_VERSION)]:
            with self.subTest(platform=platform):
                result = self.run_guard(platform=platform, version=version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('PASS symbol-oracle-pin', result.stdout)

    def test_version_substring_is_not_a_pin(self):
        result = self.run_guard(version=MAC_VERSION.replace('21.0.0', '21.0.01'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL symbol-oracle-version-mismatch', result.stdout)

    def test_version_match_does_not_replace_digest_check(self):
        result = self.run_guard(wrong_digest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL symbol-oracle-digest-mismatch', result.stdout)

    def test_failed_version_command_is_not_accepted(self):
        result = self.run_guard(child_exit=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL symbol-oracle-execution', result.stdout)

    def test_missing_binary_is_named(self):
        result = self.run_guard(absent=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL symbol-oracle-not-found', result.stdout)


if __name__ == '__main__':
    unittest.main()
