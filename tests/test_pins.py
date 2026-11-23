#!/usr/bin/env python3
"""The pin checker's QEMU and binary-manifest rules: the image builds the tarball the pin names, by its digest, with
the configure line the pin names, and every pinned oracle binary is in the measured manifest."""
import importlib.util
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_pins_tool', ROOT / 'tools/check-pins.py')
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


class QemuPins(unittest.TestCase):
    def setUp(self):
        self.oracle = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())
        self.q = dict(self.oracle['qemu'])
        self.content = (ROOT / 'ci/oracle.Containerfile').read_text()

    def test_the_tree_passes(self):
        self.assertEqual(pins.qemu_problems(self.q, self.content), [])

    def test_another_tarball_digest_is_refused(self):
        other = self.content.replace(self.q['source_sha256'], '0' * 64)
        self.assertIn('qemu source check differs from pin', pins.qemu_problems(self.q, other))

    def test_another_configure_flag_is_refused(self):
        other = self.content.replace('--disable-docs', '--enable-docs')
        self.assertIn('qemu configure line differs from pin', pins.qemu_problems(self.q, other))

    def test_a_pin_naming_another_release_is_refused(self):
        self.assertIn('qemu pin names another release than its version', pins.qemu_problems(dict(self.q, version='11.1.1'), self.content))

    def test_a_host_path_in_the_pinned_line_is_refused(self):
        q = dict(self.q, configure=self.q['configure'] + ['--prefix=/opt/x'])
        self.assertIn('qemu configure is not a list of options, or names a host path', pins.qemu_problems(q, self.content))


class ManifestPins(unittest.TestCase):
    def setUp(self):
        self.oracle = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())
        self.manifest = (ROOT / 'ci/oracle-binaries.lock').read_text()

    def test_the_tree_passes(self):
        self.assertEqual(pins.manifest_problems(self.oracle, self.manifest), [])

    def test_a_missing_digest_is_refused(self):
        for name in ('gdbserver', 'qemu', 'gdb'):
            other = self.manifest.replace(self.oracle[name]['sha256'], 'f' * 64)
            self.assertIn('binary manifest omits ' + name, pins.manifest_problems(self.oracle, other), name)


if __name__ == '__main__':
    # unittest's own report, then one `FAIL NAME` line at column 0 per failing test, so a gate or record names it
    result = unittest.main(exit=False).result
    for case, _ in result.failures + result.errors:
        print('FAIL ' + case.id().split('.')[-1], flush=True)
    sys.exit(0 if result.wasSuccessful() else 1)
