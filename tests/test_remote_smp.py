#!/usr/bin/env python3
"""The remote harness binds CPU count and conditional stops to their inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('remote_rows', ROOT / 'tools/session-remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class ProcessorInputs(unittest.TestCase):
    def test_count(self):
        self.assertEqual(remote.smp_count({}), 1)
        self.assertEqual(remote.smp_count({'smp': 1}), 1)
        self.assertEqual(remote.smp_count({'smp': 4}), 4)
        for bad in (0, -1, 2, 3, 5, True, False, '4', 4.0, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'CPU count'):
                remote.smp_count({'smp': bad})

    def test_boot_environment(self):
        self.assertEqual(remote.smp_environment({'PAX_SMP': '99', 'KEEP': 'yes'}, {'smp': 4}),
                         {'PAX_SMP': '4', 'KEEP': 'yes'})
        self.assertEqual(remote.smp_environment({'PAX_SMP': '4'}, {}), {'PAX_SMP': '1'})

    def test_source_bound_condition(self):
        temp_root = Path(os.environ.get('TMPDIR', ROOT / 'target/test-tmp'))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as d:
            p = Path(d)
            source = p / 'kernel/smp/smp.lu'
            source.parent.mkdir(parents=True)
            text = 'pub const CPUS: u64 = 0xffffd08000000000\npub const SPAN: u64 = 0x40000\n'
            source.write_text(text)
            kernel, image = p / 'kernel.elf', p / 'image.iso'
            kernel.write_bytes(b'kernel')
            image.write_bytes(b'image')
            sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
            prediction = {
                'input_evidence': {'kernel': {'sha256': sha(kernel)}, 'image': {'sha256': sha(image)},
                                   'smp_source_sha256': sha(source)},
                'oracle_census': {'cpus': '0xffffd08000000000', 'span': '0x40000', 'cpu_index': 1}}
            self.assertEqual(remote.smp_record(p, kernel, image, prediction), -52226802057216)
            for changed in (kernel, image, source):
                old = changed.read_bytes()
                changed.write_bytes(old + b'changed')
                with self.subTest(changed=changed.name), self.assertRaisesRegex(ValueError, 'input'):
                    remote.smp_record(p, kernel, image, prediction)
                changed.write_bytes(old)
            # Even a new source digest must not silently move the record from the declared constants.
            source.write_text(text.replace('0x40000', '0x80000'))
            prediction['input_evidence']['smp_source_sha256'] = sha(source)
            with self.assertRaisesRegex(ValueError, 'input'):
                remote.smp_record(p, kernel, image, prediction)

    def test_condition_placeholder_requires_binding(self):
        row = {'script': ['break pax_ap_main if rec == @AP_RECORD@']}
        with self.assertRaisesRegex(ValueError, 'input'):
            remote.script_lines(row, 7)
        self.assertEqual(remote.script_lines(row, 7, ap_record=-42), ['break pax_ap_main if rec == -42'])


if __name__ == '__main__':
    unittest.main()
