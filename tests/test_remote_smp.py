#!/usr/bin/env python3
"""The remote harness binds CPU count and conditional stops to their inputs."""
import contextlib
import hashlib
import io
import importlib.util
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('remote_rows', ROOT / 'tools/session-remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class ProcessorInputs(unittest.TestCase):
    def test_combined_gate_step_names_are_unique(self):
        names = []
        for file in ('tools/gate', 'tools/gate-remote-smp'):
            names.extend(re.findall(r'^step ([A-Za-z0-9_-]+) ', (ROOT / file).read_text(), re.M))
        self.assertEqual(len(names), len(set(names)), 'combined record has duplicate literal leaf names')

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

    def test_unjudged_observation_preserves_actual_selection(self):
        text = ('  Id Target Id Frame\n'
                '* 1 Thread 1.1 (CPU#0 [running]) any_frame\n'
                '  2 Thread 1.2 (CPU#1 [running]) another_frame\n'
                '[Current thread is 1 (Thread 1.1)]\n')
        self.assertEqual(remote.observe_processors(text), (2, '1'))
        self.assertEqual(remote.observe_processors(text.replace('thread is 1', 'thread is 2')), (2, '2'))
        self.assertEqual(remote.observe_processors(''), (0, 'unknown'))

    def test_fault_precedes_transcript_difference(self):
        temp_root = Path(os.environ.get('TMPDIR', ROOT / 'target/test-tmp'))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as d:
            p = Path(d)
            (p / 'standin.out').write_text('expected transcript\n')
            a = SimpleNamespace(mode='check', out=str(p / 'out'), rows=None, only=None,
                                accel='tcg', kernel='unused')
            row = {'name': 'standin', 'script': [], 'qemu': False}
            output = io.StringIO()
            with patch.object(remote, 'load_rows', return_value=[row]), \
                 patch.object(remote, 'load_session', return_value=None), \
                 patch.object(remote, 'run_row', return_value=('different transcript\n', 'no prompt after: continue')), \
                 patch.object(remote, 'GOLD', p), contextlib.redirect_stdout(output):
                self.assertEqual(remote.cmd_run(a), 1)
            self.assertIn('FAIL remote standin fault: no prompt after: continue', output.getvalue())
            self.assertNotIn("line 1: want", output.getvalue())

    def test_run_row_preserves_timeout_reason(self):
        temp_root = Path(os.environ.get('TMPDIR', ROOT / 'target/test-tmp'))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as d:
            p = Path(d)
            a = SimpleNamespace(kernel=str(p / 'kernel'), mode='check', sniff='standin')
            row = {'name': 'standin', 'script': ['continue'], 'qemu': False}
            endings = [('continue', 'timeout,interrupt:prompt')]
            with patch.object(remote, 'tool_argv', return_value=(['standin'], '(standin) ')), \
                 patch.object(remote, 'run_tty', return_value=('different transcript', 0, endings)), \
                 patch.object(remote, 'normalise', return_value='different transcript'):
                text, fault = remote.run_row(a, row, SimpleNamespace(ENV_BASE={}), p)
            self.assertEqual(text, 'different transcript')
            self.assertIn('fault:', fault)
            self.assertEqual(json.loads((p / 'standin.driver.json').read_text())['driver_fault'], fault)

    def test_timeout_interrupt_is_not_a_successful_prompt(self):
        self.assertEqual(remote.driver_fault([('continue', 'prompt')]), '')
        self.assertEqual(remote.driver_fault([('!interrupt 1 continue', 'interrupt:prompt')]), '')
        for command, ending in [('continue', 'timeout,interrupt:prompt'),
                                ('continue', 'eof'), ('<initial>', 'time')]:
            with self.subTest(ending=ending):
                self.assertIn('fault:', remote.driver_fault([(command, ending)]))

    def test_condition_placeholder_requires_binding(self):
        row = {'script': ['break pax_ap_main if rec == @AP_RECORD@']}
        with self.assertRaisesRegex(ValueError, 'input'):
            remote.script_lines(row, 7)
        self.assertEqual(remote.script_lines(row, 7, ap_record=-42), ['break pax_ap_main if rec == -42'])


if __name__ == '__main__':
    unittest.main()
