#!/usr/bin/env python3
"""Red-first CLI contracts. No debugger implementation is imported."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/transcript.py'

# Deliberately synthetic; real oracle sessions have separate capture files.
EXPECTED = {'schema': 1, 'events': [
    {'name': 'args', 'line': 2, 'locals': {'a': '3', 'b': '4'},
     'frame_prefix': ['helper', 'main']},
    {'name': 'local', 'line': 3, 'locals': {'a': '3', 'b': '4', 's': '7'},
     'frame_prefix': ['helper', 'main']}]}
ACTUAL = {'schema': 1, 'events': [
    {'name': 'args', 'line': 2, 'locals': {'a': '3', 'b': '4'},
     'frames': ['helper', 'main', 'start']},
    {'name': 'local', 'line': 3, 'locals': {'a': '3', 'b': '4', 's': '7'},
     'frames': ['helper', 'main', 'start']}]}


class Harness(unittest.TestCase):
    def compare(self, candidate, expected=EXPECTED):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / 'expected.json').write_text(json.dumps(expected))
            (directory / 'actual.json').write_text(json.dumps(candidate))
            return subprocess.run([sys.executable, '-I', str(TOOL), 'compare',
                str(directory / 'expected.json'), str(directory / 'actual.json')],
                capture_output=True, text=True)

    def copy(self):
        return json.loads(json.dumps(ACTUAL))

    def test_good(self):
        p = self.compare(ACTUAL)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('PASS session', p.stdout)

    def test_wrong_value(self):
        a = self.copy()
        a['events'][1]['locals']['s'] = '8'
        p = self.compare(a)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('FAIL wrong-value', p.stdout)

    def test_wrong_line_order(self):
        a = self.copy()
        a['events'][0]['line'], a['events'][1]['line'] = 3, 2
        p = self.compare(a)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('FAIL wrong-line-order', p.stdout)

    def test_missing_frame(self):
        a = self.copy()
        a['events'][1]['frames'].remove('main')
        p = self.compare(a)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('FAIL missing-frame', p.stdout)

    def test_missing_source_frame_not_hidden_by_main_shim(self):
        expected = {'schema': 1, 'events': [{'name': 'bt', 'source_frame_prefix': [
            {'function': 'helper', 'file': 'main.lu', 'line': 2},
            {'function': 'main', 'file': 'main.lu', 'line': 9}]}]}
        actual = {'schema': 1, 'events': [{'name': 'bt', 'frames': ['helper', 'main'],
            'source_frames': [{'function': 'helper', 'file': 'main.lu', 'line': 2}]}]}
        p = self.compare(actual, expected)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('FAIL missing-frame', p.stdout)

    def test_missing_event(self):

        a = self.copy()
        a['events'].pop()
        p = self.compare(a)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('FAIL event-order', p.stdout)

    def test_empty_expectation_refused(self):
        p = self.compare(ACTUAL, {'schema': 1, 'events': []})
        self.assertNotEqual(p.returncode, 0)

    def test_normalizations_preserve_values_and_source_coordinates(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            text = ('Process 123 stopped\n'
                    'frame #0: 0x0000000100001234 prog`helper at /lane/main.lu:2:5\n'
                    '(long) s = 0x1234\n(long) pid = 123\n'
                    '(str) label = "Process 123 stopped timestamp=2026-11-05T00:00:00Z"\n'
                    'timestamp=2026-11-05T00:00:00Z\n')
            p = subprocess.run([sys.executable, '-I', str(TOOL), 'normalize',
                '--root', '/lane'], input=text, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('frame #0: <ADDRESS>', p.stdout)
            self.assertIn('<ROOT>/main.lu:2:5', p.stdout)
            self.assertIn('(long) s = 0x1234', p.stdout)
            self.assertIn('(long) pid = 123', p.stdout)
            self.assertIn('(str) label = "Process 123 stopped timestamp=2026-11-05T00:00:00Z"', p.stdout)
            self.assertIn('Process <PID> stopped', p.stdout)
            self.assertIn('timestamp=<TIMESTAMP>', p.stdout)


if __name__ == '__main__':
    unittest.main()
