#!/usr/bin/env python3
"""The checked machine's verdict, not its command exit code, decides success."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReaderRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('reader_runner', ROOT / 'tools/test-readers.py')
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_checked_nonzero_verdict_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'reader-checked-verdict'):
            self.runner.check_checked({'verdict': 'exit(1)', 'stdout_inline': 'PASS row\n'}, 'PASS row\n')

    def test_checked_stdout_must_equal_native(self):
        with self.assertRaisesRegex(ValueError, 'reader-checked-output'):
            self.runner.check_checked({'verdict': 'exit(0)', 'stdout_inline': 'different\n'}, 'PASS row\n')

    def test_checked_success_matches_native(self):
        self.runner.check_checked({'verdict': 'exit(0)', 'stdout_inline': 'PASS row\n'}, 'PASS row\n')

    def test_missing_named_row_is_not_success(self):
        with self.assertRaisesRegex(ValueError, 'reader-row-missing'):
            self.runner.check_rows('', ['bytes-fixed-widths'])

    def test_duplicate_named_row_is_not_success(self):
        with self.assertRaisesRegex(ValueError, 'reader-row-count'):
            self.runner.check_rows('PASS x\nPASS x\n', ['x'])


if __name__ == '__main__':
    unittest.main()
