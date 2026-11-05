#!/usr/bin/env python3
"""Synthetic producer boundaries exercise the census parser, not DWARF itself."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INFO = '''0x00000000: Compile Unit: length = 0x40, version = 0x0005
0x0000000c: DW_TAG_compile_unit
  DW_AT_producer [DW_FORM_string] ("wolf v0 (wolfgang 0.2.37)")
0x00000020: DW_TAG_subprogram
  DW_AT_name [DW_FORM_string] ("helper")
  DW_AT_frame_base [DW_FORM_exprloc] (DW_OP_reg6 RBP)
0x00000030: DW_TAG_variable
  DW_AT_location [DW_FORM_exprloc] (DW_OP_fbreg -16)
0x00000044: Compile Unit: length = 0x40, version = 0x0004
0x00000050: DW_TAG_compile_unit
  DW_AT_producer [DW_FORM_strp] ("clang version synthetic")
0x00000060: DW_TAG_structure_type
  DW_AT_byte_size [DW_FORM_data1] (4)
'''
LINE = '''debug_line[0]
0x00000020: DW_LNS_set_prologue_end
0x00000021: DW_LNS_copy
0x00000022: DW_LNE_end_sequence
'''
FRAMES = '''.eh_frame contents:
00000000 00000010 CIE
00000014 00000020 FDE cie=0 pc=0000000000001000...0000000000001020
.debug_frame contents:
'''


class Census(unittest.TestCase):
    def test_producers_remain_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for name, text in [('info', INFO), ('line', LINE), ('frames', FRAMES)]:
                (d / name).write_text(text)
            p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/census.py'),
                'summarize', '--info', str(d / 'info'), '--line', str(d / 'line'),
                '--frames', str(d / 'frames'), '--out', str(d / 'summary.json')],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            r = json.loads((d / 'summary.json').read_text())
            self.assertEqual(r['units'], 2)
            wolf = next(v for v in r['producers'] if v['producer'].startswith('wolf'))
            clang = next(v for v in r['producers'] if v['producer'].startswith('clang'))
            self.assertEqual(wolf['versions'], [5])
            self.assertEqual(clang['versions'], [4])
            self.assertNotIn('DW_TAG_structure_type', wolf['tags'])
            self.assertIn('DW_TAG_structure_type', clang['tags'])
            self.assertIn('DW_FORM_exprloc', wolf['forms'])
            self.assertIn('DW_OP_fbreg', wolf['location_ops'])
            self.assertEqual(r['cfi_kinds'], ['.eh_frame'])
            self.assertIn('DW_LNS_copy', r['line_opcodes'])

    def test_empty_dump_is_not_a_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'empty').write_text('')
            p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/census.py'),
                'summarize', '--info', str(d / 'empty'), '--line', str(d / 'empty'),
                '--frames', str(d / 'empty'), '--out', str(d / 'summary.json')],
                capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse((d / 'summary.json').exists())


if __name__ == '__main__': unittest.main()
