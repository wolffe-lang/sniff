#!/usr/bin/env python3
"""Synthetic producer boundaries exercise the census parser, not DWARF itself."""
import hashlib
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
  DW_AT_stmt_list [DW_FORM_sec_offset] (0x00000000)
0x00000020: DW_TAG_subprogram
  DW_AT_name [DW_FORM_string] ("helper")
  DW_AT_low_pc [DW_FORM_addr] (0x2000)
  DW_AT_high_pc [DW_FORM_udata] (32)
  DW_AT_frame_base [DW_FORM_exprloc] (DW_OP_reg6 RBP)
0x00000030: DW_TAG_variable
  DW_AT_location [DW_FORM_exprloc] (DW_OP_fbreg -16)
0x00000044: Compile Unit: length = 0x40, version = 0x0004
0x00000050: DW_TAG_compile_unit
  DW_AT_producer [DW_FORM_strp] ("clang version synthetic")
  DW_AT_stmt_list [DW_FORM_sec_offset] (0x00000040)
0x00000060: DW_TAG_structure_type
  DW_AT_byte_size [DW_FORM_data1] (4)
'''
LINE = '''debug_line[0x00000000]
standard_opcode_lengths[DW_LNS_advance_pc] = 1
0x00000020: DW_LNS_set_prologue_end
0x00000021: DW_LNS_copy
0x00000022: DW_LNE_end_sequence
debug_line[0x00000040]
0x00000060: DW_LNS_advance_pc
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
            self.assertIn('DW_LNS_copy', wolf['line_opcodes'])
            self.assertNotIn('DW_LNS_advance_pc', wolf['line_opcodes'])
            self.assertIn('DW_LNS_advance_pc', clang['line_opcodes'])
            self.assertEqual(r['wolf_functions'], [{'name': 'helper', 'low_pc': 0x2000,
                'high_pc': 0x2020, 'cfi_fully_covers_range': False}])

    def test_dwarf_spelling_inside_source_names_is_not_a_feature(self):
        info = INFO.replace('("helper")', '("DW_TAG_inlined_subroutine DW_FORM_indirect DW_OP_deref DW_AT_ranges")')
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for name, text in [('info', info), ('line', LINE), ('frames', FRAMES)]:
                (d / name).write_text(text)
            p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/census.py'),
                'summarize', '--info', str(d / 'info'), '--line', str(d / 'line'),
                '--frames', str(d / 'frames'), '--out', str(d / 'summary.json')],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            wolf = next(v for v in json.loads((d / 'summary.json').read_text())['producers']
                        if v['producer'].startswith('wolf'))
            self.assertNotIn('DW_TAG_inlined_subroutine', wolf['tags'])
            self.assertNotIn('DW_FORM_indirect', wolf['forms'])
            self.assertNotIn('DW_AT_ranges', wolf['attributes'])
            self.assertNotIn('DW_OP_deref', wolf['location_ops'])

    def test_capture_rejects_replaced_binary_or_dsym(self):
        for changed in ('prog', 'prog.dSYM/Contents/Resources/DWARF/prog'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                d = Path(directory)
                case = d / 'wolf/case/wolf-debug'
                files = {}
                for name in ('prog', 'prog.dSYM/Contents/Resources/DWARF/prog'):
                    path = case / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'original artifact')
                    files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                (case / changed).write_bytes(b'replaced artifact')
                manifest = {'schema': 1, 'platform': 'Darwin-arm64', 'fixtures': [
                    {'id': 'wolf/case/wolf-debug', 'sha256_read_2': files}]}
                (d / 'builds.json').write_text(json.dumps(manifest))
                tool = d / 'fake-dwarfdump'
                tool.write_text('#!/usr/bin/env python3\nprint("synthetic oracle version")\n')
                tool.chmod(0o755)
                p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/census.py'),
                    'capture', '--builds', str(d / 'builds.json'), '--dwarfdump', str(tool),
                    '--out', str(d / 'out')], capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('fixture-digest-mismatch', p.stderr)
                self.assertFalse((d / 'out/census.json').exists())

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
