#!/usr/bin/env python3
"""Units of tools/session-dap.py, the scripted Debug Adapter Protocol client the DAP rows run on: each against
tests/standin_dap.py, so no debugger is needed. A red is the row's own comparison; a timeout, an adapter that ends
early or a body that is not JSON is a fault, named as one and never a red."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDIN = 'python3 -I %s' % (ROOT / 'tests/standin_dap.py')
INIT = ['send', 'initialize', {'clientID': 'test', 'adapterID': 'test'}]


def run(rows, mode='plain', timeout='3'):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'rows.json')
        with open(path, 'w') as f:
            json.dump({'schema': 1, 'rows': rows}, f)
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/session-dap.py'), 'check',
                            '--adapter', STANDIN + ' ' + mode, '--rows', path, '--out', os.path.join(d, 'out')],
                           capture_output=True, text=True, cwd=ROOT,
                           env={'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'SESSION_DAP_TIMEOUT': timeout})
        return p.returncode, p.stdout.splitlines(), p.stderr


def row(name, *steps):
    return {'name': name, 'prog': '-', 'steps': list(steps)}


class Steps(unittest.TestCase):
    def test_a_session_passes(self):
        rc, said, _ = run([row('r1', INIT, ['send', 'disconnect', {}, {'success': True}], ['exit', 0])])
        self.assertIn('PASS dap r1', said)
        self.assertIn('dap rows (check): 1 pass, 0 fail, 0 skip', said)
        self.assertEqual(rc, 0)

    def test_a_thread_id_comes_from_the_thread_event(self):
        # threads is refused while the program runs; pause names the thread a thread event reported started
        rc, said, _ = run([row('r2', INIT, ['post', 'launch', {'program': 'x'}], ['wait', 'initialized'],
                               ['send', 'configurationDone', {}], ['reply', 'launch'],
                               ['send', 'threads', {}, {'success': False, 'message': 'notStopped'}],
                               ['send', 'pause', {'threadId': '@THREAD@'}, {'success': True}],
                               ['wait', 'stopped', {'reason': 'pause'}],
                               ['send', 'stackTrace', {'threadId': '@THREAD@'}],
                               ['send', 'disconnect', {}], ['exit', 0])])
        self.assertIn('PASS dap r2', said, said)

    def test_an_expectation_that_differs_is_a_red_by_comparison(self):
        rc, said, _ = run([row('r3', INIT, ['send', 'stepBack', {}, {'success': True}],
                               ['send', 'disconnect', {}], ['exit', 0])])
        self.assertTrue(any(ln.startswith('FAIL dap r3 stepBack: success is false, not true') for ln in said), said)
        self.assertFalse(any('fault:' in ln for ln in said), said)
        self.assertEqual(rc, 1)

    def test_the_declared_capabilities_are_compared_exactly(self):
        caps = ['send', 'initialize', {'adapterID': 'test'}, {'success': True, 'body_true': ['supportsConfigurationDoneRequest']}]
        rc, said, _ = run([row('r4', caps, ['send', 'disconnect', {}], ['exit', 0])], mode='badcaps')
        self.assertTrue(any(ln.startswith('FAIL dap r4 initialize: the body declares supportsStepBack') for ln in said), said)
        rc, said, _ = run([row('r4', caps, ['send', 'disconnect', {}], ['exit', 0])])
        self.assertIn('PASS dap r4', said, said)

    def test_an_exit_code_and_standard_error_are_compared(self):
        rc, said, _ = run([row('r5', INIT, ['send', 'disconnect', {}], ['exit', 0])], mode='exit3')
        self.assertTrue(any(ln.startswith('FAIL dap r5 exit: 3, not 0') for ln in said), said)
        rc, said, _ = run([row('r5', INIT, ['send', 'disconnect', {}], ['exit', 3], ['stderr', 'stand-in: exit 3'])], mode='exit3')
        self.assertIn('PASS dap r5', said, said)
        rc, said, _ = run([row('r5', INIT, ['send', 'disconnect', {}], ['exit', 3], ['stderr', 'something else'])], mode='exit3')
        self.assertTrue(any(ln.startswith("FAIL dap r5 stderr: no line holds 'something else'") for ln in said), said)

    def test_raw_bytes_and_a_closed_input_reach_the_adapter(self):
        # the stand-in reads the raw frame as a request; closing its input then ends it
        rc, said, _ = run([row('r6', ['raw', 'Content-Length: 59\r\n\r\n{"seq":1,"type":"request","command":"initialize","x":"abc"}'],
                               ['close'], ['exit', 0])])
        self.assertIn('PASS dap r6', said, said)


class RelativeSniff(unittest.TestCase):
    def test_a_relative_sniff_path_runs_from_any_row_directory(self):
        # the gate passes target/sniff; each row runs the adapter from its own directory
        wrapper = ROOT / 'target/tmp/standin-sniff'
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text('#!/bin/sh\nexec %s -I %s plain\n' % (sys.executable, ROOT / 'tests/standin_dap.py'))
        wrapper.chmod(0o755)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'rows.json')
            with open(path, 'w') as f:
                json.dump({'schema': 1, 'rows': [row('r7', INIT, ['send', 'disconnect', {}], ['exit', 0])]}, f)
            p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/session-dap.py'), 'check', '--sniff',
                                'target/tmp/standin-sniff', '--rows', path, '--out', os.path.relpath(os.path.join(d, 'out'), ROOT)],
                               capture_output=True, text=True, cwd=ROOT, env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'})
        self.assertIn('PASS dap r7', p.stdout.splitlines(), p.stdout + p.stderr)


class Faults(unittest.TestCase):
    def test_a_hang_is_a_fault_by_name(self):
        rc, said, _ = run([row('f1', INIT, ['post', 'launch', {}], ['wait', 'initialized'],
                               ['send', 'pause', {'threadId': '@THREAD@'}], ['wait', 'stopped'],
                               ['send', 'stackTrace', {'threadId': '@THREAD@'}], ['send', 'disconnect', {}])], mode='hang', timeout='1')
        self.assertTrue(any(ln.startswith('FAIL dap f1 fault: no response to stackTrace within 1s') for ln in said), said)

    # An adapter that has gone away is one fault with one name, "the adapter went away", whichever of the client's
    # write (a broken pipe) or its read (the end of the adapter's output) finds out first. The stand-in's `eof` mode
    # exits, so either may; `deaf` and `mute` force each order.
    def test_an_adapter_that_ends_early_is_a_fault(self):
        rc, said, _ = run([row('f2', INIT, ['send', 'threads', {}])], mode='eof')
        self.assertTrue(any(ln.startswith('FAIL dap f2 fault: the adapter went away') for ln in said), said)

    def test_a_write_that_finds_the_adapter_gone_is_the_same_fault(self):
        # its input closed before it answered: the next write breaks the pipe before any read could see an end
        rc, said, _ = run([row('f2w', INIT, ['send', 'threads', {}])], mode='deaf')
        self.assertTrue(any(ln.startswith('FAIL dap f2w fault: the adapter went away') for ln in said), said)
        self.assertFalse(any('Broken pipe' in ln for ln in said), said)

    def test_a_read_that_finds_the_adapter_gone_is_the_same_fault(self):
        # its output closed while its input stays open: the write succeeds and the read sees the end
        rc, said, _ = run([row('f2r', INIT, ['send', 'threads', {}])], mode='mute')
        self.assertTrue(any(ln.startswith('FAIL dap f2r fault: the adapter went away') for ln in said), said)

    def test_a_body_that_is_not_json_is_a_fault(self):
        rc, said, _ = run([row('f3', INIT)], mode='garbage')
        self.assertTrue(any(ln.startswith('FAIL dap f3 fault: a body that is not JSON') for ln in said), said)

    def test_a_reverse_request_is_refused_and_noted(self):
        rc, said, _ = run([row('f4', INIT, ['send', 'disconnect', {}], ['exit', 0])], mode='reverse')
        self.assertIn('PASS dap f4', said, said)

    def test_a_thread_placeholder_with_no_thread_is_a_fault(self):
        rc, said, _ = run([row('f5', INIT, ['send', 'stackTrace', {'threadId': '@THREAD@'}])])
        self.assertTrue(any(ln.startswith('FAIL dap f5 fault: no thread id for @THREAD@') for ln in said), said)


class Selftest(unittest.TestCase):
    def test_the_selftest_passes(self):
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/session-dap.py'), 'selftest'], capture_output=True,
                           text=True, cwd=ROOT, env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(p.stdout.splitlines()[-1].startswith('PASS session-dap-selftest'), p.stdout)


class RowsFile(unittest.TestCase):
    def test_the_rows_file_is_well_formed(self):
        rows = json.loads((ROOT / 'tests/dap-rows.json').read_text())['rows']
        names = [r['name'] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        for r in rows:
            self.assertTrue(r['name'].startswith('dap-'), r['name'])
            self.assertIn(r.get('compare', 'own'), ('own',), r['name'])
            for s in r['steps']:
                self.assertIn(s[0], ('send', 'post', 'reply', 'wait', 'raw', 'close', 'exit', 'stderr', 'sleep'), r['name'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
