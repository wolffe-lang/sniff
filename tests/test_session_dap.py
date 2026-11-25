#!/usr/bin/env python3
"""Units of tools/session-dap.py, the scripted Debug Adapter Protocol client the DAP rows run on: each against
tests/standin_dap.py, so no debugger is needed. A red is the row's own comparison; a timeout, an adapter that ends
early or a body that is not JSON is a fault, named as one and never a red."""
import importlib.util
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


def client():
    spec = importlib.util.spec_from_file_location('session_dap', ROOT / 'tools/session-dap.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(rows, mode='plain', timeout='3', how='check', golden=None):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'rows.json')
        with open(path, 'w') as f:
            json.dump({'schema': 1, 'rows': rows}, f)
        extra = ['--golden', golden] if golden else []
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/session-dap.py'), how,
                            '--adapter', STANDIN + ' ' + mode, '--rows', path, '--out', os.path.join(d, 'out')] + extra,
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


class MemoryReference(unittest.TestCase):
    def test_memref_names_the_last_evaluated_address(self):
        # the stand-in's evaluate answers `(int *) 0x1234` with no memoryReference: the address in its text is used
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'rows.json')
            with open(path, 'w') as f:
                json.dump({'schema': 1, 'rows': [row('m1', INIT, ['send', 'evaluate', {'expression': '&cell', 'context': 'watch'}],
                                                     ['send', 'readMemory', {'memoryReference': '@MEMREF@', 'count': 4}, {'success': True}],
                                                     ['send', 'disconnect', {}], ['exit', 0])]}, f)
            out = os.path.join(d, 'out')
            p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/session-dap.py'), 'check', '--adapter', STANDIN + ' plain',
                                '--rows', path, '--out', out], capture_output=True, text=True, cwd=ROOT,
                               env={'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'SESSION_DAP_TIMEOUT': '3'})
            self.assertIn('PASS dap m1', p.stdout.splitlines(), p.stdout)
            sent = [json.loads(ln)['msg'] for ln in Path(out, 'm1.jsonl').read_text().splitlines()]
            reads = [m for m in sent if m.get('command') == 'readMemory' and m.get('type') == 'request']
            self.assertEqual(reads[0]['arguments']['memoryReference'], '0x1234')


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


def gdb_row(name, *steps):
    return {'name': name, 'prog': '-', 'compare': 'gdb', 'twin': '-', 'differences': ['launch-start'], 'steps': list(steps)}


LAUNCHED = (INIT, ['post', 'launch', {'program': 'x'}], ['wait', 'initialized'], ['send', 'configurationDone', {}],
            ['reply', 'launch'], ['send', 'pause', {'threadId': '@THREAD@'}], ['wait', 'stopped'],
            ['send', 'stackTrace', {'threadId': '@THREAD@'}], ['send', 'disconnect', {}], ['exit', 0])


class Normalise(unittest.TestCase):
    def test_ids_addresses_and_seq_are_named_by_first_appearance(self):
        m = client()
        recs = [{'dir': 'c2a', 'msg': {'seq': 1, 'type': 'request', 'command': 'stackTrace', 'arguments': {'threadId': 9}}},
                {'dir': 'a2c', 'msg': {'seq': 4, 'type': 'event', 'event': 'module', 'body': {'id': 3}}},
                {'dir': 'a2c', 'msg': {'seq': 5, 'type': 'response', 'request_seq': 1, 'command': 'stackTrace', 'success': True,
                                       'body': {'stackFrames': [{'id': 40, 'line': 6, 'instructionPointerReference': '0x5555'},
                                                                {'id': 41, 'line': 7, 'instructionPointerReference': '0x5566'}]}}},
                {'dir': 'a2c', 'msg': {'seq': 6, 'type': 'event', 'event': 'process', 'body': {'systemProcessId': 4242, 'name': 'p'}}},
                {'dir': 'a2c', 'msg': {'seq': 7, 'type': 'event', 'event': 'output', 'body': {'output': 'ready 4242 at 0xdead\n'}}},
                {'dir': 'note', 'msg': {'status': 'ok'}}]
        n = m.normalise(recs, [])
        self.assertEqual(n['sent'], [{'type': 'request', 'command': 'stackTrace', 'arguments': {'threadId': 'T1'}}])
        frames = n['responses'][0]['body']['stackFrames']
        self.assertEqual([f['id'] for f in frames], ['F1', 'F2'])
        self.assertEqual(frames[0]['instructionPointerReference'], '<ADDR>')
        self.assertNotIn('seq', n['responses'][0])
        self.assertNotIn('request_seq', n['responses'][0])
        # module events are left out; a pid in a field or in text is named
        self.assertEqual([e['event'] for e in n['events']], ['process', 'output'])
        self.assertEqual(n['events'][0]['body']['systemProcessId'], 'P1')
        self.assertEqual(n['events'][1]['body']['output'], 'ready <PID> at <ADDR>\n')

    def test_the_repository_root_is_named(self):
        # a golden taken in one checkout holds in another: the paths of the programs and their sources are the
        # repository's, wherever it lies
        m = client()
        root = str(ROOT)
        recs = [{'dir': 'c2a', 'msg': {'seq': 1, 'type': 'request', 'command': 'launch', 'arguments': {'program': root + '/target/p/prog'}}},
                {'dir': 'a2c', 'msg': {'seq': 2, 'type': 'event', 'event': 'process', 'body': {'name': root + '/target/p/prog'}}},
                {'dir': 'a2c', 'msg': {'seq': 3, 'type': 'response', 'request_seq': 1, 'command': 'launch', 'success': True}}]
        n = m.normalise(recs, [])
        self.assertEqual(n['sent'][0]['arguments']['program'], '@ROOT@/target/p/prog')
        self.assertEqual(n['events'][0]['body']['name'], '@ROOT@/target/p/prog')

    def test_launch_start_names_gdb_s_configuration_done(self):
        m = client()
        gdb = {'sent': [], 'events': [], 'responses': [
            {'type': 'response', 'command': 'launch', 'success': True},
            {'type': 'response', 'command': 'configurationDone', 'success': False, 'message': 'notStopped'}]}
        got = m.differ(gdb, ['launch-start'])
        self.assertEqual(got['responses'][1], {'type': 'response', 'command': 'configurationDone', 'success': True})
        self.assertEqual(got['responses'][0], gdb['responses'][0])
        # an unknown difference is the rows file's fault, never silently nothing
        with self.assertRaises(m.Fault):
            m.differ(gdb, ['no-such-difference'])

    def test_registers_scope_names_the_count(self):
        m = client()
        side = {'sent': [], 'events': [], 'responses': [{'type': 'response', 'command': 'scopes', 'success': True, 'body': {'scopes': [
            {'name': 'Locals', 'namedVariables': 3}, {'name': 'Registers', 'namedVariables': 60}]}}]}
        got = m.differ(side, ['registers-scope'])
        self.assertEqual(got['responses'][0]['body']['scopes'][0]['namedVariables'], 3)
        self.assertEqual(got['responses'][0]['body']['scopes'][1]['namedVariables'], '<registers>')


class Golden(unittest.TestCase):
    def test_capture_writes_a_golden_only_when_two_takes_agree(self):
        with tempfile.TemporaryDirectory() as g:
            rc, said, _ = run([gdb_row('g1', *LAUNCHED)], mode='gdbish', how='capture', golden=g)
            self.assertIn('CAPTURED dap g1', said, said)
            self.assertEqual(rc, 0, said)
            golden = json.loads(Path(g, 'g1.json').read_text())
            self.assertEqual(golden['row'], 'g1')
            self.assertEqual([r['command'] for r in golden['responses']],
                             ['initialize', 'launch', 'configurationDone', 'pause', 'stackTrace', 'disconnect'])
            # a value that differs between two takes is never written as a golden
            rc, said, _ = run([gdb_row('g2', *LAUNCHED)], mode='jitter', how='capture', golden=g)
            self.assertTrue(any(ln.startswith('UNSTABLE dap g2') for ln in said), said)
            self.assertFalse(Path(g, 'g2.json').exists())
            self.assertEqual(rc, 1)

    def test_check_holds_a_transcript_to_its_golden_after_the_named_differences(self):
        with tempfile.TemporaryDirectory() as g:
            run([gdb_row('g3', *LAUNCHED)], mode='gdbish', how='capture', golden=g)
            # the stand-in answers configurationDone as sniff does (launch-start), with ids and addresses of its own
            rc, said, _ = run([gdb_row('g3', *LAUNCHED)], golden=g)
            self.assertIn('PASS dap g3', said, said)
            rc, said, _ = run([gdb_row('g3', *LAUNCHED)], mode='otherline', golden=g)
            self.assertTrue(any(ln.startswith('FAIL dap g3 golden: responses[4] stackTrace') for ln in said), said)
            self.assertFalse(any('fault:' in ln for ln in said), said)
            self.assertEqual(rc, 1)

    def test_a_row_with_no_golden_is_a_fault(self):
        with tempfile.TemporaryDirectory() as g:
            rc, said, _ = run([gdb_row('g4', *LAUNCHED)], golden=g)
            self.assertTrue(any(ln.startswith('FAIL dap g4 fault: no golden') for ln in said), said)

    def test_a_golden_whose_requests_differ_is_stale(self):
        with tempfile.TemporaryDirectory() as g:
            run([gdb_row('g5', *LAUNCHED)], mode='gdbish', how='capture', golden=g)
            moved = list(LAUNCHED)
            moved[7] = ['send', 'stackTrace', {'threadId': '@THREAD@', 'levels': 1}]
            rc, said, _ = run([gdb_row('g5', *moved)], golden=g)
            self.assertTrue(any(ln.startswith('FAIL dap g5 fault: the golden is stale') for ln in said), said)


class Selection(unittest.TestCase):
    def test_program_selects_rows_with_or_without_a_program(self):
        rows = [row('b1', INIT, ['send', 'disconnect', {}], ['exit', 0]),
                dict(row('p1', INIT), prog='c/calls/@CC@-O0/prog', src='c/calls')]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'rows.json')
            with open(path, 'w') as f:
                json.dump({'schema': 1, 'rows': rows}, f)
            base = [sys.executable, '-I', str(ROOT / 'tools/session-dap.py')]
            env = {'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'SESSION_DAP_TIMEOUT': '3'}
            p = subprocess.run(base + ['check', '--adapter', STANDIN + ' plain', '--rows', path, '--out', os.path.join(d, 'o'),
                                       '--program', 'no'], capture_output=True, text=True, cwd=ROOT, env=env)
            self.assertEqual(p.stdout.splitlines(), ['PASS dap b1', 'dap rows (check): 1 pass, 0 fail, 0 skip'])
            # a host that cannot run the programs skips those rows by name, and the count is held
            p = subprocess.run(base + ['skip', '--rows', path, '--program', 'yes', '--reason', 'no programs here', '--expect', '1'],
                               capture_output=True, text=True, cwd=ROOT, env=env)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(p.stdout.splitlines(), ['SKIP dap p1 reason=no programs here', 'dap rows (skip): 1 skip'])
            p = subprocess.run(base + ['skip', '--rows', path, '--program', 'yes', '--reason', 'x', '--expect', '2'],
                               capture_output=True, text=True, cwd=ROOT, env=env)
            self.assertEqual(p.returncode, 1)
            self.assertIn('FAIL dap skip count: 1, not 2', p.stdout.splitlines())


class RowsFile(unittest.TestCase):
    def test_the_rows_file_is_well_formed(self):
        rows = json.loads((ROOT / 'tests/dap-rows.json').read_text())['rows']
        names = [r['name'] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        for r in rows:
            self.assertTrue(r['name'].startswith('dap-'), r['name'])
            self.assertIn(r.get('compare', 'own'), ('own', 'gdb'), r['name'])
            if r.get('compare') == 'gdb':
                # a row held to gdb's transcript names its CLI twin and only differences the client knows
                self.assertTrue(r.get('twin'), r['name'])
                for dname in r.get('differences', []):
                    self.assertIn(dname, client().DIFFERENCES, r['name'])
            for s in r['steps']:
                self.assertIn(s[0], ('send', 'post', 'reply', 'wait', 'raw', 'close', 'exit', 'stderr', 'sleep'), r['name'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
