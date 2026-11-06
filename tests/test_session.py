#!/usr/bin/env python3
"""The S2 session harness without a debugger: normalisation, inventory and
comparator behaviour, using a stand-in `sniff` that replays a golden."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/session.py'
spec = importlib.util.spec_from_file_location('session_tool', TOOL)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)

REPLAY = '''#!/usr/bin/env python3
import sys
from pathlib import Path
gold, mutate = Path(sys.argv[1]), None
args = sys.argv[2:]
script = args[args.index('-x') + 1] if '-x' in args else None
name = Path(script).stem
out = (gold / (name + '.out')).read_text()
err = (gold / (name + '.err')).read_text()
rc = int((gold / (name + '.rc')).read_text())
out = out.replace('<PID>', '4242')
mut = (gold / 'MUTATE').read_text().strip() if (gold / 'MUTATE').exists() else ''
if mut and name == mut:
    out = out.replace('exited normally', 'exited with code 01')
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(rc)
'''


class Normalise(unittest.TestCase):
    def test_pid_and_banner(self):
        fired = set()
        text = ('[Thread debugging using libthread_db enabled]\n'
                'Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".\n'
                '[Inferior 1 (process 4242) exited normally]\n'
                '[Detaching after fork from child process 77]\n')
        out = session.normalize(text, fired)
        self.assertEqual(out, '[Inferior 1 (process <PID>) exited normally]\n[Detaching after fork from child process <PID>]\n')
        self.assertEqual(fired, {'banner', 'pid'})

    def test_other_integers_are_kept(self):
        fired = set()
        text = 'Breakpoint 1, tick (n=4242) at /work/x.c:4\n'
        self.assertEqual(session.normalize(text, fired), text)
        self.assertEqual(fired, set())

    def test_tty_prompt_wrap_and_returns(self):
        fired = set()
        raw = '(sniff) Run till exit from #0  f (n=3)\r\n    at /work/a.c:6\r\n(sniff) '
        out = session.normalize_tty(raw, fired)
        self.assertEqual(out, 'Run till exit from #0  f (n=3) at /work/a.c:6\n')
        self.assertEqual(fired, {'tty', 'wrap80'})


class Inventory(unittest.TestCase):
    def test_rows_are_well_formed(self):
        rows = session.load_rows()
        self.assertGreater(len(rows), 100)
        names = set()
        for r in rows:
            self.assertNotIn(r['name'], names)
            names.add(r['name'])
            self.assertTrue(r['prog'].endswith('/prog'), r['name'])
            self.assertTrue(r['script'], r['name'])
            if r.get('tty'):
                self.assertNotIn('-batch', r['script'])

    def test_goldens_match_rows(self):
        p = subprocess.run([sys.executable, '-I', str(TOOL), 'verify'], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('PASS session-rows', p.stdout)

    def test_programs_exist_in_the_fixture_builder(self):
        # every fixture program a row names is one build-session.py builds
        builder = (ROOT / 'tools/build-session.py').read_text()
        for r in session.load_rows():
            case = r['prog'].split('/')
            if case[0] == 'c':
                self.assertTrue((ROOT / 'fixtures/session/c' / case[1]).is_dir(), r['name'])
            else:
                ok = (ROOT / 'fixtures/session/wolf' / case[1]).is_dir() or (ROOT / 'fixtures/wolf' / case[1]).is_dir()
                self.assertTrue(ok, r['name'])
        self.assertIn('gcc', builder)


class Comparator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.fake = d / 'sniff'
        self.fake.write_text(REPLAY)
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IEXEC)
        session.GOLD = ROOT / 'tests/evidence/linux-s2'
        self.work = d / 'work'
        self.work.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, only, mutate=False):
        gold = ROOT / 'tests/evidence/linux-s2'
        # a wrapper that passes the golden directory as the first argument
        wrapper = Path(self.tmp.name) / 'wrap'
        wrapper.write_text('#!/bin/sh\nexec %s %s "$@"\n' % (self.fake, gold))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        mut = gold / 'MUTATE'
        try:
            if mutate:
                mut.write_text(only)
            args = type('A', (), {'work': str(self.work), 'fixtures': '/nonexistent', 'only': '^%s$' % only, 'sniff': str(wrapper)})()
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = session.cmd_check(args)
            return rc, buf.getvalue()
        finally:
            if mut.exists():
                mut.unlink()

    def test_replay_passes(self):
        rc, out = self.run_check('inferior-c-gcc-exit3')
        self.assertEqual(rc, 0, out)
        self.assertIn('PASS inferior-c-gcc-exit3 [normalised: pid]', out)

    def test_a_changed_output_is_red_by_name(self):
        rc, out = self.run_check('inferior-c-gcc-exit0', mutate=True)
        self.assertEqual(rc, 1, out)
        self.assertIn('FAIL inferior-c-gcc-exit0', out)
        self.assertIn('line 1', out)

    def test_a_missing_golden_is_red(self):
        rows = {'rows': [{'name': 'zz-no-golden', 'prog': 'c/exits/gcc-O0/prog', 'script': ['run']}]}
        rows_file = Path(self.tmp.name) / 'rows.json'
        rows_file.write_text(json.dumps(rows))
        old = session.ROWS
        session.ROWS = rows_file
        try:
            args = type('A', (), {'work': str(self.work), 'fixtures': '/x', 'only': None, 'sniff': str(self.fake)})()
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = session.cmd_check(args)
            self.assertEqual(rc, 1)
            self.assertIn('FAIL zz-no-golden no-golden', buf.getvalue())
        finally:
            session.ROWS = old


if __name__ == '__main__':
    unittest.main()
