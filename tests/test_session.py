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
mspec = importlib.util.spec_from_file_location('session_mac_tool', ROOT / 'tools/session-mac.py')
smac = importlib.util.module_from_spec(mspec)
mspec.loader.exec_module(smac)

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


class MacThreadFacts(unittest.TestCase):
    """A thread's status block is no frame fact on either side: lldb prints `thread select`'s when it pleases."""
    STATUS1 = ('* thread #1, queue = \'com.apple.main-thread\'\n'
               '    frame #0: 0x0000000100000870 prog`spin(flag=0x1, want=1, slot=0) at main.c:35:12\n'
               '   34  \tstatic void spin(volatile int *flag, int want, int slot) {\n')
    BT1 = ('* thread #1, queue = \'com.apple.main-thread\'\n'
           '  * frame #0: 0x0000000100000870 prog`spin(flag=0x1, want=1, slot=0) at main.c:35:12\n'
           '    frame #1: 0x0000000100000684 prog`main(argc=1, argv=0x2) at main.c:72:5\n')
    STATUS4 = ('* thread #4, stop reason = breakpoint 1.1\n'
               '    frame #0: 0x0000000100000500 prog`work(n=4) at main.c:50:9\n'
               '-> 50  \t    int total = 0;\n')
    BT4 = ('* thread #4, stop reason = breakpoint 1.1\n'
           '  * frame #0: 0x0000000100000500 prog`work(n=4) at main.c:50:9\n'
           '    frame #1: 0x0000000100000840 prog`worker(arg=0x3) at main.c:60:14\n')
    WANT = [('frame', 0, 'spin', 'main.c', 35), ('frame', 1, 'main', 'main.c', 72)]
    WANT4 = [('frame', 0, 'work', 'main.c', 50), ('frame', 1, 'worker', 'main.c', 60)]

    def test_lldb_status_block_in_either_place(self):
        timely = ('(lldb) thread select 1\n' + self.STATUS1 + '(lldb) bt\n' + self.BT1 +
                  '(lldb) thread select 4\n' + self.STATUS4 + '(lldb) bt\n' + self.BT4)
        # as one take printed it: both selections' status blocks under the second bt's prompt
        late = ('(lldb) thread select 1\n(lldb) bt\n' + self.BT1 +
                '(lldb) thread select 4\n(lldb) bt\n' + self.STATUS1 + self.STATUS4 + self.BT4)
        self.assertEqual(smac.facts_lldb(timely), self.WANT + self.WANT4)
        self.assertEqual(smac.facts_lldb(late), self.WANT + self.WANT4)
        # a backtrace whose second frame is unstarred is still a backtrace
        bt_late_first = '(lldb) bt\n' + self.BT1.replace('  * frame #0', '    frame #0')
        self.assertEqual(smac.facts_lldb(bt_late_first), self.WANT)

    def test_sniff_thread_command_frame_is_status(self):
        out = ('[Switching to thread 1 (Thread 0x16fe87000 (tid 77))]\n'
               '#0  spin (flag=0x1, want=1, slot=0) at /w/main.c:35\n35\t    while (*flag < want) seen[slot] = 1;\n'
               '#0  spin (flag=0x1, want=1, slot=0) at /w/main.c:35\n#1  0x0000000100000684 in main (argc=1, argv=0x2) at /w/main.c:72\n')
        self.assertEqual(smac.facts_sniff(out), self.WANT)
        # a frame after a stop's switch line (capital T) is not a thread command's
        stop = '[Switching to Thread 0x16fe87000 (tid 77)]\n#0  spin (flag=0x1, want=1, slot=0) at /w/main.c:35\n'
        self.assertEqual(smac.facts_sniff(stop), self.WANT[:1])


class ThreadsAndAttach(unittest.TestCase):
    """S6's normalisations and the attach runner, each red on the break it exists to catch."""
    TABLE = ('  Id   Target Id                              Frame \n'
             '* 1    Thread 0x7ffff7da2740 (LWP 212) "prog" 0x00005555555551de in spin (flag=0x5555 <worked>, want=1) at /w/m.c:15\n'
             '  2    Thread 0x7ffff7da16c0 (LWP 1215) "prog" spin (flag=0x5556 <released>, want=1) at /w/m.c:15\n')

    def test_lwp_ids_are_numbered_by_first_appearance(self):
        fired = set()
        text = '[New Thread 0x1 (LWP 77)]\n[New Thread 0x2 (LWP 78)]\n[Switching to Thread 0x2 (LWP 78)]\n'
        out = session.normalize(text, fired)
        self.assertEqual(out, '[New Thread <T1> (LWP <L1>)]\n[New Thread <T2> (LWP <L2>)]\n[Switching to Thread <T2> (LWP <L2>)]\n')
        self.assertEqual(fired, {'lwp', 'thread-addr'})
        # a debugger that switched to the wrong thread is still told apart
        wrong = text.replace('to Thread 0x2 (LWP 78)', 'to Thread 0x1 (LWP 77)')
        self.assertNotEqual(session.normalize(wrong, set()), out)

    def test_threads_table_padding_and_spin_prefix(self):
        fired = set()
        a = session.normalize(self.TABLE, fired)
        other = self.TABLE.replace('LWP 1215) "prog" spin', 'LWP 9) "prog" 0x0000555555555198 in spin')
        other = other.replace('LWP 212) "prog" 0x00005555555551de in', 'LWP 21) "prog"')
        self.assertEqual(session.normalize(other, set()), a)
        self.assertEqual(fired, {'lwp', 'spin', 'threads-table', 'thread-addr'})
        self.assertIn('* 1 Thread <T1> (LWP <L1>) "prog" spin (', a)
        # a different frame or name is not normalised away, nor two threads shown at one address
        for change in (('want=1) at /w/m.c:15\n  2', 'want=2) at /w/m.c:15\n  2'), ('0x7ffff7da16c0', '0x7ffff7da2740'),
                       ('"prog" spin (flag=0x5556', '"prag" spin (flag=0x5556')):
            self.assertNotEqual(session.normalize(self.TABLE.replace(*change), set()), a, change)

    def test_thread_addresses_are_the_hosts(self):
        # the C library sizes a thread's stack by the stack limit: an 8 MiB limit and a 16 MiB one put the second
        # thread 8 MiB apart (a CI runner against the host the goldens came from), and PAX maps them elsewhere
        host = ('[New Thread 0x7ffff7da16c0 (LWP 215)]\n[New Thread 0x7ffff75a06c0 (LWP 216)]\n'
                '[Switching to thread 2 (Thread 0x7ffff75a06c0 (LWP 216))]\n[Thread 0x7ffff7da16c0 (LWP 215) exited]\n')
        runner = host.replace('0x7ffff75a06c0', '0x7ffff6da06c0')
        pax = host.replace('0x7ffff7da16c0', '0x7efffffff6c0').replace('0x7ffff75a06c0', '0x7effffefe6c0')
        fired = set()
        a = session.normalize(host, fired)
        self.assertEqual(session.normalize(runner, set()), a)
        self.assertIn('thread-addr', fired)
        self.assertIn('[Switching to thread 2 (Thread <T2> (LWP <L2>))]', a)
        session.PAX_MODE = True
        try:
            self.assertEqual(session.normalize(pax, set()), a)
            # only a thread's own address: another address beside it is still the stack rule's or compared
            other = 'p = 0x7efffffff6c0\n'
            self.assertEqual(session.normalize(other, set()), other)
        finally:
            session.PAX_MODE = False
        # the address names the thread: a switch to the other thread, or a thread's end under another's
        # address, is told apart
        for wrong in (host.replace('(Thread 0x7ffff75a06c0 (LWP 216))', '(Thread 0x7ffff7da16c0 (LWP 216))'),
                      host.replace('[Thread 0x7ffff7da16c0 (LWP 215) exited]', '[Thread 0x7ffff75a06c0 (LWP 215) exited]')):
            self.assertNotEqual(session.normalize(wrong, set()), a)

    def test_ticks_only_where_a_row_names_it(self):
        text = 'Breakpoint 1, tick (n=7) at /w/s.c:13\n'
        self.assertEqual(session.normalize(text, set()), text)
        fired = set()
        self.assertEqual(session.normalize(text, fired, {'normalise': ['ticks']}), 'Breakpoint 1, tick (n=<N>) at /w/s.c:13\n')
        self.assertEqual(fired, {'ticks'})

    def test_process_ids_in_attach_lines(self):
        fired = set()
        text = ('Attaching to program: /w/prog, process 4242\nwarning: process 4242 is already traced by process 4243\n'
                '* 1    process 4242 "prog" nap () at /w/s.c:19\n')
        out = session.normalize(text, fired)
        self.assertEqual(out, 'Attaching to program: /w/prog, process <PID>\nwarning: process <PID> is already traced by process <PID>\n'
                              '* 1 process <PID> "prog" nap () at /w/s.c:19\n')
        self.assertEqual(fired, {'pid', 'threads-table'})

    def test_refuses_is_an_own_row_against_a_refusing_golden(self):
        row = {'compare': 'own', 'why': 'errno', 'gdb': 'refuses', 'expect': [],
               'expect_err': ['x:1: Error in sourced command file:', 'ptrace: Operation not permitted.'], 'expect_rc': 1}
        err = 'x:1: Error in sourced command file:\nptrace: Operation not permitted.\n'
        self.assertEqual(session.judge(row, '', err, 1, 'Could not attach\n', 'ptrace: Inappropriate ioctl for device.\n', '1\n'), [])
        self.assertTrue(session.judge(row, '', err, 1, 'Could not attach\n', '', '0\n'))
        self.assertTrue(session.judge(row, '', 'ptrace: Inappropriate ioctl for device.\n', 1, '', '', '1\n'))
        self.assertEqual(session.row_form(dict(row, name='r')), '')

    def test_attach_run_gives_the_pid_and_reports_the_sleeper(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            sleeper = d / 'c/sleeper/x/prog'
            sleeper.parent.mkdir(parents=True)
            sleeper.write_text('#!%s\nimport os, sys, time\nprint("ready %%d" %% os.getpid(), flush=True)\ntime.sleep(0.3)\n'
                               'print("done " + sys.argv[1])\nsys.exit(3)\n' % sys.executable)
            sleeper.chmod(0o755)
            dbg = d / 'dbg'
            dbg.write_text('#!%s\nimport sys\na = sys.argv[1:]\nprint(" ".join("PID" if x.isdigit() else x for x in a[a.index("-x") + 2:]))\n'
                           'print(open(a[a.index("-x") + 1]).read(), end="")\n' % sys.executable)
            dbg.chmod(0o755)
            old = session.SCRIPTS
            session.SCRIPTS = 'scripts'
            try:
                row = {'name': 'r', 'script': ['attach {pid}', 'detach'], 'attach': {'ticks': 5}}
                out, err, rc = session.attach_run(str(dbg), row, str(sleeper), str(d), False)
                lines = out.splitlines()
                self.assertEqual(lines[0], str(sleeper))
                self.assertRegex(lines[1], r'^attach \d+$')
                self.assertEqual(lines[-1], '[sleeper exited with code 3: done 5]')
                out, err, rc = session.attach_run(str(dbg), dict(row, attach={'ticks': 2, 'form': 'dash-p'}), str(sleeper), str(d), False)
                self.assertEqual(out.splitlines()[0], '-p PID ' + str(sleeper))
            finally:
                session.SCRIPTS = old


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
        spec = importlib.util.spec_from_file_location('build_session', ROOT / 'tools/build-session.py')
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        for r in session.load_rows():
            case = r['prog'].split('/')
            if case[0] == 'c':
                gone = case[1].endswith('-gone') and case[1][:-5] in build.GONE
                corpus = case[1] in build.CORPUS_C and (ROOT / 'fixtures/c' / case[1]).is_dir()
                self.assertTrue((ROOT / 'fixtures/session/c' / case[1]).is_dir() or corpus or gone, r['name'])
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


class CompareModes(unittest.TestCase):
    """The head, subset and own comparisons, each shown red on the break it exists to catch."""
    GDB = ['list, l', 'List specified function or line.', 'With no argument, lists ten more lines.', '',
           'By default, ten lines.']

    def test_bytes_is_the_default(self):
        self.assertEqual(session.lines_verdict({}, ['a', 'b'], ['a', 'b']), '')
        self.assertNotEqual(session.lines_verdict({}, ['a', 'b'], ['a', 'c']), '')

    def test_head_holds_the_names_and_summary(self):
        row = {'compare': 'head', 'head': 2, 'why': 'listsize'}
        self.assertEqual(session.lines_verdict(row, self.GDB, self.GDB[:2] + ['sniff lists ten lines.']), '')
        self.assertIn('held lines', session.lines_verdict(row, self.GDB, ['list', self.GDB[1], 'x']))
        self.assertIn('held lines', session.lines_verdict(row, self.GDB, [self.GDB[0], 'List a function.', 'x']))
        self.assertIn('nothing of its own', session.lines_verdict(row, self.GDB, self.GDB[:2]))

    def test_subset_keeps_gdb_order_and_names_own_lines(self):
        row = {'compare': 'subset', 'why': 'restricted', 'own': ['sniff only']}
        self.assertEqual(session.lines_verdict(row, self.GDB, [self.GDB[0], self.GDB[3], 'sniff only', self.GDB[4]]), '')
        self.assertIn('in order', session.lines_verdict(row, self.GDB, [self.GDB[4], self.GDB[0], 'sniff only']))
        self.assertIn('in order', session.lines_verdict(row, self.GDB, [self.GDB[0], 'an invented line', 'sniff only']))
        self.assertIn('own line is missing', session.lines_verdict(row, self.GDB, [self.GDB[0]]))
        self.assertIn('prints nothing', session.lines_verdict(row, self.GDB, []))

    def test_own_is_the_expected_text_and_gdb_has_the_command(self):
        row = {'compare': 'own', 'why': 'lacking', 'expect': ['"tui" is a gdb command that sniff does not implement yet.']}
        good = row['expect'][0] + '\n'
        self.assertEqual(session.judge(row, good, '', 0, 'Text User Interface commands.\n', '', '0\n'), [])
        self.assertTrue(session.judge(row, 'Undefined command: "tui".\n', '', 0, 'Text User Interface commands.\n', '', '0\n'))
        self.assertTrue(session.judge(row, good, '', 0, '', 'Undefined command: "tui".\n', '1\n'))
        mine = dict(row, gdb='lacks')
        self.assertEqual(session.judge(mine, good, '', 0, '', '', '1\n'), [])
        self.assertTrue(session.judge(mine, good, '', 0, 'Text User Interface commands.\n', '', '0\n'))

    def test_stderr_and_status_are_always_compared(self):
        row = {'compare': 'head', 'head': 1, 'why': 'x'}
        self.assertEqual(session.judge(row, 'a\nmine\n', '', 0, 'a\nb\n', '', '0\n'), [])
        self.assertTrue(session.judge(row, 'a\nmine\n', 'Undefined command: "help".\n', 1, 'a\nb\n', '', '0\n'))

    def test_row_form(self):
        self.assertEqual(session.row_form({'name': 'r'}), '')
        self.assertTrue(session.row_form({'name': 'r', 'head': 2}))
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'head', 'head': 2}))
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'head', 'why': 'w'}))
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'own', 'why': 'w'}))
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'subset', 'why': 'w', 'tty': True}))
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'sideways', 'why': 'w'}))
        self.assertEqual(session.row_form({'name': 'r', 'compare': 'subset', 'why': 'w', 'own': ['x']}), '')
        self.assertTrue(session.row_form({'name': 'r', 'compare': 'own', 'why': 'w', 'expect': ['x'], 'gdb': 'maybe'}))
        self.assertEqual(session.row_form({'name': 'r', 'compare': 'own', 'why': 'w', 'expect': [], 'expect_err': ['e']}), '')


if __name__ == '__main__':
    unittest.main()
