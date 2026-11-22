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
import time
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


def elf_core(prstatus, xstate):
    """A minimal ELF64 core: one PT_NOTE laid at 4 with prstatus NT_PRSTATUS notes (owner CORE, 336 bytes, pr_pid
    4474, 4475, ... at offset 32) and one NT_X86_XSTATE (owner LINUX) of xstate bytes when xstate is not 0."""
    import struct

    def note(owner, kind, desc):
        name = owner.encode() + b'\0'
        name += b'\0' * (-len(name) % 4)
        return struct.pack('<III', len(owner) + 1, len(desc), kind) + name + desc + b'\0' * (-len(desc) % 4)
    notes = b''.join(note('CORE', 1, b'\0' * 32 + struct.pack('<I', 4474 + i) + b'\0' * 300) for i in range(prstatus))
    if xstate:
        notes += note('LINUX', 0x202, b'\0' * xstate)
    head = b'\x7fELF' + bytes([2, 1, 1]) + b'\0' * 9
    head += struct.pack('<HHIQQQIHHHHHH', 4, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack('<IIQQQQQQ', 4, 0, 120, 0, 0, len(notes), 0, 1)
    return head + ph + notes


class XstateSize(unittest.TestCase):
    """gdb's warnings that a core's XSAVE section is not the size its layouts give for the host's processor: larger
    (`Unexpected size of section`, a runner whose XSAVE area carries AMX tile state) or smaller (`... too small`, an
    AMD EPYC runner whose XSAVE area is 2432 bytes). Each exact sentence on gdb's standard error, and the blank line
    directly before it, are dropped and counted; each must name a thread of the row's core, at most twice (gdb
    warns twice for the thread it selects); nothing else is dropped."""
    W = "warning: Unexpected size of section `.reg-xstate/4474' in core file.\n"
    W2 = "warning: Unexpected size of section `.reg-xstate/4475' in core file.\n"
    S = "warning: Section `.reg-xstate/4474' in core file too small.\n"

    def test_the_warning_and_its_blank_line_go(self):
        self.assertEqual(session.drop_xstate('\n' + self.W + '[New LWP 4474]\n'), ('[New LWP 4474]\n', [4474], 2))
        self.assertEqual(session.drop_xstate(self.W), ('', [4474], 1))
        self.assertEqual(session.drop_xstate(self.W.rstrip('\n')), ('', [4474], 1))
        self.assertEqual(session.drop_xstate('\n' + self.W + '\n' + self.W2), ('', [4474, 4475], 4))
        self.assertEqual(session.drop_xstate(self.W + self.W2), ('', [4474, 4475], 2))
        self.assertEqual(session.drop_xstate('a\n\n' + self.W + '\nb\n'), ('a\n\nb\n', [4474], 2))

    def test_the_too_small_warning_goes(self):
        # as the hosted AMD EPYC runner printed it over a one-thread core: twice for the selected thread
        err = '\n' + self.S + '\n' + self.S + '/w/r.cmd:1: Error in sourced command file:\nThe program is not being run.\n'
        self.assertEqual(session.drop_xstate(err),
                         ('/w/r.cmd:1: Error in sourced command file:\nThe program is not being run.\n', [4474, 4474], 4))
        self.assertEqual(session.drop_xstate(self.S + self.S), ('', [4474, 4474], 2))

    def test_nothing_else_goes(self):
        for text in ('\nCore was generated by `prog\'.\n',
                     "\nwarning: Unexpected size of section `.reg2/4474' in core file.\n",
                     "\nwarning: Unexpected size of section `.reg-xstate/abc' in core file.\n",
                     "\nwarning: Unexpected size of section `.reg-xstate/4474' in core file. and more\n",
                     "\nwarning: Section `.reg2/4474' in core file too small.\n",
                     "\nwarning: Section `.reg-xstate/4474' in core file too large.\n",
                     ' ' + self.W,
                     ' ' + self.S,
                     "\nwarning: Error reading shared library list entry at 0x80\n",
                     '\n\n'):
            self.assertEqual(session.drop_xstate(text), (text, [], 0), text)

    def test_a_warning_not_of_the_cores_threads_is_red(self):
        self.assertEqual(session.xstate_excess([], []), '')
        self.assertEqual(session.xstate_excess([4474, 4474], [4474]), '')
        self.assertEqual(session.xstate_excess([4497, 4497, 4492, 4495, 4496], [4497, 4492, 4495, 4496]), '')
        self.assertIn('xstate-size', session.xstate_excess([4474, 4474, 4474], [4474]))
        self.assertIn('xstate-size', session.xstate_excess([4475], [4474]))
        self.assertIn('xstate-size', session.xstate_excess([4474], []))

    def test_host_facts_and_kept_drift(self):
        facts = session.host_facts()
        self.assertRegex(facts, r'^HOST kernel=\S+ cpu=\S+ flags=\S+$')
        with tempfile.TemporaryDirectory() as d:
            path = session.keep_drift('core-gcc-segv', 'out\n', '\n' + self.W, d, (4, 2432, [4497, 4492, 4495, 4496]))
            self.assertEqual(path.read_text(), '\n' + self.W)
            self.assertEqual((Path(d) / 'core-gcc-segv.out').read_text(), 'out\n')
            self.assertEqual((Path(d) / 'core-gcc-segv.core').read_text(), 'threads=4 xstate=2432 pids=4497,4492,4495,4496\n')
            session.keep_drift('break-gcc-main', 'o\n', 'e\n', d)
            self.assertFalse((Path(d) / 'break-gcc-main.core').exists())
            self.assertIsNone(session.row_core_facts({'name': 'r'}, d))
            self.assertEqual(session.row_core_facts({'name': 'r', 'core': {'of': 'x', 'file': 'missing'}}, d), (0, 0, []))

    def test_core_facts(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'c.core'
            path.write_bytes(elf_core(4, 11008))
            self.assertEqual(session.core_facts(path), (4, 11008, [4474, 4475, 4476, 4477]))
            path.write_bytes(elf_core(1, 0))
            self.assertEqual(session.core_facts(path), (1, 0, [4474]))
            path.write_bytes(elf_core(1, 832)[:100])
            self.assertEqual(session.core_facts(path), (0, 0, []))
            self.assertEqual(session.core_facts(Path(d) / 'missing.core'), (0, 0, []))


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


class MacCoreFacts(unittest.TestCase):
    """Over a Mach-O core: gdb's banner and lldb's `process status` print the stop as a status block (no frame fact);
    the signal that ended the program is a `died` fact on both sides; `x` and `memory read` give `mem` facts."""
    SNIFF = ("Core was generated by `/w/fx/c/calls/clang-O0/prog'.\n"
             'Program terminated with signal SIGTRAP, Trace/breakpoint trap.\n'
             '#0  count (limit=5) at /w/fixtures/session/c/calls/main.c:12\n'
             '12\t    int total = 0;\n'
             '#0  count (limit=5) at /w/fixtures/session/c/calls/main.c:12\n'
             '#1  0x0000000100000408 in main () at /w/fixtures/session/c/calls/main.c:22\n'
             '0x16fdff3a0:\t0x000000016fdff3c0\t0x00000005000003fc\n')
    LLDB = ('(lldb) target create "/w/fx/c/calls/clang-O0/prog" --core "/w/cores/calls-break.core"\n'
            "Core file '/w/cores/calls-break.core' (arm64) was loaded.\n"
            '(lldb) process status\n'
            'Process 0 stopped\n'
            '* thread #1, stop reason = ESR_EC_BRK_AARCH64 (fault address: 0x0)\n'
            '    frame #0: 0x0000000100000388 prog`count(limit=5) at main.c:12:9\n'
            '   9   \t}\n'
            '(lldb) bt\n'
            '* thread #1, stop reason = ESR_EC_BRK_AARCH64 (fault address: 0x0)\n'
            '  * frame #0: 0x0000000100000388 prog`count(limit=5) at main.c:12:9\n'
            '    frame #1: 0x0000000100000408 prog`main at main.c:22:13\n'
            '    frame #2: 0x000000018ce4bda4 dyld`start + 6992\n'
            '(lldb) memory read -s8 -fx -c2 $sp\n'
            '0x16fdff3a0: 0x000000016fdff3c0 0x00000005000003fc\n')
    WANT = [('died', 'SIGTRAP'), ('frame', 0, 'count', 'main.c', 12), ('frame', 1, 'main', 'main.c', 22),
            ('mem', 0x16fdff3a0, [0x16fdff3c0, 0x5000003fc])]

    def test_both_sides_give_the_same_facts(self):
        self.assertEqual(smac.facts_sniff(self.SNIFF), self.WANT)
        self.assertEqual(smac.facts_lldb(self.LLDB), self.WANT)

    def test_a_fault_core(self):
        self.assertEqual(smac.facts_lldb('(lldb) process status\n* thread #1, stop reason = ESR_EC_DABORT_EL0 (fault address: 0x0)\n'),
                         [('died', 'SIGSEGV')])
        # an exception class lldb names that the extraction does not know is no fact, so the row is red, not loosened
        self.assertEqual(smac.facts_lldb('(lldb) process status\n* thread #1, stop reason = ESR_EC_SVC64\n'), [])

    def test_core_forms(self):
        self.assertEqual(smac.core_argv({}, '/c'), ((('-c', '/c'), (), True), (('-c', '/c'), True)))
        self.assertEqual(smac.core_argv({'form': 'positional'}, '/c'), (((), ('/c',), True), (('-c', '/c'), True)))
        self.assertEqual(smac.core_argv({'form': 'dash-c-only'}, '/c'), ((('-c', '/c'), (), False), (('-c', '/c'), False)))
        self.assertTrue(smac.core_file({'core': 'k', 'file': 'missing'}, {}, '/w').endswith('/w/cores/k.missing.core'))
        self.assertEqual(smac.core_file({'core': 'k'}, {'k': Path('/w/cores/k.core')}, '/w'), '/w/cores/k.core')

    def test_the_take_deletes_its_cores(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'cores').mkdir()
            (Path(d) / 'cores' / 'a.core').write_bytes(b'x' * 10)
            self.assertEqual(smac.delete_cores(d), 0)
            self.assertEqual(list((Path(d) / 'cores').glob('*.core')), [])


class MacRefusalDrops(unittest.TestCase):
    """The eight core-gcc-refuse-* rows run on macOS against gdb's Linux goldens: their two drops are exact and
    anchored, applied to both sides alike and counted; a line that merely contains the words stays."""
    GOLD = ['[New LWP <L1>]', "Core was generated by `<SF>/c/calls/gcc-O0/prog'.",
            'Program terminated with signal SIGTRAP, Trace/breakpoint trap.', '#0  count (limit=5) at <FX>/session/c/calls/main.c:12']
    SNIFF = ["Core was generated by `<SF>/c/calls/clang-O0/prog'.",
             'Program terminated with signal SIGTRAP, Trace/breakpoint trap.', '#0  count (limit=5) at <FX>/session/c/calls/main.c:12']
    NEAR = ['x [New LWP <L1>]', '[New LWP <L1>] and more', '[New LWP 4474]', ' [New LWP <L1>]',
            " Core was generated by `p'.", "Core was generated by `p'. and more", "warning: Core was generated by `p'.",
            'Core was generated by p.']

    def rows(self):
        rows = [r for r in json.loads((ROOT / 'tests/macos-rows.json').read_text())['rows'] if r['name'].startswith('core-gcc-refuse-')]
        self.assertEqual(len(rows), 8)
        return rows

    def test_the_two_drops_and_their_counts(self):
        for r in self.rows():
            wl, gl, notes, bad = smac.apply_drops(r['drop'], list(self.GOLD), list(self.SNIFF))
            self.assertEqual((wl, gl, bad), (self.GOLD[2:], self.SNIFF[1:], ''), r['name'])
            self.assertEqual([n.rsplit('(', 1)[1] for n in notes], ['1 golden, 0 sniff)', '1 golden, 1 sniff)'], r['name'])

    def test_a_line_that_merely_contains_the_words_stays(self):
        for r in self.rows():
            for d in r['drop']:
                self.assertTrue(d['match'].startswith('^') and d['match'].endswith('$'), r['name'])
            wl, gl, notes, bad = smac.apply_drops(r['drop'], list(self.NEAR), list(self.NEAR))
            self.assertEqual((wl, gl), (self.NEAR, self.NEAR), r['name'])
            self.assertTrue(all(n.endswith('(0 golden, 0 sniff)') for n in notes), notes)


class MacHungDebugger(unittest.TestCase):
    """A debugger held by a system prompt never answers: each lldb the macOS harness starts is ended by the process
    id it started, its row fails by name, and the take as a whole has a deadline after which no process starts."""

    def standin(self, d, marker=None):
        path = Path(d) / 'lldb'
        path.write_text('#!/bin/sh\n' + ('touch %s\n' % marker if marker else '') + 'exec sleep 600\n')
        path.chmod(0o755)
        return str(path)

    def args(self, d, lldb, **kw):
        import argparse
        a = argparse.Namespace(only='^lldb-core-calls-registers$', work=str(Path(d) / 'w'), fixtures=d, lldb=lldb,
                               lldb_timeout=1, deadline=60, sniff=str(Path(d) / 'sniff'))
        for k, v in kw.items():
            setattr(a, k, v)
        return a

    def test_a_hung_debugger_is_ended_by_its_pid(self):
        with tempfile.TemporaryDirectory() as d:
            start = time.time()
            with self.assertRaises(smac.Hung) as cm:
                smac.lldb_run(self.standin(d), '/no/prog', ['bt'], d, 'r', 1)
            self.assertLess(time.time() - start, 10)
            self.assertIn('did not finish within 1 s', cm.exception.why())
            with self.assertRaises(ProcessLookupError):
                os.kill(cm.exception.pid, 0)

    def test_the_core_and_its_row_fail_by_name(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = smac.cmd_capture(self.args(d, self.standin(d)))
            smac.DEADLINE[0] = None
            out = buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn('FAIL core-calls-break lldb did not finish within 1 s', out)
            self.assertIn('FAIL lldb-core-calls-registers no-core calls-break', out)
            self.assertIn('cores left behind: 0 bytes', out)

    def test_a_crash_in_the_rows_still_deletes_the_cores(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            a = self.args(d, self.standin(d))
            core = Path(a.work) / 'cores' / 'calls-break.core'

            def fake_cores(rows, *rest):
                core.parent.mkdir(parents=True, exist_ok=True)
                core.write_bytes(b'x' * 64)
                return {'calls-break': core}
            keep = smac.make_cores
            smac.make_cores = fake_cores
            try:
                with contextlib.redirect_stdout(io.StringIO()) as buf:
                    with self.assertRaises(OSError):
                        smac.cmd_check(a)
            finally:
                smac.make_cores = keep
                smac.DEADLINE[0] = None
            self.assertFalse(core.exists())
            self.assertIn('cores left behind: 0 bytes', buf.getvalue())

    def test_no_process_starts_after_the_take_deadline(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / 'started'
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = smac.cmd_capture(self.args(d, self.standin(d, marker), deadline=-1))
            smac.DEADLINE[0] = None
            self.assertEqual(rc, 1)
            self.assertIn('take-deadline', buf.getvalue())
            self.assertFalse(marker.exists())


class MacAttachFacts(unittest.TestCase):
    """An attach's own stop is no signal fact, and an attached process's addresses are the system's."""
    ATTACH = ('(lldb) process attach --pid 4242\nProcess 4242 stopped\n'
              "* thread #1, queue = 'com.apple.main-thread', stop reason = signal SIGSTOP\n"
              '    frame #0: 0x000000010083869c prog`nap at main.c:28:5\n')

    def test_attach_stop_is_no_signal(self):
        self.assertEqual(smac.facts_lldb(self.ATTACH), [])
        # a SIGSTOP the program takes after the attach is still one, and another signal at an attach is too
        later = self.ATTACH + '(lldb) continue\nProcess 4242 stopped\n* thread #1, stop reason = signal SIGSTOP\n'
        self.assertEqual(smac.facts_lldb(later), [('signal', 'SIGSTOP')])
        other = self.ATTACH.replace('signal SIGSTOP', 'signal SIGUSR1')
        self.assertEqual(smac.facts_lldb(other), [('signal', 'SIGUSR1')])

    def test_attached_breakpoint_address_is_not_compared(self):
        lldb = [['bpset', 1, 4364338512, 'main.c', 13], ['frame', 0, 'tick', 'main.c', 13]]
        sniff = [['bpset', 1, 4310000000, 'main.c', 13], ['frame', 0, 'tick', 'main.c', 13]]
        attach = {'attach': {'ticks': 100}}
        self.assertEqual(smac.comparable(attach, lldb), smac.comparable(attach, sniff))
        # the file and line still are, and a started program's address still is
        self.assertNotEqual(smac.comparable(attach, lldb), smac.comparable(attach, [['bpset', 1, 4310000000, 'main.c', 14], lldb[1]]))
        self.assertNotEqual(smac.comparable({}, lldb), smac.comparable({}, sniff))


class SleeperBlocked(unittest.TestCase):
    """A debugger is started on the sleeper only once it blocks in its nap: its ready line is written by a
    system call it may not have returned from, and an attach there stops it in write(), not in nap."""

    def states(self, seq):
        calls = []
        def state(pid):
            calls.append(pid)
            return seq[min(len(calls), len(seq)) - 1]
        return state, calls

    def test_waits_for_the_nap(self):
        for mod in (session, smac):
            state, calls = self.states(['R', 'R', 'S'])
            self.assertTrue(mod.wait_blocked('42', state, tries=10, nap=0))
            self.assertEqual(calls, ['42', '42', '42'])
            # bounded: a sleeper that never blocks is given up on, and a system that keeps no state is not waited on
            state, calls = self.states(['R'])
            self.assertFalse(mod.wait_blocked('42', state, tries=5, nap=0))
            self.assertEqual(len(calls), 5)
            state, calls = self.states([''])
            self.assertFalse(mod.wait_blocked('42', state, tries=5, nap=0))
            self.assertEqual(len(calls), 1)

    def test_state_letters(self):
        self.assertEqual(session.status_state('Name:\tprog\nState:\tS (sleeping)\nTgid:\t7\n'), 'S')
        self.assertEqual(session.status_state('State:\tR (running)\n'), 'R')
        self.assertEqual(session.status_state(''), '')
        self.assertEqual(smac.ps_letter('S    \n'), 'S')
        self.assertEqual(smac.ps_letter('R+\n'), 'R')
        self.assertEqual(smac.ps_letter(''), '')

    def test_attach_run_waits_before_the_debugger(self):
        seen = []
        old = session.wait_blocked
        session.wait_blocked = lambda pid, *a, **k: seen.append(pid) or True
        try:
            with tempfile.TemporaryDirectory() as t:
                d = Path(t)
                sleeper = d / 'prog'
                sleeper.write_text('#!%s\nimport os\nprint("ready %%d" %% os.getpid(), flush=True)\n' % sys.executable)
                sleeper.chmod(0o755)
                dbg = d / 'dbg'
                dbg.write_text('#!/bin/sh\nexit 0\n')
                dbg.chmod(0o755)
                old_scripts = session.SCRIPTS
                session.SCRIPTS = 'scripts'
                try:
                    session.attach_run(str(dbg), {'name': 'r', 'script': ['detach'], 'attach': {}}, str(sleeper), str(d), False)
                finally:
                    session.SCRIPTS = old_scripts
        finally:
            session.wait_blocked = old
        self.assertEqual(len(seen), 1)
        self.assertRegex(seen[0], r'^\d+$')


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


class SharedGoldens(unittest.TestCase):
    """A row held to another row's golden ("golden_of"): sniff's bare `info registers` against the named form."""

    def test_golden_paths_follow_golden_of(self):
        self.assertEqual(session.golden_paths({'name': 'b', 'golden_of': 'a'}), session.golden_paths({'name': 'a'}))

    def test_golden_of_problems(self):
        rows = [{'name': 'a'}, {'name': 'b', 'golden_of': 'a'}]
        self.assertEqual(session.golden_of_problems(rows), [])
        self.assertTrue(session.golden_of_problems(rows + [{'name': 'c', 'golden_of': 'nowhere'}]))
        self.assertTrue(session.golden_of_problems(rows + [{'name': 'c', 'golden_of': 'b'}]))  # no chains
        self.assertTrue(session.golden_of_problems(rows + [{'name': 'c', 'golden_of': 'c'}]))
        self.assertTrue(session.golden_of_problems([{'name': 'a', 'skip': 'x'}, {'name': 'b', 'golden_of': 'a'}]))
        self.assertTrue(session.golden_of_problems(rows + [{'name': 'c', 'golden_of': 'a', 'tty': True}]))

    def test_the_bare_registers_row(self):
        rows = {r['name']: r for r in session.load_rows()}
        bare, named = rows['value-gcc-registers-bare'], rows['value-gcc-registers']
        self.assertEqual(bare['golden_of'], 'value-gcc-registers')
        self.assertEqual(bare['prog'], named['prog'])
        self.assertEqual(bare['script'], named['script'][:-1] + ['info registers'])
        self.assertTrue(named['script'][-1].startswith('info registers rax '))


class PaxGaps(unittest.TestCase):
    """A PAX-set row skipped for a gap in PAX names the probe that witnesses the gap; one skipped for the harness's
    own limit says so. A skip blaming PAX stands only while PAX answers its probe differently from Linux."""

    def test_skip_problems(self):
        probes = {'dr': 'tests/pax-probe/dr.c'}
        self.assertEqual(session.skip_problems([{'name': 'r', 'skip': 'x', 'gap': 'dr'}], probes), [])
        self.assertEqual(session.skip_problems([{'name': 'r', 'skip': 'x', 'gap': 'harness'}], probes), [])
        self.assertEqual(session.skip_problems([{'name': 'r'}], probes), [])
        self.assertTrue(session.skip_problems([{'name': 'r', 'skip': 'x'}], probes))
        self.assertTrue(session.skip_problems([{'name': 'r', 'skip': 'x', 'gap': 'maps'}], probes))
        self.assertTrue(session.skip_problems([{'name': 'r', 'gap': 'dr'}], probes))  # a gap without a skip

    def test_every_pax_skip_names_its_gap(self):
        old = (session.GOLD, session.PAX_MODE)
        try:
            session.use_pax()
            self.assertEqual(session.skip_problems(session.load_rows(), session.load_probes()), [])
            for name, src in session.load_probes().items():
                self.assertTrue((ROOT / src).is_file(), name)
        finally:
            session.GOLD, session.PAX_MODE = old

    def test_probe_goldens_are_pax_set_files(self):
        self.assertEqual([p.name for p in session.probe_golden_paths('dr')], ['probe-dr.out', 'probe-dr.rc'])
        self.assertTrue(all(p.parent == session.PAX_GOLD for p in session.probe_golden_paths('dr')))


# a stand-in gdb for make_cores: it writes the file its `gcore PATH` names, or nothing when told to fail
FAKE_GCORE = '''#!/usr/bin/env python3
import sys
from pathlib import Path
args = sys.argv[1:]
cmds = [args[i + 1] for i, x in enumerate(args) if x == '-ex']
log = Path(sys.argv[0]).parent / 'calls'
with open(log, 'a') as f:
    f.write(' '.join(cmds) + '\\n')
if 'fail' in cmds:
    sys.stderr.write('The program is not being run.\\n')
    sys.exit(1)
path = [c for c in cmds if c.startswith('gcore ')][0][6:]
Path(path).write_bytes(b'\\x7fELF' + bytes(8188))
'''


class CoreRows(unittest.TestCase):
    """Rows over a core file: the cores table, the forms a debugger is given a core in, and the cores each take
    writes with gdb's gcore before the rows that read them."""

    TABLE = {'calls-break': {'prog': 'c/calls/gcc-O0/prog', 'stop': ['break count', 'run']},
             'exits-segv': {'prog': 'c/exits/gcc-O0/prog', 'args': ['fault'], 'stop': ['run']}}

    def row(self, **kw):
        r = {'name': 'core-x', 'prog': 'c/calls/gcc-O0/prog', 'script': ['bt'], 'core': {'of': 'calls-break'}}
        r.update(kw)
        return r

    def test_forms(self):
        fx = '/work/target/session-fixtures'
        core = '/work/target/cores/s2/calls-break.core'
        prog = fx + '/c/calls/gcc-O0/prog'
        self.assertEqual(session.core_tail(self.row(), prog, fx), [prog, core])
        self.assertEqual(session.core_tail(self.row(core={'of': 'calls-break', 'form': 'dash-c'}), prog, fx),
                         ['-c', core, prog])
        self.assertEqual(session.core_tail(self.row(core={'of': 'calls-break', 'form': 'dash-c-only'}), prog, fx),
                         ['-c', core])
        self.assertEqual(session.core_tail(self.row(core={'of': 'calls-break', 'form': 'script'}), prog, fx), [prog])
        r = self.row(core={'of': 'calls-break', 'file': 'truncated'})
        self.assertEqual(session.core_path(r, fx), '/work/target/cores/s2/calls-break.truncated.core')
        self.assertEqual(session.core_path(self.row(core={'of': 'calls-break', 'file': 'missing'}), fx),
                         '/work/target/cores/s2/calls-break.missing.core')
        g = session.gdb_argv('gdb', self.row(), 'S', prog, fx)
        self.assertEqual(g[-3:], ['S', prog, core])
        self.assertNotIn('--args', g)
        self.assertEqual(session.sniff_argv('sniff', self.row(), 'S', prog, fx), ['sniff', '-batch', '-x', 'S', prog, core])
        # a row without a core is as it was
        self.assertEqual(session.sniff_argv('sniff', {'args': ['3']}, 'S', 'P'), ['sniff', '-batch', '-x', 'S', 'P', '--args', '3'])

    def test_pax_cores_are_their_own(self):
        old = (session.GOLD, session.PAX_MODE)
        try:
            session.use_pax()
            self.assertEqual(session.cores_dir('/work/target/pax-fixtures'), Path('/work/target/cores/pax'))
        finally:
            session.GOLD, session.PAX_MODE = old

    def test_script_form_names_the_core(self):
        r = self.row(core={'of': 'calls-break', 'form': 'script'}, script=['core-file {core}', 'bt'])
        s = session.core_script(r, '/f/session-fixtures')
        self.assertEqual(s['script'], ['core-file /f/cores/s2/calls-break.core', 'bt'])
        self.assertEqual(r['script'][0], 'core-file {core}')
        plain = {'name': 'n', 'script': ['run']}
        self.assertIs(session.core_script(plain, '/f'), plain)

    def test_gcore_argv(self):
        a = session.gcore_argv('gdb', self.TABLE['exits-segv'], 'P', '/c/x.core')
        self.assertEqual(a[-7:], ['-ex', 'run', '-ex', 'gcore /c/x.core', '--args', 'P', 'fault'])
        self.assertEqual(a[:2], ['gdb', '-nx'])

    def test_core_problems(self):
        ok = [self.row(), self.row(name='core-y', prog='c/exits/gcc-O0/prog', core={'of': 'exits-segv', 'form': 'dash-c'})]
        self.assertEqual(session.core_problems(ok, self.TABLE), [])
        bad = {
            'no such core': self.row(core={'of': 'nowhere'}),
            'form': self.row(core={'of': 'calls-break', 'form': 'sideways'}),
            'file': self.row(core={'of': 'calls-break', 'file': 'gone'}),
            'args': self.row(args=['3']),
            'tty': self.row(tty=True),
            'script form without {core}': self.row(core={'of': 'calls-break', 'form': 'script'}),
            '{core} in another form': self.row(script=['core-file {core}']),
            'another program unsaid': self.row(prog='c/exits/gcc-O0/prog'),
            'other_program said of its own': self.row(core={'of': 'calls-break', 'other_program': True}),
        }
        for why, r in bad.items():
            self.assertTrue(session.core_problems([r, ok[1]], self.TABLE), why)
        said = self.row(prog='c/exits/gcc-O0/prog', core={'of': 'calls-break', 'other_program': True})
        self.assertEqual(session.core_problems([said, ok[1]], self.TABLE), [])
        # a core no row reads, and a table entry without its stop
        self.assertTrue(session.core_problems([ok[0]], self.TABLE))
        self.assertTrue(session.core_problems(ok, dict(self.TABLE, **{'calls-break': {'prog': 'c/calls/gcc-O0/prog', 'stop': []}})))

    def test_make_cores(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            gdb = d / 'gdb'
            gdb.write_text(FAKE_GCORE)
            gdb.chmod(0o755)
            fx = d / 'target/session-fixtures'
            for c in self.TABLE.values():
                (fx / c['prog']).parent.mkdir(parents=True, exist_ok=True)
                (fx / c['prog']).write_text('prog')
            rows_file = d / 'rows.json'
            table = dict(self.TABLE, broken={'prog': 'c/calls/gcc-O0/prog', 'stop': ['fail']})
            rows_file.write_text(json.dumps({'rows': [], 'cores': table}))
            old = session.ROWS
            session.ROWS = rows_file
            rows = [self.row(), self.row(name='t', core={'of': 'calls-break', 'file': 'truncated'}),
                    self.row(name='m', core={'of': 'calls-break', 'file': 'missing'}),
                    self.row(name='b', core={'of': 'broken'})]
            import io
            from contextlib import redirect_stdout
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    bad = session.make_cores(rows, str(gdb), str(fx), str(d))
                cores = d / 'target/cores/s2'
                self.assertEqual(bad, {'broken'})
                self.assertIn('CORE calls-break bytes=8192', buf.getvalue())
                self.assertIn('FAIL core-broken gcore exit=1 The program is not being run.', buf.getvalue())
                self.assertEqual((cores / 'calls-break.truncated.core').stat().st_size, 4096)
                self.assertFalse((cores / 'calls-break.missing.core').exists())
                self.assertFalse((cores / 'broken.core').exists())
                self.assertFalse(any(p.suffix == '.part' for p in cores.iterdir()))
                self.assertNotIn('exits-segv', buf.getvalue())  # no row reads it
                # a core this take wrote is not written again; one older than its program is
                calls = (d / 'calls').read_text().splitlines()
                with redirect_stdout(io.StringIO()):
                    session.make_cores(rows[:1], str(gdb), str(fx), str(d))
                self.assertEqual(len((d / 'calls').read_text().splitlines()), len(calls))
                os.utime(cores / 'calls-break.core', (1, 1))
                with redirect_stdout(io.StringIO()):
                    session.make_cores(rows[:1], str(gdb), str(fx), str(d))
                self.assertEqual(len((d / 'calls').read_text().splitlines()), len(calls) + 1)
            finally:
                session.ROWS = old

    def test_registers_from_a_core_are_the_live_ones(self):
        # gdb prints the same 26 register lines at a live stop and from the core gcore wrote there
        reg = __import__('re').compile(r'^(r[a-z0-9]+|eflags|[cdefgs]s|fs_base|gs_base)\s')
        for gold in (session.GOLD, session.PAX_GOLD):
            live = [x for x in (gold / 'value-gcc-registers.out').read_text().splitlines() if reg.match(x)]
            core = [x for x in (gold / 'core-gcc-registers.out').read_text().splitlines() if reg.match(x)]
            self.assertEqual(len(core), 26, gold)
            if gold == session.GOLD:
                self.assertEqual(core, live)

    def test_the_core_rows_cover_each_form_and_file(self):
        rows = [r for r in session.load_rows() if r.get('core')]
        forms = {r['core'].get('form', 'positional') for r in rows}
        self.assertEqual(forms, set(session.CORE_FORMS))
        self.assertEqual({r['core'].get('file') for r in rows} - {None}, set(session.CORE_FILES))
        self.assertTrue(any(r['core'].get('other_program') for r in rows))
        self.assertEqual(session.core_problems(session.load_rows(), session.load_cores()), [])

    def test_readelf_nt_file_rule(self):
        # the notes rows take readelf's declined NT_FILE phrase off and say so; a decoded NT_FILE stays as it is
        spec = importlib.util.spec_from_file_location('dump_matrix', ROOT / 'tools/dump-matrix.py')
        dm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dm)
        line = b'  CORE                 0x00000411\tNT_FILE (mapped files)\t'
        text = b'\nDisplaying notes\n' + line + dm.NT_DECLINED + b'\n  CORE  0x1\tNT_AUXV (auxiliary vector)\t\n'
        got, state = dm.nt_file_rule(text)
        self.assertEqual(state, 'declined')
        self.assertEqual(got, b'\nDisplaying notes\n' + line + b'\n  CORE  0x1\tNT_AUXV (auxiliary vector)\t\n')
        decoded = line + b'    Page size: 4096\n'
        self.assertEqual(dm.nt_file_rule(decoded), (decoded, 'decoded'))
        self.assertEqual(dm.nt_file_rule(text + decoded)[1], 'decoded')
        self.assertEqual(dm.nt_file_rule(b'no notes\n'), (b'no notes\n', 'none'))

    def test_check_names_a_core_not_made(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            gdb = d / 'gdb'
            gdb.write_text(FAKE_GCORE)
            gdb.chmod(0o755)
            rows_file = d / 'rows.json'
            rows_file.write_text(json.dumps({'rows': [self.row(name='inferior-c-gcc-exit0', core={'of': 'broken'})],
                                             'cores': {'broken': {'prog': 'c/calls/gcc-O0/prog', 'stop': ['fail']}}}))
            old = (session.ROWS, session.GOLD)
            session.ROWS, session.GOLD = rows_file, ROOT / 'tests/evidence/linux-s2'
            import io
            from contextlib import redirect_stdout
            try:
                args = type('A', (), {'work': str(d), 'fixtures': str(d / 'target/session-fixtures'), 'only': None,
                                      'sniff': '/nonexistent', 'gdb': str(gdb)})()
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = session.cmd_check(args)
                self.assertEqual(rc, 1)
                self.assertIn('FAIL inferior-c-gcc-exit0 no-core broken', buf.getvalue())
            finally:
                session.ROWS, session.GOLD = old


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
    # unittest's own report, then one `FAIL NAME` line at column 0 per failing test, so a gate or record names it
    result = unittest.main(exit=False).result
    for case, _ in result.failures + result.errors:
        print('FAIL ' + case.id().split('.')[-1], flush=True)
    sys.exit(0 if result.wasSuccessful() else 1)
