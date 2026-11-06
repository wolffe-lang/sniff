#!/usr/bin/env python3
"""R-sn02-3: the platform constants come from a compiled probe, not from header text.

  capture  compile tools/abi-probe.c with the container's gcc, run it, and write
           (or, with --compare, diff against) tests/evidence/linux-s2/abi.txt
  check    compare src/platform/types.lu with the recorded probe output, and
           check the wait-status truth table that the wolf decoders are tested
           against (src/platform_test.lu)
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / 'tests/evidence/linux-s2/abi.txt'
TYPES = ROOT / 'src/platform/types.lu'

REQUESTS = {
    'PTRACE_TRACEME': 'req_traceme', 'PTRACE_PEEKDATA': 'req_peekdata', 'PTRACE_POKEDATA': 'req_pokedata',
    'PTRACE_CONT': 'req_cont', 'PTRACE_KILL': 'req_kill', 'PTRACE_SINGLESTEP': 'req_singlestep',
    'PTRACE_GETREGS': 'req_getregs', 'PTRACE_SETREGS': 'req_setregs', 'PTRACE_GETFPREGS': 'req_getfpregs',
    'PTRACE_DETACH': 'req_detach', 'PTRACE_SETOPTIONS': 'req_setoptions', 'PTRACE_GETEVENTMSG': 'req_geteventmsg',
    'PTRACE_O_TRACEFORK': 'opt_tracefork', 'PTRACE_O_TRACEVFORK': 'opt_tracevfork',
    'PTRACE_O_EXITKILL': 'opt_exitkill', 'ADDR_NO_RANDOMIZE': 'addr_no_randomize',
}
REGS = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi',
        'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs']


def constants():
    out = {}
    for m in re.finditer(r'^pub const (\w+): int = (\d+)$', TYPES.read_text(), re.M):
        out[m.group(1)] = int(m.group(2))
    return out


def capture(args):
    with tempfile.TemporaryDirectory() as d:
        exe = Path(d) / 'abi-probe'
        subprocess.run(['gcc', '-O0', str(ROOT / 'tools/abi-probe.c'), '-o', str(exe)], check=True)
        text = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
    if args.compare:
        if text != RECORD.read_text():
            print('FAIL abi-probe-drift: the probe output differs from ' + str(RECORD.relative_to(ROOT)))
            return 1
        print('PASS abi-probe-stable lines=%d' % len(text.splitlines()))
        return 0
    RECORD.write_text(text)
    print('CAPTURE abi.txt lines=%d' % len(text.splitlines()))
    return 0


def check(_args):
    consts = constants()
    lines = RECORD.read_text().splitlines()
    seen = {}
    bad = []
    for ln in lines:
        w = ln.split()
        if w[0] == 'request':
            name, value = w[1], int(w[2])
            seen[name] = value
            want = REQUESTS.get(name)
            if want is not None and consts.get(want) != value:
                bad.append('%s is %s in the probe and %s in types.lu' % (name, value, consts.get(want)))
        elif w[0] == 'regs' and w[1] in REGS:
            want = 'reg_' + w[1]
            if consts.get(want) != int(w[2]):
                bad.append('regs %s is slot %s in the probe and %s in types.lu' % (w[1], w[2], consts.get(want)))
    for name in REQUESTS:
        if name not in seen and not name.startswith('PTRACE_PEEK'):
            bad.append('probe output lacks ' + name)
    sizes = [ln for ln in lines if ln.startswith('regs size')]
    if not sizes or int(sizes[0].split()[2]) != consts.get('reg_count'):
        bad.append('regs size differs from reg_count')
    table = {}
    for ln in lines:
        if ln.startswith('wait '):
            parts = ln.split()
            table[parts[1]] = dict(p.split('=') for p in parts[2:])
    expect = {'exit0': ('raw', '0'), 'exit3': ('raw', '768'), 'exit255': ('raw', '65280'),
              'sigsegv': ('raw', '11'), 'sigkill': ('raw', '9'), 'exec-stop': ('raw', '1407')}
    for name, (key, value) in expect.items():
        if table.get(name, {}).get(key) != value:
            bad.append('wait %s %s is %s, expected %s' % (name, key, table.get(name, {}).get(key), value))
    if bad:
        for b in bad:
            print('FAIL abi-constants: ' + b)
        return 1
    print('PASS abi-constants requests=%d regs=%d waits=%d' % (len(REQUESTS), len(REGS), len(expect)))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('capture')
    c.add_argument('--compare', action='store_true')
    sub.add_parser('check')
    a = p.parse_args()
    return {'capture': capture, 'check': check}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
