#!/usr/bin/env python3
"""R-sn02-3: the platform constants come from a compiled probe, not from header text.

  capture  compile tools/abi-probe.c with the container's gcc, run it, and write
           (or, with --compare, diff against) tests/evidence/linux-s2/abi.txt;
           with --platform macos, compile tools/abi-probe-macos.c with the SDK's
           clang for arm64 and write tests/evidence/macos-s3/abi.txt
  check    compare src/platform/types.lu and the core readers' constants with the
           recorded probe outputs, and check the wait-status truth table that the
           wolf decoders are tested against (src/platform_test.lu)
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
CORE_READER = ROOT / 'src/readers/core.lu'
MACOS_RECORD = ROOT / 'tests/evidence/macos-s3/abi.txt'
MACHO_CORE_READER = ROOT / 'src/readers/macho_core.lu'

REQUESTS = {
    'PTRACE_TRACEME': 'req_traceme', 'PTRACE_PEEKDATA': 'req_peekdata', 'PTRACE_POKEDATA': 'req_pokedata',
    'PTRACE_CONT': 'req_cont', 'PTRACE_KILL': 'req_kill', 'PTRACE_SINGLESTEP': 'req_singlestep',
    'PTRACE_GETREGS': 'req_getregs', 'PTRACE_SETREGS': 'req_setregs', 'PTRACE_GETFPREGS': 'req_getfpregs',
    'PTRACE_DETACH': 'req_detach', 'PTRACE_SETOPTIONS': 'req_setoptions', 'PTRACE_GETEVENTMSG': 'req_geteventmsg',
    'PTRACE_O_TRACEFORK': 'opt_tracefork', 'PTRACE_O_TRACEVFORK': 'opt_tracevfork',
    'PTRACE_O_EXITKILL': 'opt_exitkill', 'ADDR_NO_RANDOMIZE': 'addr_no_randomize',
    'PTRACE_PEEKUSER': 'req_peekuser', 'PTRACE_POKEUSER': 'req_pokeuser',
    'PTRACE_O_TRACECLONE': 'opt_traceclone', 'PTRACE_EVENT_CLONE': 'event_clone', 'PTRACE_ATTACH': 'req_attach',
    'PTRACE_GETSIGINFO': 'req_getsiginfo', 'PTRACE_SEIZE': 'req_seize', 'PTRACE_INTERRUPT': 'req_interrupt',
    'PTRACE_EVENT_STOP': 'event_stop', '__WALL': 'wait_all', 'SYS_tgkill': 'sys_tgkill',
}
# siginfo_t (S6's signal stops): its size and the byte offsets of the fields read through PTRACE_GETSIGINFO
SIGINFO = {'size': 'siginfo_size', 'si_signo': 'siginfo_signo', 'si_code': 'siginfo_code', 'si_pid': 'siginfo_pid',
           'si_addr': 'siginfo_addr'}
# struct user fields the probe measures (S5's debug registers), byte offsets and sizes
USER = {'u_debugreg': 'user_debugreg_offset', 'u_debugreg_size': 'user_debugreg_size'}
# the core reader's descriptor layouts (S7): probe name -> core_NAME in src/readers/core.lu
CORE = ['prstatus_size', 'prstatus_cursig', 'prstatus_pid', 'prstatus_reg', 'prstatus_reg_size', 'prpsinfo_size',
        'prpsinfo_pid', 'prpsinfo_fname', 'prpsinfo_fname_size', 'prpsinfo_psargs', 'prpsinfo_psargs_size',
        'fpregset_size']
# the Mach-O core reader's layouts (S7, macOS): probe name -> macho_core_NAME in src/readers/macho_core.lu
MACHCORE = ['mh_magic_64', 'mh_core', 'cpu_type_arm64', 'header_size', 'header_cputype', 'header_cpusubtype',
            'header_filetype', 'header_ncmds', 'header_sizeofcmds', 'lc_segment_64', 'lc_thread', 'lc_note',
            'segment_size', 'segment_vmaddr', 'segment_vmsize', 'segment_fileoff', 'segment_filesize',
            'segment_initprot', 'note_size', 'note_owner', 'note_owner_size', 'note_offset', 'note_payload_size',
            'thread_state64', 'thread_state64_count', 'exception_state64', 'exception_state64_count', 'state_fp',
            'state_lr', 'state_sp', 'state_pc', 'state_cpsr', 'exception_far', 'exception_esr',
            'exception_exception']
REGS = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi',
        'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs']


def constants():
    out = {}
    for path in (TYPES, CORE_READER, MACHO_CORE_READER):
        for m in re.finditer(r'^pub const (\w+): int = (\d+)$', path.read_text(), re.M):
            out[m.group(1)] = int(m.group(2))
    return out


def capture(args):
    macos = args.platform == 'macos'
    record = MACOS_RECORD if macos else RECORD
    with tempfile.TemporaryDirectory() as d:
        exe = Path(d) / 'abi-probe'
        if macos:
            build = ['xcrun', 'clang', '-arch', 'arm64', '-O0', str(ROOT / 'tools/abi-probe-macos.c'), '-o', str(exe)]
        else:
            build = ['gcc', '-O0', str(ROOT / 'tools/abi-probe.c'), '-o', str(exe)]
        subprocess.run(build, check=True)
        text = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
    if args.compare:
        if text != record.read_text():
            print('FAIL abi-probe-drift: the probe output differs from ' + str(record.relative_to(ROOT)))
            return 1
        print('PASS abi-probe-stable platform=%s lines=%d' % (args.platform, len(text.splitlines())))
        return 0
    record.write_text(text)
    print('CAPTURE %s lines=%d' % (record.relative_to(ROOT), len(text.splitlines())))
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
        elif w[0] == 'user' and w[1] in USER:
            seen[w[1]] = int(w[2])
            if consts.get(USER[w[1]]) != int(w[2]):
                bad.append('user %s is %s in the probe and %s in types.lu' % (w[1], w[2], consts.get(USER[w[1]])))
        elif w[0] == 'siginfo' and w[1] in SIGINFO:
            seen['siginfo ' + w[1]] = int(w[2])
            if consts.get(SIGINFO[w[1]]) != int(w[2]):
                bad.append('siginfo %s is %s in the probe and %s in types.lu' % (w[1], w[2], consts.get(SIGINFO[w[1]])))
        elif w[0] == 'core' and w[1] in CORE:
            seen['core ' + w[1]] = int(w[2])
            if consts.get('core_' + w[1]) != int(w[2]):
                bad.append('core %s is %s in the probe and %s in core.lu' % (w[1], w[2], consts.get('core_' + w[1])))
        elif w[0] == 'regs' and w[1] in REGS:
            want = 'reg_' + w[1]
            if consts.get(want) != int(w[2]):
                bad.append('regs %s is slot %s in the probe and %s in types.lu' % (w[1], w[2], consts.get(want)))
    for name in REQUESTS:
        if name not in seen and not name.startswith('PTRACE_PEEK'):
            bad.append('probe output lacks ' + name)
    for name in USER:
        if name not in seen:
            bad.append('probe output lacks user ' + name)
    for name in SIGINFO:
        if 'siginfo ' + name not in seen:
            bad.append('probe output lacks siginfo ' + name)
    for name in CORE:
        if 'core ' + name not in seen:
            bad.append('probe output lacks core ' + name)
    machcore = {}
    for ln in MACOS_RECORD.read_text().splitlines():
        w = ln.split()
        if len(w) == 3 and w[0] == 'machcore' and w[1] in MACHCORE:
            machcore[w[1]] = int(w[2])
            if consts.get('macho_core_' + w[1]) != int(w[2]):
                bad.append('machcore %s is %s in the probe and %s in macho_core.lu' % (w[1], w[2], consts.get('macho_core_' + w[1])))
    for name in MACHCORE:
        if name not in machcore:
            bad.append('macOS probe output lacks machcore ' + name)
    if consts.get('core_prstatus_reg_size') != 8 * consts.get('reg_count', 0):
        bad.append("core.lu's pr_reg is not reg_count eight-byte words")
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
    print('PASS abi-constants requests=%d regs=%d user=%d siginfo=%d core=%d machcore=%d waits=%d' % (len(REQUESTS), len(REGS), len(USER), len(SIGINFO), len(CORE), len(MACHCORE), len(expect)))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('capture')
    c.add_argument('--compare', action='store_true')
    c.add_argument('--platform', choices=['linux', 'macos'], default='linux')
    sub.add_parser('check')
    a = p.parse_args()
    return {'capture': capture, 'check': check}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
