#!/usr/bin/env python3
"""S4: the S2 session on PAX, held to the Linux transcript.

sniff runs on PAX's console under KVM, as a static program of the dev image,
and debugs static fixtures with PAX's ptrace(2). Each boot is one image: the
kernel, pelt as init, a few boreutils, sniff, the fixtures a group of rows
needs and, at the paths their line tables name, the fixtures' sources. The
group's one typed command line runs every row: sniff -batch -x SCRIPT PROG,
its standard output, standard error and exit status between markers on the
console. This harness splits the console by marker and compares every row with
the golden the pinned gdb gave the same static build on Linux
(tests/evidence/pax-linux), after tools/session.py's normalisations and the
row's named drops (tests/pax-rows.json). A row that did not run is SKIP by
name and never a pass.

  session-pax.py run --pax PAXTREE --kernel ELF --inputs DIR --sniff BIN
                     --fixtures DIR --out DIR [--only RE] [--timeout S]
  session-pax.py tty --pax PAXTREE ...      the terminal rows, typed key by key
  session-pax.py selftest                   the marker splitter, no machine
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BEGIN, RC, OUT, ERR, END = '@@BEGIN ', '@@RC ', '@@OUT', '@@ERR', '@@END'
MAX_CHUNK_BYTES = 70_000_000


def load_session():
    spec = importlib.util.spec_from_file_location('session_rows', ROOT / 'tools/session.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.use_pax()
    return mod


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def serial_norm(text):
    """lib.sh's serial_norm: carriage returns and terminal escapes removed."""
    text = re.sub(r'\x1b\[[0-9;?=<>]*[A-Za-z]', '', text)
    text = re.sub(r'\x1b[()][A-Za-z0-9]', '', text)
    text = re.sub(r'\x1b[c78DEHM=>]', '', text)
    text = text.replace('\r', '')
    # the kernel's own console line for a program that a signal killed (it prints even when quiet):
    # a fact about the machine, not debugger output, and on a line of its own
    return re.sub(r'(?m)^user: [^\n]*\n', '', text)


def guest_script(rows, scripts_dir, fx_guest):
    """The text of /etc/rows.sh: one block per row; markers on lines of their own."""
    lines = []
    for row in rows:
        args = ''
        if row.get('args'):
            args = ' --args ' + ' '.join(row['args'])
        prog = fx_guest + '/' + row['prog']
        lines.append("printf '%s\\n' '" + BEGIN + row['name'] + "'")
        lines.append('/bin/sniff -batch -x %s/%s.cmd %s%s > /tmp/o 2> /tmp/e' % (scripts_dir, row['name'], prog, args))
        lines.append("printf '%s\\n' \"" + RC + "$?\"")
        lines.append("printf '%s\\n' '" + OUT + "'")
        lines.append('cat /tmp/o')
        lines.append("printf '\\n%s\\n' '" + ERR + "'")
        lines.append('cat /tmp/e')
        lines.append("printf '\\n%s\\n' '" + END + "'")
    return '\n'.join(lines) + '\n'


def split_console(text):
    """name -> (rc, out, err) for every row whose BEGIN..END is complete."""
    got = {}
    cur = None
    state = None
    out, err, rc = [], [], None
    for line in serial_norm(text).split('\n'):
        if line.startswith(BEGIN):
            cur, state, out, err, rc = line[len(BEGIN):].strip(), 'head', [], [], None
        elif cur is None:
            continue
        elif state == 'head' and line.startswith(RC):
            rc = line[len(RC):].strip()
        elif line == OUT and state == 'head':
            state = 'out'
        elif line == ERR and state == 'out':
            state = 'err'
        elif line == END and state == 'err':
            # the guest printed a newline before each marker: joining the lines keeps exactly the file's bytes
            got[cur] = (rc, '\n'.join(out), '\n'.join(err))
            cur, state = None, None
        elif state == 'out':
            out.append(line)
        elif state == 'err':
            err.append(line)
    return got


def chunk_rows(rows, fixtures):
    """Rows in groups whose distinct programs fit one image."""
    chunks, cur, progs, size = [], [], set(), 0
    for row in rows:
        p = row['prog']
        extra = 0 if p in progs else (Path(fixtures) / p).stat().st_size
        if cur and size + extra > MAX_CHUNK_BYTES:
            chunks.append(cur)
            cur, progs, size = [], set(), 0
            extra = (Path(fixtures) / p).stat().st_size
        cur.append(row)
        if p not in progs:
            progs.add(p)
            size += extra
    if cur:
        chunks.append(cur)
    return chunks


def sources_for(rows):
    """Source files the rows' programs were built from, at the absolute paths their DWARF names."""
    seen = {}
    for row in rows:
        parts = row['prog'].split('/')
        if parts[0] == 'c':
            d = ROOT / 'fixtures/session/c' / parts[1]
            for f in sorted(d.glob('*.c')):
                seen['/work/fixtures/session/c/%s/%s' % (parts[1], f.name)] = f
        else:
            name = parts[1]
            for base in ('fixtures/session/wolf', 'fixtures/wolf'):
                d = ROOT / base / name
                if (d / 'main.lu').exists():
                    for f in sorted(d.glob('*.lu')):
                        seen['/work/%s/%s/%s' % (base, name, f.name)] = f
    return seen


def run(cmd, **kw):
    print('RUN ' + ' '.join(map(str, cmd)), flush=True)
    return subprocess.run([str(c) for c in cmd], **kw)


def boot(pax, kernel, iso, serial, keys, timeout, mem, leg='bios'):
    cmd = [pax / 'tools/qemu-halt', '--firmware', leg, '--serial', serial, '--timeout', str(timeout),
           '--qemu', '-m', '--qemu', mem, '--elf', kernel, '--marker', 'halt|PANIC .*',
           '--type', keys, '--prompt', '$ ', iso]
    r = run(cmd, capture_output=True, text=True)
    Path(str(serial) + '.verdict').write_text(r.stdout + r.stderr)
    return r.returncode


def build_image(pax, kernel, inputs, sniff, fixtures, rows, work, label):
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    files = [('/bin/sh', inputs / 'pelt/pelt', 755), ('/bin/sniff', sniff, 755)]
    for tool in ('cat', 'env'):
        files.append(('/bin/' + tool, inputs / 'bore' / tool, 755))
    scripts = work / 'cmds'
    scripts.mkdir(exist_ok=True)
    sess = load_session()
    for row in rows:
        f = scripts / (row['name'] + '.cmd')
        f.write_text('\n'.join(row['script']) + '\n')
        files.append(('/work/target/s2/%s.cmd' % row['name'], f, 644))
    for prog in sorted({r['prog'] for r in rows}):
        files.append(('/work/target/pax-fixtures/' + prog, Path(fixtures) / prog, 755))
    for dest, src in sources_for(rows).items():
        files.append((dest, src, 644))
    rows_sh = work / 'rows.sh'
    rows_sh.write_text(guest_script(rows, '/work/target/s2', '/work/target/pax-fixtures'))
    files.append(('/etc/rows.sh', rows_sh, 644))
    run_line = work / 'pax-run'
    run_line.write_text('/bin/env HOME=/ /bin/sh -i\n')
    files.append(('/etc/pax-run', run_line, 644))
    args = ['/tmp/:1777'] + ['%s=%s:%s' % (d, s, m) for d, s, m in files]
    cpio = work / (label + '.cpio')
    r = run([pax / 'tools/mkinitramfs', cpio] + args, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:])
        raise SystemExit('FAIL session-pax-image mkinitramfs')
    iso = work / (label + '.iso')
    r = run([pax / 'tools/mkimage', '--conf', pax / 'boot/limine-initramfs-quiet.conf', '--add', cpio, 'initramfs.cpio', kernel, iso],
            capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:])
        raise SystemExit('FAIL session-pax-image mkimage')
    keys = work / (label + '.keys')
    keys.write_text('/bin/sh /etc/rows.sh\nexit\n')
    return iso, keys, sess


def compare(sess, rows, got):
    fails = ran = 0
    for row in rows:
        gold = sess.golden_paths(row)
        if row['name'] not in got:
            print('FAIL %s no-result: the console shows no complete block for this row' % row['name'])
            fails += 1
            continue
        rc, out, err = got[row['name']]
        ran += 1
        fired = set()
        o, e = sess.normalize(out, fired, row), sess.normalize(err, fired, row)
        want_o, want_e, want_rc = (p.read_text() for p in gold)
        bad = []
        if o != want_o:
            bad.append('stdout ' + sess.first_diff(want_o, o))
        if e != want_e:
            bad.append('stderr ' + sess.first_diff(want_e, e))
        if str(rc) != want_rc.strip():
            bad.append('exit want %s got %s' % (want_rc.strip(), rc))
        if bad:
            print('FAIL %s %s' % (row['name'], '; '.join(bad)))
            fails += 1
        else:
            print('PASS %s%s' % (row['name'], (' [normalised: ' + ','.join(sorted(fired)) + ']') if fired else ''))
    return ran, fails


def cmd_run(a):
    sess = load_session()
    rows = [r for r in sess.load_rows(a.only) if not r.get('tty')]
    skipped = [r for r in rows if r.get('skip')]
    for r in skipped:
        print('SKIP %s reason=%s' % (r['name'], r['skip']))
    rows = [r for r in rows if not r.get('skip')]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pax = Path(a.pax)
    kernel = Path(a.kernel)
    print('KERNEL sha256=%s' % sha(kernel))
    print('SNIFF sha256=%s' % sha(a.sniff))
    total_ran = total_fail = 0
    for i, chunk in enumerate(chunk_rows(rows, a.fixtures)):
        label = 'boot%02d' % i
        iso, keys, _ = build_image(pax, kernel, Path(a.inputs), a.sniff, a.fixtures, chunk, out / label, label)
        serial = out / (label + '.serial')
        print('START %s rows=%d iso_sha256=%s' % (label, len(chunk), sha(iso)), flush=True)
        rc = boot(pax, kernel, iso, serial, keys, a.timeout, a.memory)
        print('END %s-qemu-halt exit=%d' % (label, rc), flush=True)
        text = serial.read_text(errors='replace') if serial.exists() else ''
        got = split_console(text)
        ran, fails = compare(sess, chunk, got)
        total_ran += ran
        total_fail += fails
        if rc != 0 and not got:
            print('FAIL %s machine did not halt and no row finished: %s' % (label, Path(str(serial) + '.verdict').read_text()[-300:].replace('\n', ' | ')))
    print('SUMMARY ran=%d failed=%d skipped=%d' % (total_ran, total_fail, len(skipped)))
    return 1 if total_fail else 0


def tty_boot(a, sess, pax, kernel, row, work):
    """One terminal row: sniff is init, the commands are typed key by key at its prompt."""
    work.mkdir(parents=True, exist_ok=True)
    prog = '/work/target/pax-fixtures/' + row['prog']
    files = [('/bin/sniff', a.sniff, 755), (prog, Path(a.fixtures) / row['prog'], 755)]
    for dest, src in sources_for([row]).items():
        files.append((dest, src, 644))
    pr = work / 'pax-run'
    pr.write_text('/bin/sniff %s\n' % prog)
    files.append(('/etc/pax-run', pr, 644))
    cpio, iso, keys = work / 'tty.cpio', work / 'tty.iso', work / 'tty.keys'
    args = ['/tmp/:1777'] + ['%s=%s:%s' % (d, s_, m) for d, s_, m in files]
    r = run([pax / 'tools/mkinitramfs', cpio] + args, capture_output=True, text=True)
    r2 = run([pax / 'tools/mkimage', '--conf', pax / 'boot/limine-initramfs-quiet.conf', '--add', cpio, 'initramfs.cpio', kernel, iso],
             capture_output=True, text=True)
    if r.returncode or r2.returncode:
        raise SystemExit('FAIL session-pax-image tty ' + row['name'])
    keys.write_text('\n'.join(row['script'] + ['quit']) + '\n')
    serial = work / 'tty.serial'
    cmd = [pax / 'tools/qemu-halt', '--firmware', 'bios', '--serial', serial, '--timeout', str(a.timeout), '--qemu', '-m', '--qemu', a.memory,
           '--elf', kernel, '--marker', 'halt|PANIC .*', '--type', keys, '--prompt', '(sniff) ', iso]
    rc = run(cmd, capture_output=True, text=True).returncode
    return rc, serial.read_text(errors='replace') if serial.exists() else ''


def tty_extract(text, row):
    """The session's text: from sniff's first line to its exit, typed echo removed."""
    t = serial_norm(text)
    i = t.find('Reading symbols from')
    cuts = [k for k in (t.find('\nrun: ', max(i, 0)), t.find('PAX: init ', max(i, 0))) if k >= 0]
    j = min(cuts) + 1 if cuts else -1
    t = t[i:j if j > i else len(t)] if i >= 0 else ''
    for k in row['script'] + ['quit']:
        t = t.replace('(sniff) ' + k + '\n', '(sniff) ', 1)
    return t


def cmd_tty(a):
    sess = load_session()
    rows = [r for r in sess.load_rows(a.only) if r.get('tty')]
    out = Path(a.out)
    fails = 0
    for row in rows:
        if row.get('skip'):
            print('SKIP %s reason=%s' % (row['name'], row['skip']))
            continue
        rc, text = tty_boot(a, sess, Path(a.pax), Path(a.kernel), row, out / row['name'])
        print('END %s-qemu-halt exit=%d' % (row['name'], rc), flush=True)
        fired = set()
        got = sess.normalize(sess.normalize_tty(tty_extract(text, row), fired), fired, row)
        want = sess.golden_paths(row)[0].read_text()
        if got != want:
            print('FAIL %s stdout %s' % (row['name'], sess.first_diff(want, got)))
            fails += 1
        else:
            print('PASS %s%s' % (row['name'], (' [normalised: ' + ','.join(sorted(fired)) + ']') if fired else ''))
    print('SUMMARY tty failed=%d' % fails)
    return 1 if fails else 0


def cmd_selftest(a):
    sample = ('noise\r\n@@BEGIN r1\r\n@@RC 3\r\n@@OUT\r\nhello\r\nno-nl\r\n@@ERR\r\nwarn\r\n\r\n@@END\r\n'
              '@@BEGIN r2\r\n@@RC 0\r\n@@OUT\r\n\r\n@@ERR\r\n\r\n@@END\r\n@@BEGIN r3\r\n@@RC 1\r\n@@OUT\r\nx\r\n')
    got = split_console(sample)
    assert got['r1'] == ('3', 'hello\nno-nl', 'warn\n'), got['r1']
    assert got['r2'] == ('0', '', ''), got['r2']
    assert 'r3' not in got
    print('PASS session-pax-selftest')
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    for k in ('pax', 'kernel', 'inputs', 'sniff', 'fixtures', 'out'):
        r.add_argument('--' + k, required=True)
    r.add_argument('--only')
    r.add_argument('--timeout', type=int, default=1800)
    r.add_argument('--memory', default='4096M')
    t = sub.add_parser('tty')
    for k in ('pax', 'kernel', 'sniff', 'fixtures', 'out'):
        t.add_argument('--' + k, required=True)
    t.add_argument('--only')
    t.add_argument('--timeout', type=int, default=600)
    t.add_argument('--memory', default='4096M')
    sub.add_parser('selftest')
    a = p.parse_args()
    return {'run': cmd_run, 'tty': cmd_tty, 'selftest': cmd_selftest}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
