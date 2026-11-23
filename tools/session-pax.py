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
  session-pax.py probes --fixtures DIR [--capture]   build the kernel probes static and run them on Linux
  session-pax.py selftest                   the marker splitter, no machine

The kernel probes ("probes" in tests/pax-rows.json) run first in the first image, between markers of their own
(probe:NAME), and are held to their Linux answers (tests/evidence/pax-linux/probe-NAME.out, .rc). A row skipped
for a gap in PAX names its probe; while PAX answers that probe differently from Linux the row is SKIP with the first
differing line as its witness, and once PAX answers alike the row is FAIL skip-stale: the skip is no longer true.
A probe no skip names is a capability rows rely on, PASS or FAIL against Linux.

A core row reads a core the pinned gdb wrote on Linux from the same static build (tools/session.py makes the PAX
set's cores in target/cores/pax beside --fixtures, in the oracle image). The image carries each core at the path
it has there, /work/target/cores/pax/NAME.core, and sniff is given it as the row's form says; a core that was not
made is FAIL no-core by name.
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
BEGIN, RC, OUT, ERR, END, WAIT = '@@BEGIN ', '@@RC ', '@@OUT', '@@ERR', '@@END', '@@WAIT '
MAX_CHUNK_BYTES = 70_000_000
# where the image puts the fixtures, as their line tables and the Linux goldens name them
GUEST_FX = '/work/target/pax-fixtures'


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


def sh_double(text):
    """text as the inside of a double-quoted shell word, with {pid} becoming the sleeper's pid."""
    t = text.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    return t.replace('{pid}', '$pid')


# How many reads a row's shell lines make while they wait for the sleeper's or the holder's first line. pelt's
# read loop takes memory each time round, and a wait that never ends ran the console out of frames and ended
# every row after it; a bounded wait ends one row instead.
WAIT_READS = 400


def holder_prog(prog):
    """The holder fixture beside a sleeper fixture, for the same compiler: c/holder/CC-O0/prog."""
    return prog.replace('c/sleeper/', 'c/holder/', 1)


def image_progs(rows):
    """The fixtures an image carries for its rows: each row's program, and the holder of a held attach row."""
    progs = {r['prog'] for r in rows}
    progs |= {holder_prog(r['prog']) for r in rows if r.get('attach', {}).get('held')}
    return sorted(progs)


def attach_block(row, scripts_dir, fx_guest, prog):
    """The shell lines that start an attach row's sleeper and give sniff its pid, as tools/session.py's attach_run
    does on Linux: the sleeper in the background, its 'ready PID' line awaited, the holder first if the row says
    so, the script written with the pid, sniff run, then the sleeper's end appended to stdout."""
    a = row['attach']
    script = '%s/%s.cmd' % (scripts_dir, row['name'])
    out = ['%s %d > /tmp/sl 2> /dev/null &' % (prog, a.get('ticks', 100)), 'sp=$!', 'r=', 'n=0',
           'while [ -z "$r" ] && [ $n -lt %d ]; do read r < /tmp/sl; n=$((n + 1)); done' % WAIT_READS, 'pid=${r#ready }',
           # sniff starts once the sleeper blocks in its nap (tools/session.py says why); the state seen is
           # printed before the row's result, where the console's reader ignores it
           'st=', 'n=0',
           'while [ "$st" != S ] && [ $n -lt %d ]; do st=; while read k v rest; do [ "$k" = State: ] && st=$v; done '
           '< /proc/$pid/status; n=$((n + 1)); done' % WAIT_READS,
           "printf '%s\\n' \"" + WAIT + "$st $n\""]
    if a.get('held'):
        out += ['%s $pid 3000 > /tmp/hl &' % holder_prog(prog), 'hp=$!', 'h=', 'n=0',
                'while [ -z "$h" ] && [ $n -lt %d ]; do read h < /tmp/hl; n=$((n + 1)); done' % WAIT_READS]
    out.append(': > %s' % script)
    for ln in row['script']:
        out.append('printf \'%%s\\n\' "%s" >> %s' % (sh_double(ln), script))
    form = a.get('form', 'script')
    target = '-p $pid %s' % prog if form == 'dash-p' else '%s $pid' % prog if form == 'positional' else prog
    out.append('/bin/sniff -batch -x %s %s > /tmp/o 2> /tmp/e' % (script, target))
    out.append('rc=$?')
    out.append('wait $sp')
    out.append('src=$?')
    out.append('last=; while read l; do last=$l; done < /tmp/sl')
    out.append('if [ $src -gt 128 ]; then printf \'%s\\n\' "[sleeper killed by signal $((src - 128))]" >> /tmp/o; '
               'else printf \'%s\\n\' "[sleeper exited with code $src: $last]" >> /tmp/o; fi')
    if a.get('held'):
        out.append('wait $hp')
    out.append("printf '%s\\n' \"" + RC + "$rc\"")
    return out


def probe_block(name, fx_guest):
    """A kernel probe's lines: its answer between the markers a row's has, under the name probe:NAME."""
    return ["printf '%s\\n' '" + BEGIN + "probe:" + name + "'",
            '%s/probe/%s > /tmp/o 2> /tmp/e' % (fx_guest, name),
            "printf '%s\\n' \"" + RC + "$?\"",
            "printf '%s\\n' '" + OUT + "'", 'cat /tmp/o', "printf '\\n%s\\n' '" + ERR + "'", 'cat /tmp/e',
            "printf '\\n%s\\n' '" + END + "'"]


def guest_script(rows, scripts_dir, fx_guest, probes=(), sess=None):
    """The text of /etc/rows.sh: the probes, then one block per row; markers on lines of their own."""
    if sess is None and any(r.get('core') for r in rows):
        sess = load_session()
    lines = []
    for name in probes:
        lines += probe_block(name, fx_guest)
    for row in rows:
        args = ''
        if row.get('args'):
            args = ' --args ' + ' '.join(row['args'])
        prog = fx_guest + '/' + row['prog']
        lines.append("printf '%s\\n' '" + BEGIN + row['name'] + "'")
        if row.get('attach'):
            lines += attach_block(row, scripts_dir, fx_guest, prog)
        elif row.get('core'):
            tail = ' '.join(sess.core_tail(row, prog, fx_guest))
            lines.append('/bin/sniff -batch -x %s/%s.cmd %s > /tmp/o 2> /tmp/e' % (scripts_dir, row['name'], tail))
            lines.append("printf '%s\\n' \"" + RC + "$?\"")
        else:
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


def row_files(row, fixtures, sess=None):
    """The host files a row's image needs besides the shared ones: its program and the core it reads (none for a
    row whose core is missing on purpose)."""
    files = [Path(fixtures) / row['prog']]
    if row.get('core') and row['core'].get('file') != 'missing':
        files.append(Path((sess or load_session()).core_path(row, fixtures)))
    return files


def chunk_rows(rows, fixtures):
    """Rows in groups whose distinct programs and cores fit one image."""
    sess = load_session() if any(r.get('core') for r in rows) else None
    chunks, cur, have, size = [], [], set(), 0
    for row in rows:
        need = [f for f in row_files(row, fixtures, sess) if f not in have]
        extra = sum(f.stat().st_size for f in need)
        if cur and size + extra > MAX_CHUNK_BYTES:
            chunks.append(cur)
            cur, have, size = [], set(), 0
            need = row_files(row, fixtures, sess)
            extra = sum(f.stat().st_size for f in need)
        cur.append(row)
        have.update(need)
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
            # a session program, or one of the S1 corpus's (build-session.py's CORPUS_C); a c/NAME-gone build's
            # source was removed by its build, so nothing is put at the path its line table names
            for base in ('fixtures/session/c', 'fixtures/c'):
                d = ROOT / base / parts[1]
                for f in sorted(d.glob('*.c')):
                    seen['/work/%s/%s/%s' % (base, parts[1], f.name)] = f
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


def smp_args(n):
    """QEMU's processor count for a boot, passed through tools/qemu-halt: none for one processor."""
    return ['--qemu', '-smp', '--qemu', str(n)] if n > 1 else []


def boot(pax, kernel, iso, serial, keys, timeout, mem, leg='bios', smp=1):
    cmd = [pax / 'tools/qemu-halt', '--firmware', leg, '--serial', serial, '--timeout', str(timeout),
           '--qemu', '-m', '--qemu', mem] + smp_args(smp) + ['--elf', kernel, '--marker', 'halt|PANIC .*',
           '--type', keys, '--prompt', '$ ', iso]
    r = run(cmd, capture_output=True, text=True)
    Path(str(serial) + '.verdict').write_text(r.stdout + r.stderr)
    return r.returncode


def build_image(pax, kernel, inputs, sniff, fixtures, rows, work, label, probes=()):
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    files = [('/bin/sh', inputs / 'pelt/pelt', 755), ('/bin/sniff', sniff, 755)]
    for tool in ('cat', 'env'):
        files.append(('/bin/' + tool, inputs / 'bore' / tool, 755))
    scripts = work / 'cmds'
    scripts.mkdir(exist_ok=True)
    sess = load_session()
    cores = {}
    for row in rows:
        f = scripts / (row['name'] + '.cmd')
        f.write_text('\n'.join(sess.core_script(row, GUEST_FX)['script']) + '\n')
        files.append(('/work/target/s2/%s.cmd' % row['name'], f, 644))
        if row.get('core') and row['core'].get('file') != 'missing':
            cores[sess.core_path(row, GUEST_FX)] = Path(sess.core_path(row, fixtures))
    for prog in image_progs(rows):
        files.append((GUEST_FX + '/' + prog, Path(fixtures) / prog, 755))
    for dest, src in sorted(cores.items()):
        files.append((dest, src, 644))
    for name in probes:
        files.append(('/work/target/pax-fixtures/probe/' + name, Path(fixtures) / 'probe' / name, 755))
    for dest, src in sources_for(rows).items():
        files.append((dest, src, 644))
    rows_sh = work / 'rows.sh'
    rows_sh.write_text(guest_script(rows, '/work/target/s2', GUEST_FX, probes, sess))
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
    # one typed line: a second step would wait for the shell's second '$ ', and a row's own output can hold
    # '$ ' (help print's "$ is the last value"), which typed `exit` into the middle of the rows
    keys.write_text('/bin/sh /etc/rows.sh; exit\n')
    return iso, keys, sess


def first_line_diff(want, got):
    wl, gl = want.splitlines(), got.splitlines()
    for i in range(max(len(wl), len(gl))):
        w = wl[i] if i < len(wl) else '<end>'
        g = gl[i] if i < len(gl) else '<end>'
        if w != g:
            return 'line %d: want %r got %r' % (i + 1, w, g)
    return 'equal'


def expect_differences(want_o, out, named):
    """PAX's answer with the probe's named differences applied: each named call's line, where Linux answers `linux`
    and PAX `pax`, is compared as Linux's. Returns (the answer as compared, the notes, the problems): a named line that
    PAX answers as Linux does is difference-stale, one PAX answers otherwise again is difference-moved, and one Linux
    no longer answers as named is difference-golden."""
    w, g = want_o.split('\n'), out.split('\n')
    notes, bad = [], []
    for d in named:
        lw, lp = '%s -> %s' % (d['call'], d['linux']), '%s -> %s' % (d['call'], d['pax'])
        if lw not in w:
            bad.append('difference-golden: Linux no longer answers %r' % lw)
            continue
        i = w.index(lw)
        here = g[i] if i < len(g) else '<end>'
        if here == lp:
            g[i] = lw
            notes.append('%s (%s)' % (lp, d['why']))
        elif here == lw:
            bad.append('difference-stale: PAX answers %r as Linux does' % d['call'])
        else:
            bad.append('difference-moved: want %r got %r' % (lp, here))
    return '\n'.join(g), notes, bad


def probe_verdicts(skipped, got, linux, differences=None):
    """(verdict, name, why) for every probe and every skipped row. got: probe name -> (rc, out, err) from the
    console; linux: probe name -> (out, rc), the golden; differences: probe name -> its named differences
    (expect_differences), each of which PAX must show as named. A skip whose gap is a probe PAX answers as Linux does
    is FAIL skip-stale; one PAX answers otherwise is SKIP, witnessed by the first differing line; a harness skip is
    SKIP; a probe no skip names is PASS (naming the differences it expected) or FAIL against Linux; a probe with no
    answer is FAIL."""
    res = []
    named = {r['gap'] for r in skipped if r.get('gap') not in (None, 'harness')}
    for name in sorted(linux):
        want_o, want_rc = linux[name]
        if name not in got:
            res.append(('FAIL', 'probe-' + name, 'no-result: the console shows no complete block for this probe'))
            for r in skipped:
                if r.get('gap') == name:
                    res.append(('SKIP', r['name'], 'reason=%s gap=%s witness=none' % (r['skip'], name)))
            continue
        rc, out, err = got[name]
        notes, bad = [], []
        if differences and differences.get(name):
            out, notes, bad = expect_differences(want_o, out, differences[name])
        same = not bad and out == want_o and str(rc).strip() == str(want_rc).strip() and err == ''
        why = 'equal' if same else bad[0] if bad else (first_line_diff(want_o, out) if out != want_o else
                                    'exit want %s got %s' % (str(want_rc).strip(), rc) if str(rc).strip() != str(want_rc).strip()
                                    else 'stderr %r' % err[:80])
        for r in skipped:
            if r.get('gap') != name:
                continue
            if same:
                res.append(('FAIL', r['name'], 'skip-stale: PAX answers the %s probe as Linux does, so "%s" is no '
                            'longer true' % (name, r['skip'])))
            else:
                res.append(('SKIP', r['name'], 'reason=%s gap=%s witness=%s' % (r['skip'], name, why)))
        if name not in named:
            res.append(('PASS', 'probe-' + name, ('expected differences: ' + '; '.join(notes)) if notes else '') if same
                       else ('FAIL', 'probe-' + name, why))
    for r in skipped:
        if r.get('gap') == 'harness':
            res.append(('SKIP', r['name'], 'reason=' + r['skip']))
    return res


def linux_probe_goldens(sess):
    gold = {}
    for name in sess.load_probes():
        o, rc = sess.probe_golden_paths(name)
        gold[name] = (o.read_text(), rc.read_text())
    return gold


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
        bad = sess.judge(row, o, e, rc, want_o, want_e, want_rc)
        if bad:
            print('FAIL %s %s' % (row['name'], '; '.join(bad)))
            fails += 1
        else:
            print('PASS %s%s' % (row['name'], (' [normalised: ' + ','.join(sorted(fired)) + ']') if fired else ''))
    return ran, fails


def cmd_run(a):
    sess = load_session()
    sess.FIXTURES = a.fixtures
    rows = [r for r in sess.load_rows(a.only) if not r.get('tty')]
    skipped = [r for r in rows if r.get('skip')]
    rows = [r for r in rows if not r.get('skip')]
    no_core = [r for r in rows if not all(f.exists() for f in row_files(r, a.fixtures, sess))]
    for r in no_core:
        print('FAIL %s no-core %s' % (r['name'], r['core']['of']))
    rows = [r for r in rows if r not in no_core]
    linux = linux_probe_goldens(sess)
    probes = sorted(linux)
    probe_got = {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pax = Path(a.pax)
    kernel = Path(a.kernel)
    print('KERNEL sha256=%s' % sha(kernel))
    print('SNIFF sha256=%s' % sha(a.sniff))
    print('SMP %d' % a.smp)
    total_ran = total_fail = 0
    for i, chunk in enumerate(chunk_rows(rows, a.fixtures) or [[]]):
        label = 'boot%02d' % i
        first = probes if i == 0 else ()
        iso, keys, _ = build_image(pax, kernel, Path(a.inputs), a.sniff, a.fixtures, chunk, out / label, label, first)
        serial = out / (label + '.serial')
        print('START %s rows=%d iso_sha256=%s' % (label, len(chunk), sha(iso)), flush=True)
        rc = boot(pax, kernel, iso, serial, keys, a.timeout, a.memory, smp=a.smp)
        print('END %s-qemu-halt exit=%d' % (label, rc), flush=True)
        text = serial.read_text(errors='replace') if serial.exists() else ''
        got = split_console(text)
        for name in first:
            if 'probe:' + name in got:
                probe_got[name] = got['probe:' + name]
        ran, fails = compare(sess, chunk, got)
        total_ran += ran
        total_fail += fails
        if rc != 0 and not got:
            print('FAIL %s machine did not halt and no row finished: %s' % (label, Path(str(serial) + '.verdict').read_text()[-300:].replace('\n', ' | ')))
    nskip = 0
    for verdict, name, why in probe_verdicts(skipped, probe_got, linux, sess.load_probe_differences()):
        print('%s %s%s' % (verdict, name, (' ' + why) if why else ''))
        total_fail += verdict == 'FAIL'
        nskip += verdict == 'SKIP'
    total_fail += len(no_core)
    print('SUMMARY ran=%d failed=%d skipped=%d' % (total_ran, total_fail, nskip))
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
    cmd = [pax / 'tools/qemu-halt', '--firmware', 'bios', '--serial', serial, '--timeout', str(a.timeout), '--qemu', '-m', '--qemu', a.memory]
    cmd += smp_args(a.smp) + ['--elf', kernel, '--marker', 'halt|PANIC .*', '--type', keys, '--prompt', '(sniff) ', iso]
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
    sess.FIXTURES = a.fixtures
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


def cmd_probes(a):
    """Build each kernel probe static (the PAX image's copy) and run it here, on Linux: --capture writes its
    golden, otherwise it is held to it."""
    sess = load_session()
    fails = 0
    outdir = Path(a.fixtures) / 'probe'
    outdir.mkdir(parents=True, exist_ok=True)
    env = dict(sess.ENV_BASE)
    for name, src in sorted(sess.load_probes().items()):
        exe = outdir / name
        b = subprocess.run([a.cc, '-O0', '-fno-pie', '-static', '-no-pie', '-o', str(exe), str(ROOT / src)], capture_output=True, text=True)
        if b.returncode != 0:
            print('FAIL probe-linux-%s build %s' % (name, (b.stderr or b.stdout).strip()[-300:]))
            fails += 1
            continue
        try:
            r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60, env=env, cwd=str(outdir))
        except subprocess.TimeoutExpired:
            print('FAIL probe-linux-%s timeout' % name)
            fails += 1
            continue
        o, rc = sess.probe_golden_paths(name)
        if a.capture:
            o.write_text(r.stdout)
            rc.write_text('%d\n' % r.returncode)
            print('CAPTURE probe-linux-%s rc=%d sha256=%s' % (name, r.returncode, sha(exe)))
            continue
        if not (o.exists() and rc.exists()):
            print('FAIL probe-linux-%s no-golden' % name)
            fails += 1
            continue
        if r.stdout != o.read_text() or str(r.returncode) != rc.read_text().strip() or r.stderr:
            why = first_line_diff(o.read_text(), r.stdout) if r.stdout != o.read_text() else 'exit %d stderr %r' % (r.returncode, r.stderr[:80])
            print('FAIL probe-linux-%s %s' % (name, why))
            fails += 1
        else:
            print('PASS probe-linux-%s sha256=%s' % (name, sha(exe)))
    return 1 if fails else 0


def cmd_selftest(a):
    sample = ('noise\r\n@@BEGIN r1\r\n@@RC 3\r\n@@OUT\r\nhello\r\nno-nl\r\n@@ERR\r\nwarn\r\n\r\n@@END\r\n'
              '@@BEGIN r2\r\n@@RC 0\r\n@@OUT\r\n\r\n@@ERR\r\n\r\n@@END\r\n@@BEGIN r3\r\n@@RC 1\r\n@@OUT\r\nx\r\n')
    got = split_console(sample)
    assert got['r1'] == ('3', 'hello\nno-nl', 'warn\n'), got['r1']
    assert got['r2'] == ('0', '', ''), got['r2']
    assert 'r3' not in got
    held = {'name': 'a1', 'prog': 'c/sleeper/gcc-O0/prog', 'script': ['attach {pid}', 'print "$x"'], 'attach': {'ticks': 7, 'held': True}}
    text = guest_script([held], '/s', '/f')
    assert '/f/c/sleeper/gcc-O0/prog 7 > /tmp/sl 2> /dev/null &' in text, text
    assert '/f/c/holder/gcc-O0/prog $pid 3000 > /tmp/hl &' in text, text
    assert 'printf \'%s\\n\' "attach $pid" >> /s/a1.cmd' in text, text
    assert 'printf \'%s\\n\' "print \\"\\$x\\"" >> /s/a1.cmd' in text, text
    assert '/bin/sniff -batch -x /s/a1.cmd /f/c/sleeper/gcc-O0/prog > /tmp/o 2> /tmp/e' in text, text
    dash = guest_script([dict(held, attach={'form': 'dash-p'})], '/s', '/f')
    assert '-x /s/a1.cmd -p $pid /f/c/sleeper/gcc-O0/prog >' in dash and 'holder' not in dash, dash
    # the image carries the holder a held row starts, at the path the row's shell lines run it from
    progs = image_progs([held, {'name': 'r', 'prog': 'c/hits/gcc-O0/prog', 'script': []}])
    assert progs == ['c/hits/gcc-O0/prog', 'c/holder/gcc-O0/prog', 'c/sleeper/gcc-O0/prog'], progs
    assert image_progs([dict(held, attach={'ticks': 7})]) == ['c/sleeper/gcc-O0/prog']
    # every wait for a line is bounded: pelt's read loop cannot spin the console out of memory
    for ln in text.splitlines():
        if ln.startswith('while '):
            assert '-lt %d' % WAIT_READS in ln, ln
    # sniff starts once the sleeper blocks in its nap (State S in its status), bounded, and the state is printed
    i_wait = [i for i, ln in enumerate(text.splitlines()) if '/proc/$pid/status' in ln]
    i_sniff = [i for i, ln in enumerate(text.splitlines()) if ln.startswith('/bin/sniff ')]
    assert i_wait and i_sniff and i_wait[0] < i_sniff[0], text
    assert '"$st" != S' in text.splitlines()[i_wait[0]], text
    assert "printf '%s\\n' \"" + WAIT + "$st $n\"" in text, text
    # a kernel probe runs first in the image, between its own markers, and its answer is split like a row's
    probed = guest_script([], '/s', '/f', probes=['dr'])
    assert probed.splitlines()[0] == "printf '%s\\n' '" + BEGIN + "probe:dr'", probed
    assert '/f/probe/dr > /tmp/o 2> /tmp/e' in probed, probed
    assert split_console('@@BEGIN probe:dr\n@@RC 0\n@@OUT\na 1\nb 2\n\n@@ERR\n\n@@END\n')['probe:dr'] == ('0', 'a 1\nb 2\n', '')
    # a skip that blames PAX stands only while PAX answers its probe unlike Linux: the same answer makes the
    # skipped row red by name; another answer keeps the SKIP and names the first line that differs
    linux = {'dr': ('a 1\nb 2\n', '0')}
    watch = {'name': 'watch-x', 'skip': 'no debug registers', 'gap': 'dr'}
    tty = {'name': 'tty-x', 'skip': 'no shell', 'gap': 'harness'}
    same = probe_verdicts([watch, tty], {'dr': ('0', 'a 1\nb 2\n', '')}, linux)
    assert ('FAIL', 'watch-x') in [(v, n) for v, n, _ in same], same
    assert ('SKIP', 'tty-x') in [(v, n) for v, n, _ in same], same
    assert [w for v, n, w in same if n == 'watch-x'][0].startswith('skip-stale'), same
    other = probe_verdicts([watch], {'dr': ('0', 'a 1\nb -1\n', '')}, linux)
    assert other[0][:2] == ('SKIP', 'watch-x') and "line 2: want 'b 2' got 'b -1'" in other[0][2], other
    # a probe no skip names is held to Linux's answer: a capability a row relies on
    assert probe_verdicts([], {'dr': ('0', 'a 1\nb 2\n', '')}, linux) == [('PASS', 'probe-dr', '')]
    assert probe_verdicts([], {'dr': ('0', 'a 1\n', '')}, linux)[0][:2] == ('FAIL', 'probe-dr')
    assert probe_verdicts([watch], {}, linux)[0][:2] == ('FAIL', 'probe-dr')
    # a core row: sniff is given the core at the path the image carries it at, in the row's form
    sess = load_session()
    core = {'name': 'c1', 'prog': 'c/calls/gcc-O0/prog', 'script': ['bt'], 'core': {'of': 'gcc-break'}}
    ct = guest_script([core, dict(core, name='c2', core={'of': 'gcc-break', 'form': 'dash-c'})], '/s', GUEST_FX, sess=sess)
    g = GUEST_FX + '/c/calls/gcc-O0/prog'
    assert '/bin/sniff -batch -x /s/c1.cmd %s /work/target/cores/pax/gcc-break.core > /tmp/o 2> /tmp/e' % g in ct, ct
    assert '/bin/sniff -batch -x /s/c2.cmd -c /work/target/cores/pax/gcc-break.core %s >' % g in ct, ct
    drop = dict(core, script=['core-file {core}', 'bt'], core={'of': 'gcc-break', 'form': 'script'})
    assert sess.core_script(drop, GUEST_FX)['script'][0] == 'core-file /work/target/cores/pax/gcc-break.core'
    assert row_files(dict(core, core={'of': 'gcc-break', 'file': 'missing'}), '/h/pax-fixtures', sess) == \
        [Path('/h/pax-fixtures/c/calls/gcc-O0/prog')]
    assert row_files(core, '/h/pax-fixtures', sess)[1] == Path('/h/cores/pax/gcc-break.core')
    # the processor count reaches QEMU through qemu-halt only when it is more than one
    assert smp_args(1) == [] and smp_args(4) == ['--qemu', '-smp', '--qemu', '4']
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
    r.add_argument('--smp', type=int, default=1, help='processors QEMU gives the guest')
    t = sub.add_parser('tty')
    for k in ('pax', 'kernel', 'sniff', 'fixtures', 'out'):
        t.add_argument('--' + k, required=True)
    t.add_argument('--only')
    t.add_argument('--timeout', type=int, default=600)
    t.add_argument('--memory', default='4096M')
    t.add_argument('--smp', type=int, default=1, help='processors QEMU gives the guest')
    pr = sub.add_parser('probes')
    pr.add_argument('--fixtures', required=True)
    pr.add_argument('--cc', default='gcc')
    pr.add_argument('--capture', action='store_true')
    sub.add_parser('selftest')
    a = p.parse_args()
    return {'run': cmd_run, 'tty': cmd_tty, 'probes': cmd_probes, 'selftest': cmd_selftest}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
