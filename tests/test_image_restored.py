#!/usr/bin/env python3
"""A restored oracle image is used as it is, and checked exactly as a built one.

With SNIFF_IMAGE_RESTORED=1, and an image under the key's tag already present,
tools/in-container does not build: the Linux job sets the switch only after it
loads the image its cache restored. Without the switch, or with the switch and
no such image, it builds as before, so every other host is unchanged. Either
way the image's packages and binaries are then diffed against ci/packages.txt
and ci/oracle-binaries.lock by the same calls, and a restored image that
differs from its pins fails as a built one does.

Each case runs a copy of the tool and its pin files in a scratch tree, with a
stand-in engine that logs every call: nothing is built and the repository's own
target/ is not touched.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
tmp = root / 'target' / 'tmp'
tmp.mkdir(parents=True, exist_ok=True)
ENGINE = r'''#!/bin/sh
printf '%s\n' "$*" >> "$ENGINE_LOG"
case "$1" in
  build) : > "$ENGINE_STATE/present"; exit 0 ;;
  image) [ -f "$ENGINE_STATE/present" ] || exit 1
         case "$*" in *--format*) echo sha256:5e1f00d0;; esac; exit 0 ;;
  run) for a in "$@"; do last=$a; done
       case "$last" in
         /opt/oracle-packages.txt) cat "$ENGINE_PACKAGES" ;;
         /opt/oracle-binaries.txt) cat "$ENGINE_BINARIES" ;;
         *) exit 1 ;;
       esac
       exit 0 ;;
esac
exit 1
'''
failures = []


def check(what, ok, detail=''):
    if ok:
        print('PASS oracle-image-restored %s' % what)
    else:
        print('FAIL oracle-image-restored %s %s' % (what, detail))
        failures.append(what)


def case(work, name, restored=None, present=False, packages=None, binaries=None):
    """Run in-container (prepare only) in a fresh copy; return (exit, output, engine calls)."""
    tree = work / name
    for rel in ('tools/in-container', 'tools/oracle-image-key'):
        if (root / rel).exists():
            (tree / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / rel, tree / rel)
    shutil.copytree(root / 'ci', tree / 'ci')
    state = tree / 'engine-state'
    state.mkdir()
    if present:
        (state / 'present').write_text('')
    engine = tree / 'engine'
    engine.write_text(ENGINE)
    engine.chmod(0o755)
    log = tree / 'engine.log'
    env = {k: v for k, v in os.environ.items() if not k.startswith('SNIFF_')}
    env.update(SNIFF_ENGINE=str(engine), SNIFF_PREPARE_ONLY='1', SNIFF_IMAGE_PREFIX='test-oracle',
               ENGINE_LOG=str(log), ENGINE_STATE=str(state),
               ENGINE_PACKAGES=str(packages or root / 'ci/packages.txt'),
               ENGINE_BINARIES=str(binaries or root / 'ci/oracle-binaries.lock'))
    if restored is not None:
        env['SNIFF_IMAGE_RESTORED'] = restored
    r = subprocess.run(['bash', str(tree / 'tools/in-container')], cwd=tree, env=env, text=True, capture_output=True)
    calls = log.read_text().splitlines() if log.exists() else []
    return r.returncode, r.stdout + r.stderr, calls


def builds(calls):
    return [c for c in calls if c.startswith('build ')]


def checks_of(calls):
    """The calls that check the image: everything but the build and the switch's own probe for the tag."""
    return [c for c in calls if not c.startswith('build ') and not re.fullmatch(r'image inspect \S+', c)]


def diff_lines(out):
    """The changed lines a pin diff printed (its file headers name the scratch tree, so they are left out)."""
    return [ln for ln in out.splitlines() if re.match(r'[-+](?![-+]{2} )', ln)]


PASS_PINS = 'PASS oracle-binary-and-package-pins'
with tempfile.TemporaryDirectory(dir=tmp) as work:
    work = Path(work)
    drifted = work / 'packages-drifted.txt'
    lines = (root / 'ci/packages.txt').read_text().splitlines()
    first = next(i for i, ln in enumerate(lines) if ln and not ln.startswith('#'))
    lines[first] = lines[first] + '.drifted'
    drifted.write_text('\n'.join(lines) + '\n')
    moved = work / 'binaries-moved.txt'
    blines = (root / 'ci/oracle-binaries.lock').read_text().splitlines()
    blines[-1] = re.sub(r'[0-9a-f]{64}', '0' * 64, blines[-1])
    moved.write_text('\n'.join(blines) + '\n')

    rc_r, out_r, calls_r = case(work, 'restored', restored='1', present=True)
    check('a restored image is not built', rc_r == 0 and not builds(calls_r) and PASS_PINS in out_r,
          '(exit %s, builds %r)' % (rc_r, builds(calls_r)))
    check('a restored image is named as restored', re.search(r'oracle image test-oracle:\S+ restored: not built', out_r)
          is not None, out_r[-300:])
    rc_b, out_b, calls_b = case(work, 'built', present=True)
    check('without the switch the image is built, present or not', rc_b == 0 and len(builds(calls_b)) == 1
          and PASS_PINS in out_b, '(exit %s, builds %r)' % (rc_b, builds(calls_b)))
    rc_f, out_f, calls_f = case(work, 'fallback', restored='1', present=False)
    check('with the switch and no image present it builds', rc_f == 0 and len(builds(calls_f)) == 1 and PASS_PINS in out_f,
          '(exit %s, builds %r)' % (rc_f, builds(calls_f)))
    rc_o, out_o, calls_o = case(work, 'other-value', restored='yes', present=True)
    check('only the value 1 is the switch', rc_o == 0 and len(builds(calls_o)) == 1, '(builds %r)' % (builds(calls_o),))
    check('the pins are checked by the same calls on a restored image as on a built one',
          checks_of(calls_r) == checks_of(calls_b) and any('oracle-packages.txt' in c for c in checks_of(calls_r))
          and any('oracle-binaries.txt' in c for c in checks_of(calls_r)),
          '(restored %r, built %r)' % (checks_of(calls_r), checks_of(calls_b)))
    for what, kw in (('packages', dict(packages=drifted)), ('binaries', dict(binaries=moved))):
        rc_rd, out_rd, _ = case(work, 'restored-' + what, restored='1', present=True, **kw)
        rc_bd, out_bd, _ = case(work, 'built-' + what, present=True, **kw)
        check('a restored image whose %s differ from their pins fails' % what,
              rc_rd != 0 and PASS_PINS not in out_rd and diff_lines(out_rd), '(exit %s)' % rc_rd)
        check('a built image whose %s differ fails the same way' % what,
              rc_bd != 0 and PASS_PINS not in out_bd and diff_lines(out_bd) == diff_lines(out_rd),
              '(exit %s: %r against %r)' % (rc_bd, diff_lines(out_bd), diff_lines(out_rd)))

print('%s oracle-image-restored (%d failed)' % ('FAIL' if failures else 'PASS', len(failures)))
raise SystemExit(1 if failures else 0)
