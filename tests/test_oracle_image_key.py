#!/usr/bin/env python3
"""The oracle image's key, and which runs may save the image under it.

tools/oracle-image-key prints the key tools/in-container tags the image with: one
definition, read by the tool and by the workflow's cache steps. With --cache it
prints the cache entry the Linux job restores and whether that job may save one:
only a run on trunk saves under trunk's key, and a dispatch on another branch that
asks for its own entry saves under a key with the branch prefix, which trunk never
restores. A pull request's run never saves. The workflow's only save step is
gated on that answer, and no combined cache action (which saves when the job
ends) is used.
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
SCRIPT = root / 'tools' / 'oracle-image-key'
PINS = ('ci/oracle.Containerfile', 'ci/packages.txt', 'ci/apt-snapshot', 'ci/snapshot-update.sh',
        'ci/snapshot-install.sh')
TRUNK = 'refs/heads/trunk'
failures = []


def check(what, ok, detail=''):
    if ok:
        print('PASS oracle-image-key %s' % what)
    else:
        print('FAIL oracle-image-key %s %s' % (what, detail))
        failures.append(what)


def key_of(tree):
    r = subprocess.run(['python3', '-I', str(SCRIPT), str(tree)], text=True, capture_output=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def cache_of(event, ref, entry='', arch='X64', prefix=None, tree=root):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('GITHUB_', 'RUNNER_', 'BRANCH_CACHE_', 'SNIFF_'))}
    env.update(GITHUB_EVENT_NAME=event, GITHUB_REF=ref, RUNNER_ARCH=arch, BRANCH_CACHE_ENTRY=entry)
    if prefix is not None:
        env['SNIFF_IMAGE_PREFIX'] = prefix
    r = subprocess.run(['python3', '-I', str(SCRIPT), '--cache', str(tree)], text=True, capture_output=True, env=env)
    out = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
    return r.returncode, out, r.stderr.strip()


# the key: 20 hex digits, the one tools/in-container tags with
rc, key, err = key_of(root)
check('prints a key', rc == 0 and re.fullmatch(r'[0-9a-f]{20}', key or '') is not None, '(exit %s: %r %s)' % (rc, key, err))
with tempfile.TemporaryDirectory(dir=tmp) as work:
    work = Path(work)
    engine, capture = work / 'engine', work / 'capture'
    engine.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CAPTURE"\nexit 1\n')
    engine.chmod(0o755)
    env = dict(os.environ, SNIFF_ENGINE=str(engine), SNIFF_IMAGE_PREFIX='test-oracle', CAPTURE=str(capture))
    env.pop('SNIFF_IMAGE_RESTORED', None)
    subprocess.run(['bash', str(root / 'tools/in-container')], cwd=root, env=env, text=True, capture_output=True)
    tagged = re.search(r' -t test-oracle:([0-9a-f]+)', capture.read_text() if capture.exists() else '')
    check('tools/in-container tags the image with it', tagged is not None and tagged.group(1) == key,
          '(tagged %s, key %s)' % (tagged and tagged.group(1), key))
    # every pin file is in the key, and nothing else in the tree is
    copy = work / 'tree'
    for name in PINS:
        (copy / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, copy / name)
    base = key_of(copy)[1]
    check('a copy of the five pin files keys alike', bool(key) and base == key, '(%s, %s)' % (base, key))
    (copy / 'README.md').write_text('not a pin\n')
    check('a file outside the pins changes nothing', bool(base) and key_of(copy)[1] == base)
    for name in PINS:
        saved = (copy / name).read_bytes()
        (copy / name).write_bytes(saved + b'\n')
        check('%s changes the key' % name, key_of(copy)[1] not in (base, ''))
        (copy / name).write_bytes(saved)

# which entry each run restores, and which may save
trunk_key = 'sniff-oracle-X64-%s' % key
branch_key = 'sniff-oracle-branch-X64-%s' % key
rows = [
    # (what, event, ref, entry, want exit, want key, want save)
    ('a pull request reads trunk and saves nothing', 'pull_request', 'refs/pull/44/merge', '', 0, trunk_key, 'no'),
    ('a pull request asking for a branch entry still saves nothing', 'pull_request', 'refs/pull/44/merge', 'true', 0,
     trunk_key, 'no'),
    ('a pull request whose ref names trunk saves nothing', 'pull_request', TRUNK, '', 0, trunk_key, 'no'),
    ('a push to trunk saves under trunk', 'push', TRUNK, '', 0, trunk_key, 'yes'),
    ('the nightly on trunk saves under trunk', 'schedule', TRUNK, '', 0, trunk_key, 'yes'),
    ('a dispatch on trunk saves under trunk', 'workflow_dispatch', TRUNK, 'false', 0, trunk_key, 'yes'),
    ('a dispatch on trunk asking for a branch entry is refused', 'workflow_dispatch', TRUNK, 'true', 1, None, None),
    ('a dispatch on a branch asking for its entry saves under the branch prefix', 'workflow_dispatch',
     'refs/heads/sn08-ci-image-cache', 'true', 0, branch_key, 'yes'),
    ('a dispatch on a branch without it reads trunk and saves nothing', 'workflow_dispatch',
     'refs/heads/sn08-ci-image-cache', 'false', 0, trunk_key, 'no'),
    ('a push to another branch saves nothing', 'push', 'refs/heads/sn08-ci-image-cache', '', 0, trunk_key, 'no'),
    ('an event the workflow does not name saves nothing', 'merge_group', TRUNK, '', 0, trunk_key, 'no'),
]
for what, event, ref, entry, want_rc, want_key, want_save in rows:
    rc, out, err = cache_of(event, ref, entry)
    if want_rc:
        check(what, rc != 0 and 'trunk' in err and 'save' not in out, '(exit %s, %r, %s)' % (rc, out, err))
        continue
    got = (rc, out.get('key'), out.get('save'), out.get('image'))
    check(what, got == (0, want_key, want_save, 'sn00-oracle:%s' % key), '(got %r)' % (got,))
    # the invariant every row keeps: a save under a key trunk restores comes only from a run on trunk, never from a
    # pull request, and any other save carries the branch prefix
    if out.get('save') == 'yes':
        check(what + ': its save is trunk\'s or the branch prefix\'s',
              (ref == TRUNK and event != 'pull_request' and out['key'] == trunk_key) or
              out['key'].startswith('sniff-oracle-branch-'))
rc, out, _ = cache_of('push', TRUNK, prefix='test-oracle')
check('the image name follows SNIFF_IMAGE_PREFIX', out.get('image') == 'test-oracle:%s' % key, '(%r)' % (out,))
rc, out, _ = cache_of('push', TRUNK, arch='ARM64')
check('the entry names the runner\'s architecture', out.get('key') == 'sniff-oracle-ARM64-%s' % key, '(%r)' % (out,))

# the workflow: the Linux job's cache steps read the script's answer, and its one save is gated on it
text = (root / '.github/workflows/ci.yml').read_text()
check('no combined cache action (it saves when the job ends)', re.search(r'uses:\s*actions/cache@', text) is None)
job = re.search(r'(?ms)^  linux:\n(.*?)(?=^  [a-z][a-z-]*:\n)', text)
steps = re.split(r'(?m)^      - ', job.group(1)) if job else []


def steps_using(action):
    return [s for s in steps if re.search(r'uses:\s*%s@' % re.escape(action), s)]


keyed = [s for s in steps if re.search(r'^id:\s*cache\b', s, re.M) or re.search(r'\n\s+id:\s*cache\b', s)]
check('the job asks the script for its entry',
      len(keyed) == 1 and 'tools/oracle-image-key --cache' in keyed[0] and 'GITHUB_OUTPUT' in keyed[0],
      '(%d steps)' % len(keyed))
restores = steps_using('actions/cache/restore')
check('it restores the script\'s entry',
      len(restores) == 1 and '${{ steps.cache.outputs.key }}' in restores[0] and re.search(r'id:\s*restore\b', restores[0]))
saves = [s for s in re.split(r'(?m)^      - ', text) if re.search(r'uses:\s*actions/cache/save@', s)]
check('the workflow saves in one place, the Linux job', len(saves) == 1 and len(steps_using('actions/cache/save')) == 1,
      '(%d saves)' % len(saves))
if saves:
    cond = re.search(r'(?m)^\s*if:\s*(.+)$', saves[0])
    cond = cond.group(1) if cond else ''
    check('the save runs only when the script said yes',
          "steps.cache.outputs.save == 'yes'" in cond and "steps.restore.outputs.cache-hit != 'true'" in cond
          and not re.search(r'always\(\)|failure\(\)|cancelled\(\)|\|\|', cond), '(if: %s)' % cond)
    check('the save writes the script\'s entry', '${{ steps.cache.outputs.key }}' in saves[0])
check('a dispatch can ask for a branch entry', re.search(r'(?m)^      branch-cache-entry:\n', text) is not None)

print('%s oracle-image-key (%d failed)' % ('FAIL' if failures else 'PASS', len(failures)))
raise SystemExit(1 if failures else 0)
