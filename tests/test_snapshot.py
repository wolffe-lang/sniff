"""Snapshot index failure must stop the oracle build."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
tmp = root / 'target' / 'tmp'
tmp.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=tmp) as work:
    work = Path(work)
    apt = work / 'apt-get'
    apt.write_text('''#!/bin/sh
case " $* " in
  *" APT::Update::Error-Mode=any "*" --snapshot 20261106T000000Z "*) exit 100 ;;
  *) exit 0 ;;
esac
''')
    apt.chmod(0o755)
    env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'])
    result = subprocess.run(['sh', str(root / 'ci/snapshot-update.sh')], env=env, text=True, capture_output=True)
    assert result.returncode != 0, 'failed snapshot was ignored or not selected'
    assert 'FAIL oracle-snapshot' in result.stderr, result.stderr
print('PASS oracle-snapshot index failure')
