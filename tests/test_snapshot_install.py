"""Package installation must select the dated archive."""
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
case "$*" in
  '--snapshot 20261106T000000Z install -y --no-install-recommends libc6-dev') exit 0 ;;
  *) printf '%s\\n' 'FAIL snapshot-install selected a live archive' >&2; exit 1 ;;
esac
''')
    apt.chmod(0o755)
    env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'])
    result = subprocess.run(['sh', str(root / 'ci/snapshot-install.sh'), '20261106T000000Z', 'libc6-dev'],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
print('PASS snapshot-install uses the dated archive')
