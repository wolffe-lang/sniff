"""A caller may isolate oracle image names."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
tmp = root / 'target' / 'tmp'
tmp.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=tmp) as work:
    work = Path(work)
    engine, capture = work / 'engine', work / 'capture'
    engine.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$CAPTURE"\nexit 1\n')
    engine.chmod(0o755)
    env = dict(os.environ, SNIFF_ENGINE=str(engine), SNIFF_IMAGE_PREFIX='test-oracle', CAPTURE=str(capture))
    result = subprocess.run(['bash', str(root / 'tools/in-container')], cwd=root, env=env, text=True, capture_output=True)
    assert result.returncode != 0, 'the fake engine must stop the build'
    assert ' -t test-oracle:' in capture.read_text(), capture.read_text()
print('PASS oracle image prefix')
