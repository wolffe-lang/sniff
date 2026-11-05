#!/usr/bin/env python3
"""Fetch only published binaries; bind downloads and staged bytes to archive pins."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-dir', type=Path)
    parser.add_argument('--out', type=Path, default=ROOT / '.wolf-bin')
    args = parser.parse_args()
    arch = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x86_64'}[platform.machine()]
    target = arch + ('-apple-darwin' if platform.system() == 'Darwin' else '-unknown-linux-gnu')
    pins = tomllib.loads((ROOT / 'wolf-toolchain.toml').read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    downloads = args.archive_dir or args.out / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    result = {'schema': 1, 'target': target, 'tools': {}}
    for name in ('wolf', 'lupin'):
        pin = pins[name]
        filename = f'{name}-{pin["version"]}-{target}.tar.gz'
        archive = downloads / filename
        if not archive.exists():
            url = f'https://github.com/{pin["repo"]}/releases/download/v{pin["version"]}/{filename}'
            subprocess.run(['curl', '-fLsS', '--retry', '3', url, '-o', str(archive)], check=True)
        first, second = digest(archive), digest(archive)
        if first != pin[target] or second != first:
            raise ValueError('archive digest mismatch: ' + filename)
        staged = args.out / f'{name}-{pin["version"]}-{target}'
        if staged.exists():
            shutil.rmtree(staged)
        # Archives have a single known root. Reject links/traversal before extraction.
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                if (not parts or parts[0] != staged.name or '..' in parts or
                        member.name.startswith('/') or not (member.isdir() or member.isfile())):
                    raise ValueError('unsafe archive member: ' + member.name)
            tar.extractall(args.out, filter='data')
        exe = staged / name
        version = subprocess.check_output([str(exe), '--version'], text=True).strip()
        if not version.startswith(f'{name} {pin["version"]} '):
            raise ValueError('unexpected binary version: ' + version)
        files = {str(p.relative_to(staged)): digest(p) for p in sorted(staged.rglob('*')) if p.is_file()}
        result['tools'][name] = {'archive_sha256_read_1': first, 'archive_sha256_read_2': second,
            'root': str(staged.resolve()), 'version': version, 'files': files}
    (args.out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS toolchain-digests target=' + target)


if __name__ == '__main__':
    main()
