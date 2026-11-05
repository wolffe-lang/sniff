#!/usr/bin/env python3
"""Execute and identify the symbol oracle before any reader comparison."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def verify(platform, pins):
    key = 'llvm_nm_macos' if platform == 'macos' else 'readelf'
    pin = tomllib.loads(Path(pins).read_text())[key]
    command = pin['command']
    binary = shutil.which(command)
    # Prefer PATH deliberately: an injected or upgraded tool must be rejected,
    # not silently ignored. SDK fallback is only for a missing PATH command.
    if binary is None and platform == 'macos':
        xcrun = shutil.which('xcrun')
        if xcrun:
            result = subprocess.run([xcrun, '--find', command], capture_output=True,
                                    text=True, timeout=10)
            if result.returncode == 0:
                binary = result.stdout.strip()
    if not binary:
        raise ValueError('symbol-oracle-not-found: ' + command)
    binary = Path(binary).resolve(strict=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    try:
        version = subprocess.run([str(binary), '--version'], capture_output=True,
                                 text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('symbol-oracle-execution: ' + str(error)) from error
    if version.returncode != 0 or version.stderr:
        raise ValueError('symbol-oracle-execution: --version did not succeed cleanly')
    if pin['version_line'] not in version.stdout.splitlines():
        raise ValueError('symbol-oracle-version-mismatch: expected ' + pin['version_line'])
    after = hashlib.sha256(binary.read_bytes()).hexdigest()
    if before != pin['sha256'] or after != pin['sha256']:
        raise ValueError('symbol-oracle-digest-mismatch: ' + command)
    return binary, after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=('linux', 'macos'))
    parser.add_argument('--pins', type=Path, default=ROOT / 'sniff-oracle.toml')
    args = parser.parse_args()
    try:
        binary, digest = verify(args.platform, args.pins)
        print('PASS symbol-oracle-pin platform=' + args.platform
              + ' binary=' + str(binary) + ' sha256=' + digest)
        return 0
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print('FAIL ' + str(error))
        return 1


if __name__ == '__main__':
    sys.exit(main())
