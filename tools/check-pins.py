#!/usr/bin/env python3
"""Check pin metadata consistency before downloading or executing anything."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    pins = tomllib.loads((ROOT / 'wolf-toolchain.toml').read_text())
    first = json.loads((ROOT / 'tests/pin-read-1.json').read_text())
    second = json.loads((ROOT / 'tests/pin-read-2.json').read_text())
    if first != second: raise ValueError('independent release metadata reads differ')
    for name in ('wolf', 'lupin'):
        pin = pins[name]
        if first[name]['tag'] != 'v' + pin['version']:
            raise ValueError('release tag mismatch: ' + name)
        assets = {a['name']: a for a in first[name]['assets']}
        for target in ('aarch64-apple-darwin', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
            asset = assets[f'{name}-{pin["version"]}-{target}.tar.gz']
            if asset['digest'] != 'sha256:' + pin[target]:
                raise ValueError('archive pin differs from release: ' + name + '/' + target)
    oracle = tomllib.loads((ROOT / 'sniff-oracle.toml').read_text())
    for file, key in [('ci/packages.txt', 'packages_sha256'),
                      ('ci/oracle-binaries.lock', 'binary_manifest_sha256')]:
        if hashlib.sha256((ROOT / file).read_bytes()).hexdigest() != oracle['container'][key]:
            raise ValueError('oracle metadata digest mismatch: ' + file)
    base = (ROOT / 'ci/oracle.Containerfile').read_text().splitlines()[0].removeprefix('FROM ')
    if base != oracle['container']['base']: raise ValueError('container base differs from pin')
    c = oracle['container']
    if (ROOT / 'ci/apt-snapshot').read_text().strip() != c['apt_snapshot']:
        raise ValueError('snapshot differs from pin')
    content = (ROOT / 'ci/oracle.Containerfile').read_text()
    filename = 'ca-certificates_%s_all.deb' % c['bootstrap_ca_version']
    url = 'https://snapshot.ubuntu.com/ubuntu/%s/pool/main/c/ca-certificates/%s' % (c['apt_snapshot'], filename)
    if c['bootstrap_ca_source'] != url:
        raise ValueError('certificate bootstrap source differs from pin')
    # The image build fetches nothing before apt: the bootstrap is in the tree, by digest.
    if any(line.split()[:1] == ['ADD'] for line in content.splitlines()):
        raise ValueError('image recipe fetches with ADD; keep the file in the tree by digest')
    vendored = ROOT / 'ci/bootstrap' / filename
    if not vendored.is_file():
        raise ValueError('certificate bootstrap not in the tree: ci/bootstrap/' + filename)
    for _ in range(2):
        if hashlib.sha256(vendored.read_bytes()).hexdigest() != c['bootstrap_ca_sha256']:
            raise ValueError('certificate bootstrap digest differs from pin')
    if ('COPY ci/bootstrap/%s /pins/bootstrap-ca.deb' % filename) not in content.splitlines():
        raise ValueError('certificate bootstrap copy differs from pin')
    if ('printf "%%s  %%s\\n" %s /pins/bootstrap-ca.deb | sha256sum -c -' % c['bootstrap_ca_sha256']) not in content:
        raise ValueError('certificate bootstrap check differs from pin')
    if 'ca-certificates=%s' % c['bootstrap_ca_version'] not in (ROOT / 'ci/packages.txt').read_text().splitlines():
        raise ValueError('certificate bootstrap differs from package lock')
    manifest = (ROOT / 'ci/oracle-binaries.lock').read_text()
    for name in ('gdb', 'llvm_dwarfdump', 'readelf', 'gcc', 'clang'):
        if oracle[name]['sha256'] not in manifest:
            raise ValueError('binary manifest omits ' + name)
    print('PASS pin-metadata toolchains=2 oracle_binaries=5')


if __name__ == '__main__':
    try: main()
    except (ValueError, KeyError, OSError) as error:
        print('FAIL pin-metadata ' + str(error))
        raise SystemExit(1)
