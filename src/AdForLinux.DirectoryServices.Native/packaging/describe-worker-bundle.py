#!/usr/bin/env python3
"""Describe an already assembled versioned worker bundle; never install or execute it.

The administrator must install the complete version immutably. This inventory
identifies bytes, not their publisher or their authentication capability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def describe(root, version, roles):
    root = root.resolve(strict=True)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', version):
        raise ValueError('Invalid bundle version token.')
    target = root / 'manifest.json'
    if target.exists():
        raise ValueError('A versioned bundle manifest already exists.')
    artifacts = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Bundle symlinks are not supported.')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('Only regular artifact files are supported.')
        relative = path.relative_to(root).as_posix()
        if not all(part not in {'.', '..'} and re.fullmatch(r'[A-Za-z0-9._-]+', part) for part in relative.split('/')):
            raise ValueError('Artifact path is outside the supported portable shape.')
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        artifacts.append({'Path': relative, 'Sha256': digest})
    names = {item['Path'] for item in artifacts}
    if any(value not in names for value in roles.values()):
        raise ValueError('Every role must name an inventoried artifact.')
    manifest = {'FormatVersion': 1, 'Version': version, 'Roles': roles, 'Artifacts': artifacts}
    with target.open('x') as output:
        json.dump(manifest, output, indent=2)
        output.write('\n')
    print('Created worker bundle inventory:', len(artifacts), 'artifacts; no admission or execution.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--supervisor', required=True)
    parser.add_argument('--bridge', required=True)
    args = parser.parse_args()
    describe(args.bundle, args.version, {'Dotnet': args.dotnet, 'HostAssembly': args.host,
        'Supervisor': args.supervisor, 'NativeBridge': args.bridge})


if __name__ == '__main__':
    main()
