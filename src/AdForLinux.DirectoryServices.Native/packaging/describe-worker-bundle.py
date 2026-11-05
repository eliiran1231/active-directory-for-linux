#!/usr/bin/env python3
"""Describe an already assembled versioned worker bundle; never install or execute it.

The administrator must install the complete version immutably. This inventory
identifies bytes, not their publisher or their authentication capability.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def require_managed_runtime_assets(root, host_role):
    """Reject inventories that cannot satisfy their managed host's deps graph."""
    host = root / host_role
    deps = host.with_suffix('.deps.json')
    if not deps.is_file():
        raise ValueError('Managed host dependency graph is missing.')
    try:
        document = json.loads(deps.read_text(encoding='utf-8'))
        target_name = document['runtimeTarget']['name']
        libraries = document['targets'][target_name]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('Managed host dependency graph is invalid.') from error
    if not isinstance(libraries, dict):
        raise ValueError('Managed host dependency graph is invalid.')
    required = set()
    def relative_asset(value):
        if not isinstance(value, str):
            raise ValueError('Managed host dependency graph is invalid.')
        relative = PurePosixPath(value)
        if relative.is_absolute() or not relative.parts or any(part in {'', '.', '..'} or
                not re.fullmatch(r'[A-Za-z0-9._-]+', part) for part in relative.parts):
            raise ValueError('Managed host dependency graph contains an unsafe asset path.')
        return relative
    for library in libraries.values():
        if not isinstance(library, dict):
            raise ValueError('Managed host dependency graph is invalid.')
        runtime = library.get('runtime', {})
        native = library.get('native', {})
        resources = library.get('resources', {})
        targets = library.get('runtimeTargets', {})
        if any(not isinstance(section, dict) for section in (runtime, native, resources, targets)):
            raise ValueError('Managed host dependency graph is invalid.')
        # Framework-dependent publish output flattens ordinary managed runtime
        # and native assets beside the host. Satellite resources retain their
        # locale directory, while RID assets retain their complete package path.
        required.update(host.parent / relative_asset(value).name for value in (*runtime, *native))
        for value, metadata in resources.items():
            if not isinstance(metadata, dict):
                raise ValueError('Managed host dependency graph is invalid.')
            locale = metadata.get('locale')
            if (not isinstance(locale, str) or locale in {'.', '..'} or
                    not re.fullmatch(r'[A-Za-z0-9._-]+', locale)):
                raise ValueError('Managed host dependency graph is invalid.')
            required.add(host.parent / locale / relative_asset(value).name)
        for value, metadata in targets.items():
            if not isinstance(metadata, dict):
                raise ValueError('Managed host dependency graph is invalid.')
            if metadata.get('assetType') in {'runtime', 'native', 'resources'}:
                relative = relative_asset(value)
                required.add(host.parent / Path(*relative.parts))
    if any(not path.is_file() for path in required):
        raise ValueError('Managed host dependency asset is missing from the bundle.')


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
    require_managed_runtime_assets(root, roles['HostAssembly'])
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
