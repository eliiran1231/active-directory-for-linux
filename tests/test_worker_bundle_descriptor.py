#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / 'src/AdForLinux.DirectoryServices.Native/packaging/describe-worker-bundle.py'
SPEC = importlib.util.spec_from_file_location('describe_worker_bundle', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WorkerBundleDescriptorTests(unittest.TestCase):
    def test_rejects_missing_rid_runtime_asset_then_accepts_complete_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roles = {'Dotnet': 'dotnet/dotnet', 'HostAssembly': 'host/App.dll',
                     'Supervisor': 'host/worker.so', 'NativeBridge': 'host/bridge.so'}
            for relative in [*roles.values(), 'host/Dependency.dll',
                             'host/NativeDependency.so', 'host/fr/Dependency.resources.dll']:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'offline-fixture')
            deps = {
                'runtimeTarget': {'name': '.NETCoreApp,Version=v8.0'},
                'targets': {'.NETCoreApp,Version=v8.0': {
                    'App/1.0.0': {'runtime': {'App.dll': {}}},
                    'Dependency/1.0.0': {
                        'runtime': {'lib/net8.0/Dependency.dll': {}},
                        'native': {'lib/net8.0/NativeDependency.so': {}},
                        'resources': {'lib/net8.0/fr/Dependency.resources.dll':
                                      {'locale': 'fr'}},
                        'runtimeTargets': {
                            'runtimes/linux/lib/net8.0/Dependency.dll':
                                {'rid': 'linux', 'assetType': 'runtime'},
                            'runtimes/win/lib/net8.0/Dependency.dll':
                                {'rid': 'win', 'assetType': 'runtime'}
                        }
                    }
                }}
            }
            (root / 'host/App.deps.json').write_text(json.dumps(deps), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'dependency asset is missing'):
                MODULE.describe(root, 'test-v1', roles)
            self.assertFalse((root / 'manifest.json').exists())
            runtime = root / 'host/runtimes/linux/lib/net8.0/Dependency.dll'
            runtime.parent.mkdir(parents=True)
            runtime.write_bytes(b'linux-runtime')
            with self.assertRaisesRegex(ValueError, 'dependency asset is missing'):
                MODULE.describe(root, 'test-v1', roles)
            self.assertFalse((root / 'manifest.json').exists())
            runtime = root / 'host/runtimes/win/lib/net8.0/Dependency.dll'
            runtime.parent.mkdir(parents=True)
            runtime.write_bytes(b'windows-runtime')
            MODULE.describe(root, 'test-v1', roles)
            manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
            self.assertIn('host/runtimes/linux/lib/net8.0/Dependency.dll',
                          {artifact['Path'] for artifact in manifest['Artifacts']})

    def test_rejects_missing_dependency_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'host').mkdir(parents=True)
            (root / 'host/App.dll').write_bytes(b'offline-fixture')
            with self.assertRaisesRegex(ValueError, 'dependency graph is missing'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')

    def test_rejects_missing_ordinary_native_and_resource_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / 'host/App.dll'
            host.parent.mkdir(parents=True)
            host.write_bytes(b'offline-fixture')
            deps = {'runtimeTarget': {'name': 'target'}, 'targets': {'target': {
                'Dependency/1.0.0': {
                    'native': {'lib/net8.0/NativeDependency.so': {}},
                    'resources': {'lib/net8.0/fr/Dependency.resources.dll':
                                  {'locale': 'fr'}}
                }
            }}}
            (root / 'host/App.deps.json').write_text(json.dumps(deps), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'dependency asset is missing'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')
            (root / 'host/NativeDependency.so').write_bytes(b'native')
            with self.assertRaisesRegex(ValueError, 'dependency asset is missing'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')
            resource = root / 'host/fr/Dependency.resources.dll'
            resource.parent.mkdir()
            resource.write_bytes(b'resource')
            MODULE.require_managed_runtime_assets(root, 'host/App.dll')

    def test_rejects_dependency_paths_outside_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / 'host/App.dll'
            host.parent.mkdir(parents=True)
            host.write_bytes(b'offline-fixture')
            deps = {'runtimeTarget': {'name': 'target'}, 'targets': {'target': {
                'Bad/1.0.0': {'runtimeTargets': {
                    '../../outside.dll': {'assetType': 'runtime', 'rid': 'linux'}
                }}
            }}}
            (root / 'host/App.deps.json').write_text(json.dumps(deps), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unsafe asset path'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')

    def test_rejects_resource_locale_traversal_and_malformed_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / 'host/App.dll'
            host.parent.mkdir(parents=True)
            host.write_bytes(b'offline-fixture')
            deps_path = root / 'host/App.deps.json'
            deps = {'runtimeTarget': {'name': 'target'}, 'targets': {'target': {
                'Bad/1.0.0': {'resources': {
                    'lib/net8.0/Secret.resources.dll': {'locale': '..'}
                }}
            }}}
            deps_path.write_text(json.dumps(deps), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'dependency graph is invalid'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')
            deps['targets']['target'] = []
            deps_path.write_text(json.dumps(deps), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'dependency graph is invalid'):
                MODULE.require_managed_runtime_assets(root, 'host/App.dll')


if __name__ == '__main__':
    unittest.main()
