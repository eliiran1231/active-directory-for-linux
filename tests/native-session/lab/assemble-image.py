#!/usr/bin/env python3
"""Prepare (never run) a scratch lab image from locally built, trusted binaries."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('servers', type=Path)
p.add_argument('harness', type=Path)
p.add_argument('profile', type=Path, help='Restricted profile emitted by the production generator in worker-demo')
p.add_argument('output', type=Path)
p.add_argument('--dotnet', type=Path, help='Existing trusted .NET root; copies runtime only, never SDK/user state')
p.add_argument('--worker-demo', type=Path)
p.add_argument('--supervisor', type=Path)
p.add_argument('--lab-native', type=Path)
p.add_argument('--production-host', type=Path)
p.add_argument('--restricted-native', type=Path)
p.add_argument('--composition', type=Path)
a = p.parse_args()
if any((a.dotnet, a.worker_demo, a.supervisor, a.lab_native)) and not all((a.dotnet, a.worker_demo, a.supervisor, a.lab_native)):
    p.error('Managed lab requires dotnet, worker-demo, supervisor and lab-native together.')
if any((a.production_host, a.restricted_native, a.composition)) and not all((a.production_host, a.restricted_native, a.composition, a.dotnet)):
    p.error('Public activation lab requires production-host, restricted-native, composition and managed lab.')
root = a.output.resolve()
root.mkdir(exist_ok=False)
def copy(source, destination):
    target = root / destination.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)
def binary(source, destination):
    copy(source, destination)
    # Inputs are locally compiled trusted programs, never arbitrary uploaded ELF.
    dependencies = subprocess.check_output(['ldd', str(source)], text=True)
    for line in dependencies.splitlines():
        match = re.search(r'(?:=>\s*)?(/\S+)', line)
        if match:
            copy(match[1], match[1])
mit = a.servers.resolve() / 'krb5-1.21.3/src'
for name, relative in [('krb5kdc', 'kdc/krb5kdc'), ('kdb5_util', 'kadmin/dbutil/kdb5_util'),
                       ('kadmin.local', 'kadmin/cli/kadmin.local'), ('kinit', 'clients/kinit/kinit')]:
    binary(mit / relative, '/bin/' + name)
binary(a.servers.resolve() / 'openldap-OPENLDAP_REL_ENG_2_6_10/servers/slapd/slapd', '/bin/slapd')
binary(a.harness.resolve(), '/bin/real-bind')
for name in ['dash', 'cat', 'id', 'od', 'tr', 'sleep', 'mkdir']:
    binary('/bin/' + name, '/bin/' + name)
(root / 'bin/sh').symlink_to('dash')
source = Path(__file__).resolve().parent
subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                str(source / 'isolation-probe.c'), '-o', str(root / 'probe')], check=True)
(root / 'probe').chmod(0o755)
copy(source / 'run-inside.sh', '/run-inside.sh')
copy(a.profile.resolve(), '/etc/lab-krb5.conf')
(root / 'etc').mkdir(exist_ok=True)
copy(a.servers.resolve() / 'openldap-OPENLDAP_REL_ENG_2_6_10/servers/slapd/schema/core.schema', '/etc/core.schema')
copy(a.servers.resolve() / 'openldap-OPENLDAP_REL_ENG_2_6_10/servers/slapd/schema/cosine.schema', '/etc/cosine.schema')
(root / 'etc/hosts').write_text('127.0.0.1 localhost\n')
(root / 'etc/passwd').write_text('nobody:x:65534:65534::/run/adfl:/bin/sh\n')
(root / 'etc/group').write_text('nogroup:x:65534:\n')
if a.dotnet:
    # Copy only reviewed application output and a known installed .NET8 runtime.
    dotnet = a.dotnet.resolve()
    binary(dotnet / 'dotnet', '/dotnet/dotnet')
    # .NET crypto loads OpenSSL lazily; ldd of its shim cannot discover this.
    binary('/lib/x86_64-linux-gnu/libssl.so.3', '/lib/x86_64-linux-gnu/libssl.so.3')
    for relative in ['host/fxr/8.0.33', 'shared/Microsoft.NETCore.App/8.0.33']:
        directory = dotnet / relative
        if not directory.is_dir():
            raise ValueError('Expected .NET8.0.33 runtime is unavailable.')
        for path in directory.rglob('*'):
            if path.is_file():
                destination = '/dotnet/' + str(path.relative_to(dotnet))
                if path.suffix == '.so': binary(path, destination)
                else: copy(path, destination)
    for path in a.worker_demo.resolve().rglob('*'):
        if path.is_file() and path.suffix in {'.dll', '.json'}:
            copy(path, '/lab/' + str(path.relative_to(a.worker_demo.resolve())))
    runtime = root / 'lab/AdForLinux.NativeWorkerDemo.runtimeconfig.json'
    config = json.loads(runtime.read_text())
    config['runtimeOptions'].setdefault('configProperties', {})['System.Globalization.Invariant'] = True
    runtime.write_text(json.dumps(config))
    binary(a.supervisor.resolve(), '/lab/libadfl_worker.so')
    binary(a.lab_native.resolve(), '/lab/libadfl_lab_native.so')
    bundle = root / 'bundle/lab-v1'
    bundle.mkdir(parents=True)
    (root / 'dotnet').rename(bundle / 'dotnet')
    (root / 'lab').rename(bundle / 'host')
    (root / 'dotnet').symlink_to('bundle/lab-v1/dotnet')
    (root / 'lab').symlink_to('bundle/lab-v1/host')
    describe = source.parents[2] / 'src/AdForLinux.DirectoryServices.Native/packaging/describe-worker-bundle.py'
    subprocess.run(['python3', str(describe), str(bundle), '--version', 'lab-v1',
        '--dotnet', 'dotnet/dotnet', '--host', 'host/AdForLinux.NativeWorkerDemo.dll',
        '--supervisor', 'host/libadfl_worker.so', '--bridge', 'host/libadfl_lab_native.so'], check=True)
    if a.production_host:
        production = root / 'bundle/production-v1'
        shutil.copytree(bundle, production)
        (production / 'manifest.json').unlink()
        for path in a.production_host.resolve().rglob('*'):
            if path.is_file() and path.suffix in {'.dll', '.json'}:
                copy(path, '/bundle/production-v1/host/' + str(path.relative_to(a.production_host.resolve())))
        runtime = production / 'host/AdForLinux.NativeHost.runtimeconfig.json'
        config = json.loads(runtime.read_text())
        config['runtimeOptions'].setdefault('configProperties', {})['System.Globalization.Invariant'] = True
        runtime.write_text(json.dumps(config))
        # Exact dedicated bridge bytes; no test bridge is a production role.
        (production / 'host/libadfl_lab_native.so').unlink()
        binary(a.restricted_native.resolve(), '/bundle/production-v1/host/libadfl_restricted.so')
        copy(a.composition.resolve(), '/bundle/production-v1/composition.json')
        subprocess.run(['python3', str(describe), str(production), '--version', 'production-v1',
            '--dotnet', 'dotnet/dotnet', '--host', 'host/AdForLinux.NativeHost.dll',
            '--supervisor', 'host/libadfl_worker.so', '--bridge', 'host/libadfl_restricted.so'], check=True)
    # Tiny, non-executable negative inventories; no credential or server state.
    import hashlib
    for kind in ['digest', 'extra', 'symlink']:
        bad = root / 'admission-reject' / kind
        bad.mkdir(parents=True)
        artifacts = []
        for name in ['dotnet', 'host.dll', 'worker.so', 'bridge.so']:
            (bad / name).write_bytes(b'harmless admission fixture')
            artifacts.append({'Path': name, 'Sha256': hashlib.sha256(b'harmless admission fixture').hexdigest()})
        if kind == 'digest': artifacts[0]['Sha256'] = '0' * 64
        if kind == 'extra': (bad / 'unexpected').write_text('not inventoried')
        if kind == 'symlink':
            (bad / 'bridge.so').unlink()
            (bad / 'bridge.so').symlink_to('worker.so')
        (bad / 'manifest.json').write_text(json.dumps({'FormatVersion': 1, 'Version': kind,
            'Roles': {'Dotnet': 'dotnet', 'HostAssembly': 'host.dll', 'Supervisor': 'worker.so', 'NativeBridge': 'bridge.so'},
            'Artifacts': artifacts}))


(root / 'Dockerfile').write_text('FROM scratch\nCOPY --chmod=755 . /\nUSER 65534:65534\nENTRYPOINT ["/bin/sh", "/run-inside.sh"]\n')
for directory in [root, *(path for path in root.rglob('*') if path.is_dir())]:
    directory.chmod(0o755)
print('Prepared scratch image context; no credentials or container created.')
