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
a = p.parse_args()
if any((a.dotnet, a.worker_demo, a.supervisor, a.lab_native)) and not all((a.dotnet, a.worker_demo, a.supervisor, a.lab_native)):
    p.error('Managed lab requires dotnet, worker-demo, supervisor and lab-native together.')
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
(root / 'Dockerfile').write_text('FROM scratch\nCOPY --chmod=755 . /\nUSER 65534:65534\nENTRYPOINT ["/bin/sh", "/run-inside.sh"]\n')
for directory in [root, *(path for path in root.rglob('*') if path.is_dir())]:
    directory.chmod(0o755)
print('Prepared scratch image context; no credentials or container created.')
