#!/usr/bin/env python3
"""Explicit opt-in: real authentication in a disposable network-none lab only."""
import argparse
import json
import subprocess
import uuid
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--authorize-disposable-lab', action='store_true', required=True)
p.add_argument('--docker-config', required=True)
p.add_argument('image')
a = p.parse_args()
name = 'adfl-kerberos-lab-' + uuid.uuid4().hex
cmd = ['docker', '--config', a.docker_config]
def call(*args, **kw):
    return subprocess.run(cmd + list(args), check=True, timeout=30, **kw)
try:
    call('create', '--name', name, '--network', 'none', '--read-only', '--user', '65534:65534',
         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128',
         '--memory', '512m', '--cpus', '2', '--tmpfs',
         '/run/adfl:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=65534,gid=65534', a.image,
         stdout=subprocess.DEVNULL)
    state = json.loads(call('inspect', name, capture_output=True, text=True).stdout)[0]
    h = state['HostConfig']
    if (h['NetworkMode'] != 'none' or not h['ReadonlyRootfs'] or h['Privileged'] or h['Binds']
            or h['PortBindings'] or h.get('Mounts') or h.get('Devices') or h.get('DeviceRequests')
            or h.get('VolumesFrom') or state['Config'].get('Volumes')
            or any(mount['Type'] != 'tmpfs' or mount['Destination'] != '/run/adfl'
                   for mount in state.get('Mounts', []))
            or h.get('Tmpfs') != {'/run/adfl': 'rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=65534,gid=65534'}
            or h['CapDrop'] != ['ALL']
            or 'no-new-privileges' not in h['SecurityOpt']
            or state['Config']['User'] != '65534:65534'):
        raise RuntimeError('Isolation verification failed; refusing to start.')
    call('start', name, stdout=subprocess.DEVNULL)
    result = subprocess.run(cmd + ['wait', name], check=True, timeout=90, capture_output=True, text=True)
    # run-inside/harness emit only fixed assertions and numeric diagnostics.
    call('logs', name)
    if result.stdout.strip() != '0':
        raise RuntimeError('Isolated lab did not pass.')
finally:
    # Forced removal kills only this named lab; tmpfs keys/caches are destroyed.
    call('rm', '--force', '--volumes', name, stdout=subprocess.DEVNULL)
    remaining = call('ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}', capture_output=True, text=True)
    if remaining.stdout.strip():
        raise RuntimeError('Lab container teardown not verified.')
    print('Verified lab container teardown; no credential volume or host mount used.')
