"""Offline negative admission checks. Never supplies a cache or directory endpoint."""
import argparse
import json
import os
import platform
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--dotnet', required=True)
p.add_argument('--assembly', required=True)
a = p.parse_args()
root = Path(__file__).resolve().parent.parent
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
environment = dict(os.environ, ADFL_OFFLINE_TESTS='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false',
                   DOTNET_CLI_TELEMETRY_OPTOUT='1')
with tempfile.TemporaryDirectory(prefix='adfl-ad-preflight-') as directory:
    missing = str(Path(directory) / 'absent.json')
    for mode, revision in [('--ad-kerberos-preflight', commit), ('--ad-kerberos-run', commit),
                           ('--ad-kerberos-run', 'invalid-revision-do-not-echo')]:
        run = subprocess.run([a.dotnet, a.assembly, mode, missing, revision], cwd=root,
                             env=environment, capture_output=True, text=True, timeout=30)
        assert run.returncode == 2, (mode, run.returncode)
        report = json.loads(run.stdout)
        assert report['status'] == 'MISSING_PREREQUISITES'
        assert report['backend'] == 'restricted-linux-owned-kerberos'
        expected = ('source-revision' if revision != commit else
                    'configuration' if platform.system() == 'Linux' else 'linux-runner-required')
        assert report['stage'] == expected, report['stage']
        assert missing not in run.stdout and 'invalid-revision-do-not-echo' not in run.stdout
        assert 'PASSED' not in run.stdout and not run.stderr
print('PASS: explicit AD entrypoints refuse missing prerequisites without credentials, authentication or fallback.')
