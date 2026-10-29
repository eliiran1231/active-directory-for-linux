#!/usr/bin/env python3
"""Build pinned MIT client libraries privately; no install, credential or network operations.

Static linking alone does not isolate configuration/plugin discovery. The resulting
archives are a packaging component, never permission to enable authentication.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile

# Official upstream release, also mirrored unchanged by Debian as krb5_1.21.3.orig.tar.gz.
# https://web.mit.edu/kerberos/dist/krb5/1.21/krb5-1.21.3.tar.gz
PLUGIN_SOURCE_SHA256 = '82c786b99dbb6ef6361334e17288c9ac185e3cc6c1ca878909330dafd2f87968'
ARCHIVE_SHA256 = 'b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35'


def build(archive, output):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('MIT release archive hash mismatch.')
    if re.search(r'\s', str(output)):
        raise ValueError('Upstream makefiles require a build path without whitespace.')
    output.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as bundle:
        for member in bundle:
            parts = Path(member.name).parts
            if not parts or parts[0] != 'krb5-1.21.3' or '..' in parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unexpected MIT archive layout.')
        bundle.extractall(output, filter='data')
    source = output / 'krb5-1.21.3/src'
    # Deliberately modified MIT composition: use upstream's existing dummy
    # loader on Linux. No environment/config switch can restore dynamic loading.
    plugin_source = source / 'util/support/plugins.c'
    original = plugin_source.read_bytes()
    if hashlib.sha256(original).hexdigest() != PLUGIN_SOURCE_SHA256:
        raise ValueError('MIT plugin-loader source hash mismatch.')
    anchor = b'#include "k5-platform.h"\n#include "k5-plugin.h"\n'
    if original.count(anchor) != 1:
        raise ValueError('MIT plugin-loader patch context mismatch.')
    restriction = b"""/* ADFL modified private Linux build: runtime modules are unavailable.
 * Preserve built-in mechanisms; select the upstream dummy loader below. */
#if !defined(__linux__)
#error ADFL private MIT composition is reviewed only on Linux
#endif
#undef USE_DLOPEN
"""
    plugin_source.write_bytes(original.replace(anchor, anchor + restriction))
    # Never installed: legacy plugin paths name this private deployment boundary.
    # MIT still includes /etc/krb5.conf in compiled default profile paths even with
    # private sysconfdir; an explicit child KRB5_CONFIG remains mandatory.
    prefix = output / 'runtime'
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'CONFIG_SITE': '/dev/null',
           'CFLAGS': '-O2 -fPIC', 'CPPFLAGS': '', 'LDFLAGS': ''}
    def run(*command):
        subprocess.run(command, cwd=source, env=env, check=True)
    run('./configure', '--enable-static', '--disable-shared', '--disable-nls',
        '--with-crypto-impl=builtin', '--with-tls-impl=no', '--without-keyutils',
        '--without-libedit', '--disable-pkinit', '--prefix=' + str(prefix),
        '--libdir=' + str(prefix / 'lib'), '--sysconfdir=' + str(prefix / 'etc'))
    # Do not build clients, KDCs, administration programs, or run upstream auth tests.
    run('make', 'all-prerecurse')
    for directory in ['util', 'include', 'lib']:
        run('make', '-C', directory, '-j2')
    for name in ['libgssapi_krb5.a', 'libkrb5.a', 'libk5crypto.a', 'libkrb5support.a', 'libcom_err.a']:
        if not (source / 'lib' / name).is_file():
            raise ValueError('Missing private MIT library: ' + name)
    # Check actual archive references, not a descriptive capability flag.
    archives = [source / 'lib' / name for name in
                ['libgssapi_krb5.a', 'libkrb5.a', 'libk5crypto.a', 'libkrb5support.a', 'libcom_err.a']]
    symbols = subprocess.check_output(['nm', '-u', *map(str, archives)], text=True, env=env)
    if re.search(r'\bU\s+(?:dlopen|dlmopen|dlsym|dlclose|dlerror)(?:@\S+)?$', symbols, re.M):
        raise ValueError('Private MIT archives still reference a runtime module loader.')
    print('Built private MIT client archives:', source / 'lib')
    print('Compiled private configuration/plugin prefix:', prefix)
    print('No install/authentication. Modified MIT runtime module loading is unavailable; configuration policy remains required.')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    build(args.archive.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
