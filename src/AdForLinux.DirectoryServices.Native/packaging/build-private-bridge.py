#!/usr/bin/env python3
"""Build a private static LDAP/Cyrus bridge; leave all authentication gates closed.

No downloads/installations/authentication. MIT remains a system build dependency;
this is a verifiable composition increment, not a complete deployment package.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[3]
# https://github.com/openldap/openldap/archive/refs/tags/OPENLDAP_REL_ENG_2_6_10.tar.gz
OPENLDAP_SHA256 = '1794dbb7225516ae5fb21f3f9a19c0181f0ce33e9d0218e0f623b0a386578181'
OPENLDAP_ROOT = 'openldap-OPENLDAP_REL_ENG_2_6_10'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cyrus_archive', type=Path)
    parser.add_argument('openldap_archive', type=Path, help='Official GitHub OPENLDAP_REL_ENG_2_6_10 tag archive')
    parser.add_argument('output', type=Path, help='New build directory without whitespace')
    args = parser.parse_args()
    output = args.output.resolve()
    if re.search(r'\s', str(output)):
        parser.error('Upstream makefiles require a build path without whitespace.')
    if hashlib.sha256(args.openldap_archive.read_bytes()).hexdigest() != OPENLDAP_SHA256:
        parser.error('OpenLDAP source archive hash mismatch.')
    output.mkdir(parents=True, exist_ok=False)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('private_cyrus', Path(__file__).with_name('build-private-cyrus.py'))
    cyrus = importlib.util.module_from_spec(spec); spec.loader.exec_module(cyrus)
    sasl_archive = cyrus.build(args.cyrus_archive.resolve(), output / 'cyrus')
    sasl_source = sasl_archive.parents[2]
    includes = output / 'include/sasl'; includes.mkdir(parents=True)
    for header in (sasl_source / 'include').glob('*.h'):
        shutil.copyfile(header, includes / header.name)
    with tarfile.open(args.openldap_archive) as bundle:
        for member in bundle:
            parts = Path(member.name).parts
            if not parts or parts[0] != OPENLDAP_ROOT or '..' in parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unexpected OpenLDAP archive layout.')
        bundle.extractall(output, filter='data')
    source = output / OPENLDAP_ROOT
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'CONFIG_SITE': '/dev/null',
           'CFLAGS': '-O2 -fPIC', 'CPPFLAGS': '-I' + str(includes.parent),
           'LDFLAGS': '-L' + str(sasl_archive.parent),
           'LIBS': '-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lresolv'}
    def run(*command, capture=False):
        return subprocess.run(command, cwd=source, env=env, check=True,
                              stdout=subprocess.PIPE if capture else None, text=True).stdout
    if run('pkg-config', '--modversion', 'krb5-gssapi', capture=True).strip() != '1.21.3':
        raise ValueError('Only the reviewed MIT 1.21.3 build dependency is supported.')
    run('./configure', '--enable-static', '--disable-shared', '--disable-slapd',
        '--disable-balancer', '--disable-dynamic', '--without-tls', '--without-systemd',
        '--without-fetch', '--with-cyrus-sasl', '--with-threads=posix')
    config = (source / 'include/portable.h').read_text()
    macros = set(re.findall(r'^#define[ \t]+(\w+)(?:[ \t]|$)', config, re.M))
    if 'HAVE_CYRUS_SASL' not in macros or {'HAVE_TLS', 'HAVE_OPENSSL', 'HAVE_GNUTLS'} & macros:
        raise ValueError('Unexpected SASL/TLS build profile.')
    for directory in ['include', 'libraries/liblutil', 'libraries/liblber', 'libraries/libldap']:
        run('make', '-C', directory, '-j2')
    native = ROOT / 'src/AdForLinux.DirectoryServices.Native'
    sources = [native / name for name in ['adfl_controls.c', 'adfl_native.c', 'adfl_system.c',
               'adfl_dispatch.c', 'adfl_search_system.c', 'adfl_conversation.c']]
    exports = output / 'bridge.exports'
    exports.write_text('{ global: adfl_*; local: *; };\n')
    bridge = output / 'libadfl_native.so'
    mit_flags = shlex.split(run('pkg-config', '--cflags', '--libs', 'krb5-gssapi', 'krb5', capture=True))
    run('cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O2', '-fPIC',
        '-fvisibility=hidden', '-DADFL_REVIEWED_MIT_1_21_3', '-shared',
        '-I' + str(native), '-I' + str(source / 'include'), '-I' + str(includes.parent),
        *map(str, sources), str(source / 'libraries/libldap/.libs/libldap.a'),
        str(source / 'libraries/liblber/.libs/liblber.a'), str(sasl_archive),
        *mit_flags, '-lresolv', '-pthread', '-Wl,--exclude-libs,ALL',
        '-Wl,--version-script=' + str(exports), '-Wl,-z,defs', '-o', str(bridge))
    dynamic = run('readelf', '-d', str(bridge), capture=True)
    if re.search(r'Shared library: \[(?:libldap|liblber|libsasl)', dynamic):
        raise ValueError('Bridge still depends on host LDAP/Cyrus libraries.')
    symbols = run('nm', '-D', '--defined-only', str(bridge), capture=True)
    if any(line.split()[-1].startswith(('sasl_', 'ldap_', 'ber_', '_sasl_')) for line in symbols.splitlines()):
        raise ValueError('Private LDAP/Cyrus symbols escaped the bridge.')
    local_symbols = run('nm', '--defined-only', str(bridge), capture=True)
    if not re.search(r'\bt\s+gssapiv2_client_plug_init\b', local_symbols):
        raise ValueError('Private static GSSAPI plugin was not linked locally.')
    print('Built private LDAP/Cyrus bridge:', bridge)
    print('SHA256:', hashlib.sha256(bridge.read_bytes()).hexdigest())
    print('System MIT/config/plugin closure remains unproven; authentication gates remain false.')


if __name__ == '__main__':
    main()
