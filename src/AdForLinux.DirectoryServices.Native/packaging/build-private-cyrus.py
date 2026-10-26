#!/usr/bin/env python3
"""Build the pinned guarded static Cyrus component offline, never install it.

This component is NOT an authentication-enablement certificate. MIT/OpenLDAP,
loader/config/plugin closure and credential-source policy require separate proof.
Input is the official release archive; no downloads or host configuration writes.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile

ARCHIVE_SHA256 = '7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c'
SOURCE_SHA256 = '732d311438c588ece922b866aa74d5833734cddedc5a8a1954ef737fa0e6cac0'
ROOT = Path(__file__).resolve().parents[3]
PATCH = ROOT / 'src/AdForLinux.DirectoryServices.Native/patches/cyrus-sasl-2.1.28-explicit-credential.patch'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(archive, output):
    if digest(archive) != ARCHIVE_SHA256:
        raise ValueError('Only the pinned official Cyrus 2.1.28 release archive is supported.')
    # A new directory prevents accidental reuse of generated configuration/objects.
    output.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as bundle:
        for member in bundle:
            parts = Path(member.name).parts
            if not parts or parts[0] != 'cyrus-sasl-2.1.28' or '..' in parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unexpected archive layout or non-regular member.')
        bundle.extractall(output, filter='data')
    source = output / 'cyrus-sasl-2.1.28'
    if digest(source / 'plugins/gssapi.c') != SOURCE_SHA256:
        raise ValueError('Guard source hash mismatch.')
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'CONFIG_SITE': '/dev/null',
           'CFLAGS': '-O2 -fPIC', 'CPPFLAGS': '-DHAVE_TIME_H=1 -DTIME_WITH_SYS_TIME=1', 'LDFLAGS': ''}
    def run(*args, capture=False):
        return subprocess.run(args, cwd=source, env=env, check=True,
                              stdout=subprocess.PIPE if capture else None, text=True).stdout
    # The release configure omits obsolete AC_HEADER_TIME defines; Linux has
    # both standard time headers. Fail compilation rather than suppress warnings.
    run('patch', '--batch', '--forward', '-p1', '-i', str(PATCH))
    # -fPIC is required for a private bridge; -DPIC would select the dynamic
    # plugin path in upstream dlopen.c and is deliberately absent.
    disabled = ['sample', 'cram', 'digest', 'scram', 'otp', 'srp', 'srp-setpass',
                'krb4', 'plain', 'anon', 'login', 'ntlm', 'passdss', 'sql', 'ldapdb',
                'auth-sasldb', 'httpform', 'sia', 'alwaystrue', 'checkapop']
    run('./configure', '--enable-static', '--disable-shared', '--disable-staticdlopen',
        '--enable-gssapi', '--with-gss_impl=mit', '--with-dblib=none',
        '--without-saslauthd', '--without-authdaemond', '--without-pwcheck',
        '--without-pam', '--without-openssl', '--without-des', '--without-opie',
        '--without-rc4', '--without-sphinx-build',
        '--with-plugindir=' + str(output / 'disabled-plugins'),
        '--with-configdir=' + str(output / 'disabled-config'),
        *['--disable-' + name for name in disabled])
    config = (source / 'config.h').read_text()
    macros = set(re.findall(r'^#define[ \t]+(\w+)(?:[ \t]|$)', config, re.M))
    if {'DO_DLOPEN', 'TRY_DLOPEN_WHEN_STATIC', 'PIC'} & macros or 'STATIC_GSSAPIV2' not in macros:
        raise ValueError('Static guarded GSSAPI composition was not selected.')
    if {name for name in macros if name.startswith('STATIC_')} != {'STATIC_GSSAPIV2'}:
        raise ValueError('Unexpected static mechanism configured.')
    for directory in ['include', 'sasldb', 'common', 'lib', 'plugins']:
        run('make', '-C', directory, '-j2')
    # Upstream explicitly appends static mechanism objects in this target.
    run('make', '-C', 'lib', 'libsasl2.a')
    library = source / 'lib/.libs/libsasl2.a'
    members = run('ar', 't', str(library), capture=True).splitlines()
    if members.count('gssapi.o') != 1:
        raise ValueError('Patched GSSAPI object is missing or duplicated.')
    symbols = run('nm', '-g', str(library), capture=True)
    if re.search(r'\bU\s+(?:dlopen|dlsym)\b', symbols):
        raise ValueError('Static Cyrus still references a dynamic plugin loader.')
    if not re.search(r'\bT\s+gssapiv2_client_plug_init\b', symbols):
        raise ValueError('Static GSSAPI entry point is absent.')
    print('Built guarded static Cyrus:', library)
    print('SHA256:', digest(library))
    print('No install, credential acquisition or authentication. Full private closure remains unproven.')
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path, help='New private build directory')
    args = parser.parse_args()
    build(args.archive.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
