#!/usr/bin/env python3
"""Compile restricted source-only composition from a trusted full-private build.

No installation, authentication or execution. The receipt records build identity;
trusted administrator adoption and immutable deployment are required, not inferred.
The input private directory must be produced by build-private-bridge.py, never an
untrusted collection of archives. Module checks are not arbitrary-code attestation.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import json

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = 'adfl-restricted-file-gssapi-v1'
INPUTS = {
    'MitArchiveSha256': 'b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35',
    'CyrusArchiveSha256': '7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c',
    'OpenLdapArchiveSha256': '1794dbb7225516ae5fb21f3f9a19c0181f0ce33e9d0218e0f623b0a386578181',
    'MitPluginSourceSha256': '86f737e2ffe69a587c53bddb36df3b103dc632eccc978a3fe0f69118f6524898',
    'CyrusGssapiSourceSha256': 'a105e8462e893f6f17f594e6997df6a4a275ef34e468c017dcbcb8933a096e59'
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('private',type=Path,help='Trusted fresh full-private build output')
    parser.add_argument('output',type=Path,help='New restricted artifact directory')
    args = parser.parse_args()
    private, out = args.private.resolve(), args.output.resolve()
    mit = private/'mit/krb5-1.21.3/src'
    cyrus = private/'cyrus/cyrus-sasl-2.1.28'
    ldap = private/'openldap-OPENLDAP_REL_ENG_2_6_10'
    env = {'PATH':'/usr/bin:/bin','LC_ALL':'C'}
    def run(*command):
        return subprocess.check_output(command,env=env,text=True)
    for source, key in [(mit/'util/support/plugins.c','MitPluginSourceSha256'),
                        (cyrus/'plugins/gssapi.c','CyrusGssapiSourceSha256')]:
        if digest(source) != INPUTS[key]: raise ValueError('Unreviewed private source: '+str(source))
    def macros(path):
        return set(re.findall(r'^#define[ \t]+(\w+)(?:[ \t]|$)',path.read_text(),re.M))
    cm = macros(cyrus/'config.h'); lm = macros(ldap/'include/portable.h')
    if {'DO_DLOPEN','TRY_DLOPEN_WHEN_STATIC','PIC'} & cm or {s for s in cm if s.startswith('STATIC_')} != {'STATIC_GSSAPIV2'}:
        raise ValueError('Unreviewed Cyrus composition')
    if 'HAVE_CYRUS_SASL' not in lm or {'HAVE_TLS','HAVE_OPENSSL','HAVE_GNUTLS'} & lm:
        raise ValueError('Unreviewed OpenLDAP composition')
    archives = [ldap/'libraries/libldap/.libs/libldap.a',ldap/'libraries/liblber/.libs/liblber.a',
                cyrus/'lib/.libs/libsasl2.a']
    mit_archives = [mit/'lib'/name for name in ['libgssapi_krb5.a','libkrb5.a','libk5crypto.a','libcom_err.a','libkrb5support.a']]
    imports = run('nm','-u',*map(str,archives+mit_archives))
    loader = r'\bU\s+(?:dlopen|dlmopen|dlsym|dlclose|dlerror)(?:@\S+)?$'
    if re.search(loader,imports,re.M): raise ValueError('Runtime loader reference remains')
    members = run('ar','t',str(archives[2])).splitlines()
    if members.count('gssapi.o') != 1: raise ValueError('Missing/duplicate static GSSAPI object')
    plugin = subprocess.check_output(['ar','p',str(archives[2]),'gssapi.o'],env=env)
    if b'ADFL requires an explicit GSS credential' not in plugin:
        raise ValueError('Compiled GSSAPI guard diagnostic absent')
    native = ROOT/'src/AdForLinux.DirectoryServices.Native'
    sources = [native/name for name in ['adfl_controls.c','adfl_native.c','adfl_system.c',
               'adfl_dispatch.c','adfl_search_system.c','adfl_conversation.c','adfl_restricted.c']]
    headers = [native/'adfl_native.h',native/'adfl_native_internal.h',native/'adfl_restricted.h']
    out.mkdir(parents=True,exist_ok=False)
    exports = out/'restricted.exports'; exports.write_text('{ global: adfl_*; local: *; };\n')
    bridge = out/'libadfl_restricted.so'
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-O2','-fPIC',
        '-fvisibility=hidden','-DADFL_REVIEWED_MIT_1_21_3','-shared','-I'+str(native),
        '-I'+str(ldap/'include'),'-I'+str(private/'include'),'-I'+str(mit/'include'),
        *map(str,sources),*map(str,archives),'-Wl,--start-group',*map(str,mit_archives),'-Wl,--end-group',
        '-lresolv','-pthread','-Wl,--exclude-libs,ALL','-Wl,--version-script='+str(exports),
        '-Wl,-z,defs','-o',str(bridge)],env=env,check=True)
    needed = set(re.findall(r'Shared library: \[([^\]]+)\]',run('readelf','-d',str(bridge))))
    if needed-{'libc.so.6','libresolv.so.2','libm.so.6','libdl.so.2','libpthread.so.0'}:
        raise ValueError('Unexpected dynamic dependencies: '+repr(needed))
    if re.search(loader,run('nm','-D','--undefined-only',str(bridge)),re.M): raise ValueError('Bridge loader import remains')
    definitions = run('nm','-D','--defined-only',str(bridge)).splitlines()
    names = {line.split()[-1] for line in definitions}
    if any(not name.startswith('adfl_') or name.startswith('adfl_lab_') or name.startswith('adfl_test_') for name in names):
        raise ValueError('Unexpected exported symbols')
    if not {'adfl_restricted_authority_resolve_from','adfl_restricted_authority_bind'} <= names:
        raise ValueError('Restricted entry points missing')
    source_records = sources+headers+[Path(__file__).resolve()]
    receipt = {'FormatVersion':1,'Contract':CONTRACT,'NativeAbi':4,'NativeBridgeSha256':digest(bridge),
               'Inputs':INPUTS,'Sources':[{'Path':str(p.relative_to(ROOT)),'Sha256':digest(p)} for p in source_records],
               'Archives':[{'Path':str(p.relative_to(private)),'Sha256':digest(p)} for p in archives+mit_archives]}
    (out/'composition.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(bridge); print(out/'composition.json')
    print('Compile-only: generic authentication gate remains closed; receipt requires trusted deployment adoption.')

if __name__ == '__main__': main()
