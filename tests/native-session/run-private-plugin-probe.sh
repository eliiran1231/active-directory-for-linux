#!/usr/bin/env bash
# Offline module-denial proof against actual modified private archives + bridge.
set -euo pipefail
cd "$(dirname "$0")/../.."
private=$(realpath "${1:?Pass fresh private build with modified MIT}")
mit="$private/mit/krb5-1.21.3/src"
out=$(realpath -m "${ADFL_PRIVATE_PLUGIN_OUT:-/tmp/adfl-private-plugin-probe}")
mkdir -p "$out/modules"
cc -shared -fPIC tests/native-session/private-plugin-canary.c -o "$out/modules/canary.so"
# Positive control: this is a valid loadable library, in a separate Python process.
python3 - "$out/modules/canary.so" <<'PY'
import ctypes,sys
module=ctypes.CDLL(sys.argv[1])
assert ctypes.c_int.in_dll(module,'adfl_canary_loaded').value == 1
PY
python3 - "$out" "$mit" "$private/libadfl_native.so" <<'PY'
import pathlib,re,subprocess,sys
out,mit,bridge=map(pathlib.Path,sys.argv[1:])
# Values originate only from controlled test output paths, never user config.
if any(c in str(out) for c in '\n\r{}#;'): raise ValueError('Unsafe test path')
(out/'krb5.conf').write_text('[libdefaults]\n default_realm = SYNTHETIC.INVALID\n dns_lookup_realm = false\n dns_lookup_kdc = false\n[plugins]\n ccselect = {\n  module = canary:'+str(out/'modules/canary.so')+'\n }\n')
(out/'dynamic-profile.conf').write_text('module '+str(out/'modules/canary.so')+':synthetic\n')
# Ask GSS to inspect an external mechanism too; built-in Kerberos must survive.
(out/'mech.conf').write_text('canary 1.3.6.1.4.1.5322.999 '+str(out/'modules/canary.so')+'\n')
archives=[mit/'lib'/name for name in ('libgssapi_krb5.a','libkrb5.a','libk5crypto.a','libcom_err.a','libkrb5support.a')]
for command in (['nm','-u',*map(str,archives)],['nm','-D','--undefined-only',str(bridge)]):
    symbols=subprocess.check_output(command,text=True)
    assert not re.search(r'\bU\s+(?:dlopen|dlmopen|dlsym|dlclose|dlerror)(?:@\S+)?$',symbols,re.M), symbols
PY
cc -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
 -isystem "$mit/include" -isystem "$mit/util/profile" tests/native-session/private-plugin-probe.c \
 -Wl,--start-group "$mit/lib/"{libgssapi_krb5,libkrb5,libk5crypto,libcom_err,libkrb5support}.a -Wl,--end-group \
 -Wl,--wrap=dlopen -Wl,--wrap=dlsym -lresolv -pthread -o "$out/private-plugin-probe"
env -i PATH=/usr/bin:/bin LC_ALL=C KRB5_CONFIG="$out/krb5.conf" GSS_MECH_CONFIG="$out/mech.conf" \
 "$out/private-plugin-probe" "$out/modules/canary.so" "$out/modules" "$out/dynamic-profile.conf"
