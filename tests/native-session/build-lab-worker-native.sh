#!/usr/bin/env bash
# Compile ONLY. Running the resulting test library requires isolated-lab approval.
set -euo pipefail
cd "$(dirname "$0")/../.."
private=$(realpath "${1:?Modified private stack output}")
out=$(realpath -m "${ADFL_LAB_WORKER_NATIVE_OUT:-/tmp/adfl-lab-worker-native}")
mkdir -p "$out"
ldap="$private/openldap-OPENLDAP_REL_ENG_2_6_10"
mit="$private/mit/krb5-1.21.3/src"
native=src/AdForLinux.DirectoryServices.Native
printf '{ global: adfl_*; adfl_lab_*; local: *; };\n' > "$out/lab.exports"
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -fPIC -fvisibility=hidden \
 -DADFL_REVIEWED_MIT_1_21_3 -shared -I"$native" -I"$ldap/include" -I"$private/include" -I"$mit/include" \
 tests/native-session/lab-worker-native.c \
 "$native"/{adfl_controls,adfl_native,adfl_system,adfl_dispatch,adfl_search_system,adfl_conversation}.c \
 "$ldap/libraries/libldap/.libs/libldap.a" "$ldap/libraries/liblber/.libs/liblber.a" \
 "$private/cyrus/cyrus-sasl-2.1.28/lib/.libs/libsasl2.a" \
 -Wl,--start-group "$mit/lib/"{libgssapi_krb5,libkrb5,libk5crypto,libcom_err,libkrb5support}.a -Wl,--end-group \
 -lresolv -pthread -Wl,--exclude-libs,ALL -Wl,--version-script="$out/lab.exports" -Wl,-z,defs \
 -o "$out/libadfl_lab_worker.so"
python3 - "$out/libadfl_lab_worker.so" <<'PY'
import re,subprocess,sys
path=sys.argv[1]
needed=set(re.findall(r'Shared library: \[([^\]]+)\]',subprocess.check_output(['readelf','-d',path],text=True)))
assert not needed-{'libc.so.6','libresolv.so.2','libm.so.6','libdl.so.2','libpthread.so.0'},needed
imports=subprocess.check_output(['nm','-D','--undefined-only',path],text=True)
assert not re.search(r'\bU\s+(?:dlopen|dlmopen|dlsym|dlclose|dlerror|ldap_\w+|sasl_\w+|gss_\w+|krb5_\w+)(?:@\S+)?$',imports,re.M),imports
exports=subprocess.check_output(['nm','-D','--defined-only',path],text=True)
assert all(line.split()[-1].startswith('adfl_') for line in exports.splitlines()),exports
print(path)
print('Compile/link checks passed; library was not loaded or executed.')
PY
