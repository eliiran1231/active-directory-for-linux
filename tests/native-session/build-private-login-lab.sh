#!/usr/bin/env bash
# COMPILE ONLY. Never executes the credential-consuming executable.
set -euo pipefail
cd "$(dirname "$0")/../.."
private="$(realpath "${1:?Pass full private bridge output}")"
out="${ADFL_LOGIN_LAB_OUT:-/tmp/adfl-private-login-lab-build}"
mkdir -p "$out"
ldap="$private/openldap-OPENLDAP_REL_ENG_2_6_10"
mit="$private/mit/krb5-1.21.3/src"
native=src/AdForLinux.DirectoryServices.Native
mit_libraries=(-Wl,--start-group)
for archive in libgssapi_krb5.a libkrb5.a libk5crypto.a libcom_err.a libkrb5support.a; do
  mit_libraries+=("$mit/lib/$archive")
done
mit_libraries+=(-Wl,--end-group -ldl)
cc -std=c11 -Wall -Wextra -Werror -pedantic -DADFL_REVIEWED_MIT_1_21_3 \
  -I"$native" -I"$ldap/include" -I"$private/include" -I"$mit/include" \
  tests/native-session/private-login-lab.c \
  "$native"/{adfl_controls,adfl_native,adfl_system,adfl_dispatch,adfl_search_system,adfl_conversation}.c \
  "$ldap/libraries/libldap/.libs/libldap.a" "$ldap/libraries/liblber/.libs/liblber.a" \
  "$private/cyrus/cyrus-sasl-2.1.28/lib/.libs/libsasl2.a" "${mit_libraries[@]}" \
  -lresolv -pthread -o "$out/private-login-lab"
printf 'Compiled only; NOT executed: %s\n' "$out/private-login-lab"
