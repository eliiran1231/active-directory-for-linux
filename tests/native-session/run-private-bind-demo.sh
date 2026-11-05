#!/usr/bin/env bash
# Actual private callback stack; synthetic GSS only, no authentication/network.
set -euo pipefail
cd "$(dirname "$0")/../.."
private="$(realpath "${1:?Pass build-private-bridge.py output}")"
ldap="$private/openldap-OPENLDAP_REL_ENG_2_6_10"
out="${ADFL_PRIVATE_BIND_DEMO_OUT:-/tmp/adfl-private-bind-demo}"
mkdir -p "$out"
native=src/AdForLinux.DirectoryServices.Native
mit="$private/mit/krb5-1.21.3/src"
mit_headers=()
mit_libraries=(-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err)
if [[ -d "$mit/lib" ]]; then
  mit_headers=(-I"$mit/include")
  mit_libraries=(-Wl,--start-group)
  for archive in libgssapi_krb5.a libkrb5.a libk5crypto.a libcom_err.a libkrb5support.a; do
    mit_libraries+=("$mit/lib/$archive")
  done
  mit_libraries+=(-Wl,--end-group -ldl)
fi
wrap=()
for symbol in connect getaddrinfo gss_release_cred gss_delete_sec_context gss_acquire_cred gss_acquire_cred_from gss_import_name gss_release_name gss_display_status gss_release_buffer gss_init_sec_context; do
  wrap+=("-Wl,--wrap=$symbol")
done
cc -std=c11 -Wall -Wextra -Werror -pedantic -DADFL_REVIEWED_MIT_1_21_3 \
  -I"$native" -I"$ldap/include" -I"$private/include" "${mit_headers[@]}" \
  tests/native-session/private-bind-demo.c \
  "$native"/{adfl_controls,adfl_native,adfl_system,adfl_dispatch,adfl_search_system,adfl_conversation}.c \
  "$ldap/libraries/libldap/.libs/libldap.a" "$ldap/libraries/liblber/.libs/liblber.a" \
  "$private/cyrus/cyrus-sasl-2.1.28/lib/.libs/libsasl2.a" "${wrap[@]}" \
  "${mit_libraries[@]}" -lresolv -pthread -o "$out/private-bind-demo"
env -i PATH=/usr/bin:/bin LC_ALL=C "$out/private-bind-demo"
