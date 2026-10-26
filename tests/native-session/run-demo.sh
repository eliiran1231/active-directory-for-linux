#!/usr/bin/env bash
# Does not install/download software, read credential stores, or bind to LDAP.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "$(pkg-config --modversion krb5-gssapi)" != "1.21.3" ]]; then
  echo "This prototype requires reviewed MIT 1.21.3 headers/libraries." >&2; exit 2
fi
native_include="${ADFL_SASL_INCLUDE:-/usr/include}"
if [[ ! -f "$native_include/sasl/sasl.h" && -z "${ADFL_SASL_INCLUDE:-}" ]]; then
  native_include=tests/native-session/headers
  echo "Using unmodified pinned upstream Cyrus public headers (compile/link evidence only)."
fi
if [[ ! -f "$native_include/sasl/sasl.h" ]]; then
  echo "Missing Cyrus SASL 2.1.28 public headers; set ADFL_SASL_INCLUDE to their parent. Nothing installed." >&2; exit 2
fi
native_out="${ADFL_NATIVE_OUT:-/tmp/adfl-native-demo}"
mkdir -p "$native_out"
read -r -a native_flags <<< "$(pkg-config --cflags --libs krb5-gssapi krb5 ldap)"
read -r -a extra_flags <<< "${ADFL_NATIVE_CFLAGS:-}"
common=("${extra_flags[@]}" -std=c11 -Wall -Wextra -Werror -pedantic -g -fPIC -fvisibility=hidden -DADFL_REVIEWED_MIT_1_21_3
        -Isrc/AdForLinux.DirectoryServices.Native -I"$native_include")
sources=(src/AdForLinux.DirectoryServices.Native/adfl_native.c src/AdForLinux.DirectoryServices.Native/adfl_system.c src/AdForLinux.DirectoryServices.Native/adfl_dispatch.c src/AdForLinux.DirectoryServices.Native/adfl_search_system.c src/AdForLinux.DirectoryServices.Native/adfl_conversation.c)
cc "${common[@]}" -shared "${sources[@]}" "${native_flags[@]}" -l:libsasl2.so.2 -o "$native_out/libadfl_native.so"
cc "${common[@]}" tests/native-session/session_demo.c "${sources[@]}" "${native_flags[@]}" -l:libsasl2.so.2 -pthread -o "$native_out/session-demo"
cc "${common[@]}" -shared -DADFL_TEST_BRIDGE tests/native-session/session_demo.c "${sources[@]}" "${native_flags[@]}" -l:libsasl2.so.2 -pthread -o "$native_out/libadfl_native_test.so"
cc "${common[@]}" tests/native-session/version_probe.c -L"$native_out" -ladfl_native -Wl,-rpath,"$native_out" -o "$native_out/version-probe"
"$native_out/session-demo"
"$native_out/version-probe"
