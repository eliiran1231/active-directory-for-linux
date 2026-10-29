#!/usr/bin/env bash
# Build a test-only metadata probe against the pinned private MIT archives.
set -euo pipefail
cd "$(dirname "$0")/../.."
mit="$(realpath "${1:?Pass private MIT src directory}")"
out="${ADFL_PRIVATE_PROFILE_OUT:-/tmp/adfl-private-profile}"
mkdir -p "$out"
cc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -fvisibility=hidden -shared \
  -I"$mit/include" -I"$mit/util/profile" tests/native-session/private-profile-probe.c \
  -Wl,--start-group "$mit/lib/"{libgssapi_krb5,libkrb5,libk5crypto,libcom_err,libkrb5support}.a -Wl,--end-group \
  -Wl,--wrap=fopen -Wl,--wrap=dlopen -Wl,--wrap=connect -Wl,--wrap=getaddrinfo \
  -Wl,--exclude-libs,ALL -Wl,-z,defs -ldl -lresolv -pthread -o "$out/libadfl_profile_test.so"
printf '%s\n' "$out/libadfl_profile_test.so"
