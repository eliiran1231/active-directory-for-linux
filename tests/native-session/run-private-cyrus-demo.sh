#!/usr/bin/env bash
# Build output from build-private-cyrus.py only; no installation/authentication.
set -euo pipefail
cd "$(dirname "$0")/../.."
source_dir="$(realpath "${1:?Pass the private cyrus-sasl-2.1.28 build directory}")"
out="${ADFL_CYRUS_DEMO_OUT:-/tmp/adfl-private-cyrus-demo}"
mkdir -p "$out"
cc -std=c11 -Wall -Wextra -Werror -pedantic -I"$source_dir/include" \
  tests/native-session/private-cyrus-demo.c "$source_dir/lib/.libs/libsasl2.a" \
  -Wl,--wrap=gss_acquire_cred -Wl,--wrap=gss_init_sec_context \
  -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lresolv -o "$out/private-cyrus-demo"
"$out/private-cyrus-demo"
