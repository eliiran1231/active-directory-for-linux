#!/usr/bin/env bash
# libc-only supervisor proof: no LDAP, credentials, authentication or network peers.
set -euo pipefail
cd "$(dirname "$0")/../.."
worker_out="${ADFL_WORKER_OUT:-/tmp/adfl-worker-demo}"
mkdir -p "$worker_out"
read -r -a extra_flags <<< "${ADFL_WORKER_CFLAGS:-}"
flags=("${extra_flags[@]}" -std=c11 -Wall -Wextra -Werror -pedantic -g -fPIC -fvisibility=hidden -Isrc/AdForLinux.DirectoryServices.Native/worker)
cc "${flags[@]}" -shared src/AdForLinux.DirectoryServices.Native/worker/adfl_worker.c -o "$worker_out/libadfl_worker.so"
cc "${flags[@]}" tests/native-session/worker-supervisor-demo.c src/AdForLinux.DirectoryServices.Native/worker/adfl_worker.c -o "$worker_out/worker-supervisor-demo"
"$worker_out/worker-supervisor-demo"
