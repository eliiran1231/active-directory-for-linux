#!/usr/bin/env bash
# Metadata and hard-refusal proof only; no native credentials or LDAP connection.
set -euo pipefail
cd "$(dirname "$0")/../.."
private_bridge="$(realpath "${1:?Pass output directory from build-private-bridge.py}")"
out="${ADFL_PRIVATE_BRIDGE_DEMO_OUT:-/tmp/adfl-private-bridge-demo}"
mkdir -p "$out"
cc -std=c11 -Wall -Wextra -Werror -pedantic -Isrc/AdForLinux.DirectoryServices.Native \
  tests/native-session/version_probe.c "$private_bridge/libadfl_native.so" \
  -o "$out/version-probe"
env -i PATH=/usr/bin:/bin LC_ALL=C "$out/version-probe"
