#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash tests/native-session/run-demo.sh
native_out="${ADFL_NATIVE_OUT:-/tmp/adfl-native-demo}"
native_out="$(cd "$native_out" && pwd)"
ADFL_OFFLINE_TESTS=1 "${ADFL_DEMO_DOTNET:-dotnet}" run \
  --project tests/native-session/managed-demo/AdForLinux.NativeTransportDemo.csproj \
  --configuration Release --framework "${1:-net8.0}" -- "$native_out/libadfl_native_test.so"
