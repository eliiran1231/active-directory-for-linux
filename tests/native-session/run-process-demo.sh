#!/usr/bin/env bash
# Real exec/IPC/pidfd supervision with recording native dependencies. No AD or credentials.
set -euo pipefail
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_TELEMETRY_OPTOUT=1
cd "$(dirname "$0")/../.."
bash tests/native-session/run-worker-demo.sh
bash tests/native-session/run-demo.sh
framework="${1:-net8.0}"
dotnet_command="${ADFL_DEMO_DOTNET:-dotnet}"
dotnet_path="$(command -v "$dotnet_command")"
dotnet_path="$(realpath "$dotnet_path")"
"$dotnet_path" build src/AdForLinux.NativeHost/AdForLinux.NativeHost.csproj --configuration Release --framework "$framework"
"$dotnet_path" build tests/native-session/worker-demo/AdForLinux.NativeWorkerDemo.csproj --configuration Release --framework "$framework"
worker_out="${ADFL_WORKER_OUT:-/tmp/adfl-worker-demo}"
native_out="${ADFL_NATIVE_OUT:-/tmp/adfl-native-demo}"
profile_args=()
if [[ -n "${ADFL_PRIVATE_MIT_SOURCE:-}" ]]; then
  profile_probe="$(bash tests/native-session/build-private-profile-probe.sh "$ADFL_PRIVATE_MIT_SOURCE")"
  profile_args+=("$(realpath "$profile_probe")")
fi
ADFL_OFFLINE_TESTS=1 "$dotnet_path" "tests/native-session/worker-demo/bin/Release/$framework/AdForLinux.NativeWorkerDemo.dll" \
  "$dotnet_path" "$(realpath "$worker_out/libadfl_worker.so")" "$(realpath "$native_out/libadfl_native_test.so")" \
  "$(realpath "src/AdForLinux.NativeHost/bin/Release/$framework/AdForLinux.NativeHost.dll")" "${profile_args[@]}"
