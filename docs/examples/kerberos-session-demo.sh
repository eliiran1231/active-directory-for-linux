#!/usr/bin/env bash
# Deterministic session architecture demonstration. No LDAP/native bind is made.
set -euo pipefail
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_TELEMETRY_OPTOUT=1
cd "$(dirname "$0")/../.."
python3 tests/run-offline-tests.py functional --framework "${1:-net8.0}" \
  --dotnet "${ADFL_DEMO_DOTNET:-dotnet}" \
  --class ConnectionPoolTests --class ConnectionPoolOperationTests \
  --class WindowsContextScopedReadTests
