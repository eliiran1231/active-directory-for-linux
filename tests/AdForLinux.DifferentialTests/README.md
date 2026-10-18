# Windows differential tests

Compares Microsoft and portable APIs on Windows. The project builds on Linux,
but Microsoft directory API execution requires Windows. Tests cover public API
shape, local behavior, and separately configured live directory operations.

## Offline comparisons

From the repository root, build first and use the approved runner:

```powershell
dotnet build AdForLinux.sln --configuration Release
python tests/run-offline-tests.py surface --framework net8.0
python tests/run-offline-tests.py surface --framework net10.0
```

Read [OFFLINE-TESTING.md](../OFFLINE-TESTING.md) before choosing additional classes.
Do not use an unfiltered suite for offline work or disable the admission guards.

## Live AD comparisons

Only use a disposable directory and an isolated writable OU for which fixture
creation, account/password changes, and cleanup are authorized. Full test runs
create, modify and delete directory objects. Coordinate runs so fixtures do not overlap.

Provide these environment variables through your local secret/configuration mechanism:

| Variable | Value |
| --- | --- |
| `AD_HOST` | Explicit domain controller DNS name |
| `AD_PORT` | `636` |
| `AD_USE_TLS` | `true` |
| `AD_BIND_DN` | Authorized test identity |
| `AD_BIND_PW` | Test identity's password; do not commit it |
| `AD_BASE_DN` | Isolated test OU, e.g. `OU=Run,OU=CI,DC=example,DC=com` |
| `AD_USERS_CONTAINER_DN` | Optional writable principal container inside that OU |

Trust the server certificate. Confirm the fixture and cleanup scope before running
an unfiltered suite in a separately configured live-test process:

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows
```

Record the exact commit, runtime, server and test results. A passing offline check
is not evidence for live server behavior. Preserve Microsoft-oracle assertions when
fixing differences; intentional portable boundaries are described in the
[user limitations](../../docs/limitations.md). Two-DC validation remains separate in
[issue 230](https://github.com/eliiran1231/active-directory-for-linux/issues/230).

Old batch-by-batch results are available in
[Git history](https://github.com/eliiran1231/active-directory-for-linux/tree/5056d5f/tests/AdForLinux.DifferentialTests).
