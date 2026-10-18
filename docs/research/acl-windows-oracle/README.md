# Offline Windows descriptor oracle

Contributor tool for recording Microsoft `System.DirectoryServices` 9.0.0 behavior
on detached in-memory security descriptors. It does not connect to AD or modify
system permissions. User guidance is in [the documentation](../../../README.md).

## Run on Windows

With the .NET 10 SDK and .NET 8/10 runtimes, from the repository root:

```sh
dotnet build docs/research/acl-windows-oracle/AclWindowsOracle.csproj
dotnet run --project docs/research/acl-windows-oracle/AclWindowsOracle.csproj -f net8.0 --no-build
dotnet run --project docs/research/acl-windows-oracle/AclWindowsOracle.csproj -f net10.0 --no-build
```

Other operating systems exit without running cases. This project is outside the
solution and is not packaged.

## Maintain recordings

[Fixtures.cs](Fixtures.cs) builds independent binary inputs; [Program.cs](Program.cs)
selects recording modes. The [Windows offline workflow](../../../.github/workflows/acl-offline-windows.yml)
contains the bounded recording commands, verification scripts and artifact paths.
Keep its limits and explicit modes when reproducing native boundary cases.

The `results` directory contains test fixtures and original observations, including
text transcripts referenced by replay-test comments. Preserve these inputs and their
provenance; do not regenerate expected values from the portable implementation.
Record the source commit, Microsoft package and runtime versions when adding evidence.

An observation establishes behavior for that case, not universal Microsoft parity
or live AD persistence. Historical interpretation and per-issue reports are in the
[pre-cleanup documentation](https://github.com/eliiran1231/active-directory-for-linux/tree/5056d5f/docs).
