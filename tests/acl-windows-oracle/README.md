# Offline Windows descriptor oracle

Contributor tool for recording Microsoft `System.DirectoryServices` 9.0.0 behavior
on detached in-memory security descriptors. It does not connect to AD or modify
system permissions. User guidance is in [the documentation](../../README.md).

## Run on Windows

With the .NET 10 SDK and .NET 8/10 runtimes, from the repository root:

```sh
dotnet build tests/acl-windows-oracle/AclWindowsOracle.csproj
dotnet run --project tests/acl-windows-oracle/AclWindowsOracle.csproj -f net8.0 --no-build
dotnet run --project tests/acl-windows-oracle/AclWindowsOracle.csproj -f net10.0 --no-build
```

Other operating systems exit without running cases. This project is outside the
solution and is not packaged.

## Maintain recordings

[Fixtures.cs](Fixtures.cs) builds independent binary inputs; [Program.cs](Program.cs)
selects recording modes. The [Windows offline workflow](../../.github/workflows/acl-offline-windows.yml)
contains the bounded recording commands, verification scripts and artifact paths.
Keep its limits and explicit modes when reproducing native boundary cases.

The `results` directory contains 34 baselines consumed by replay tests or the Windows
workflow, plus two original transcripts cited by replay-test comments.
[manifest.json](results/manifest.json) records their byte counts and SHA-256 hashes,
with source runs and commits. Recording headers retain Microsoft package and runtime
versions. Preserve these inputs; never regenerate expected values from the portable
implementation. Update the manifest when adding native evidence.

Historical comparisons and detailed extraction provenance are available through the
manifest's pinned archive link. Duplicate JSONL copies were removed only after checking
that every header and observation matched the retained JSON baseline.

An observation establishes behavior for that case, not universal Microsoft parity
or live AD persistence. Historical interpretation and per-issue reports are in the
[pre-cleanup documentation](https://github.com/eliiran1231/active-directory-for-linux/tree/5056d5f/docs).
