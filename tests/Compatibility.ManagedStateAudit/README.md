# Managed searcher state audit

This small console harness compares a deterministic sequence of public
DirectorySearcher configuration changes with the actual Microsoft 9.0.0
implementation. It is separate from the live differential test project and is
not included in the solution or any workflow.

It deliberately loads the pinned package's **Windows implementation assembly**
on Linux, bypassing the package's platform-not-supported facade only for this
audited list of managed operations. Do not expand it to SearchRoot, directory
entries, Find methods, Bind, native handles, or default-domain discovery.
This is not a supported Windows deployment or an AD integration test.

From the repository root, with .NET 8 and .NET 10 runtimes installed:

```sh
dotnet run --project tests/Compatibility.ManagedStateAudit -f net8.0 -c Release
dotnet run --project tests/Compatibility.ManagedStateAudit -f net10.0 -c Release
```

`System.DirectoryServices` is pinned to 9.0.0. The project references its net8.0
Windows asset on .NET 8 and its net9.0 Windows asset on .NET 10, matching the
differential suite's asset selection. NuGet supplies the paths; no hard-coded
workspace or credentials are required. Output includes the loaded assembly
SHA-256 and actual runtime. A difference makes the process exit nonzero.

Seed `1032026` generates 2,000 sequences of 60 operations. Each operation
compares its exception type/argument parameter and 19 observable state values.
The whitelist covers coupled ASQ/scope, VLV/cache, DirSync/paging transitions,
invalid enum and numeric assignments, timeout boundaries, filter and sort
replacement/null assignments, and disposal interleaving. It does not compare
search results, provider coercion, network timing, or every property identity.
Counts describe this bounded experiment and are not an API-coverage metric.

See [RESULTS.md](RESULTS.md) for compact results. No raw user data or directory
credentials are read by this harness.
