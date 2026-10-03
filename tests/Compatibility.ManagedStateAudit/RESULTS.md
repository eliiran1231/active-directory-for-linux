# Managed-state audit results

Observed on 2026-10-03, Linux x64 (Debian 13), SDK 10.0.100.
The checked-in harness was rerun using the commands in [README.md](README.md).

| Actual runtime | Pinned Microsoft Windows asset | Sequences | Operations | State/exception comparisons | Differences |
| --- | --- | ---: | ---: | ---: | ---: |
| .NET 8.0.22 | package 9.0.0, net8.0 | 2,000 | 120,000 | 2,400,000 | 0 |
| .NET 10.0.0 | package 9.0.0, net9.0 | 2,000 | 120,000 | 2,400,000 | 0 |

These counts are generated attempts and checks, not independent contracts or
API coverage. The result rules out differences in the particular generated
sequences of the whitelist; it says nothing about provider execution.

Program.cs SHA-256:
`5140630e9e7f5740c39909c4c887930cd9c9b832d88471cb0b7a2010a6af39ac`

Loaded Microsoft implementation SHA-256 values matched the NuGet package files:

- net8.0: `d35f0bdab41e3181ea5f753f52ba91f17909af7f0d58d789cdefa877e5ee7254`
- net9.0: `44bf17a8baf90976835d3cd3a5ea66626222471b659f114365f57da94e50ed87`

Compact command output follows; only the machine-specific output-directory
prefix is replaced with `<output>`.

```text
seed=1032026 sequences=2000 operations=120000 comparisons=2400000 differences=0; microsoft=<output>/System.DirectoryServices.dll version=9.0.0.0
runtime=.NET 8.0.22; os=Debian GNU/Linux 13 (trixie); architecture=X64
microsoft-sha256=d35f0bdab41e3181ea5f753f52ba91f17909af7f0d58d789cdefa877e5ee7254

seed=1032026 sequences=2000 operations=120000 comparisons=2400000 differences=0; microsoft=<output>/System.DirectoryServices.dll version=9.0.0.0
runtime=.NET 10.0.0; os=Debian GNU/Linux 13 (trixie); architecture=X64
microsoft-sha256=44bf17a8baf90976835d3cd3a5ea66626222471b659f114365f57da94e50ed87
```

No directory, native-handle, Bind, Find, or default-domain-discovery operations
were executed. This harness does not establish Windows/AD integration parity.
