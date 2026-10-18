# Build and test

User documentation starts in the [README](README.md). This page is for contributors.

## Safe default: offline tests

Install the .NET 10 SDK and .NET 8/10 runtimes, then run from the repository root:

```sh
dotnet build AdForLinux.sln --configuration Release
python tests/test_offline_runner.py
python tests/run-offline-tests.py functional --framework net8.0
python tests/run-offline-tests.py functional --framework net10.0
```

Follow [the offline testing contract](tests/OFFLINE-TESTING.md). The reviewed runner
sets the offline guard and admits exact test classes. Do not replace it with an
unfiltered `dotnet test`, broaden its allowlist casually, or disable a guard to
make a test pass. Unfiltered suites include live directory mutations.

On Windows, the same runner also supports `surface` and `companion` groups.
Microsoft comparisons and companion object construction require Windows.

## Directory integration

Live tests need an explicitly selected disposable directory, appropriate permission
to create/change/delete test objects, and a cleanup plan. They are separate from
offline validation. See [Windows differential test setup](tests/AdForLinux.DifferentialTests/README.md).
The Docker functional environment is also a live Samba directory, not an offline test.
Do not aim either suite at production.

## Test assets and historical evidence

- [Windows descriptor oracle](tests/acl-windows-oracle/README.md): detached
  recordings used by compatibility tests; no directory access.
- [Two-controller probe](docs/research/cross-dc-save-probe/README.md): opt-in research,
  not public cross-controller save support. Its fixture requirements still apply.
- [Compiled user examples](docs/examples): preserve these with their consumer tests.

Development status reports and historical failure narratives were removed from the
current docs. They remain in [the pre-cleanup tree](https://github.com/eliiran1231/active-directory-for-linux/tree/5056d5f/docs)
and linked PR history, including the [security audit and exact-commit results](https://github.com/eliiran1231/active-directory-for-linux/pull/232).
Recorded fixtures and third-party license notices remain in the repository.

When changing docs, check relative links and keep setup commands aligned with the
source. Explain differences in terms of user actions and consequences; keep issue
chronologies, private state-machine details, and old test counts out of user guides.
