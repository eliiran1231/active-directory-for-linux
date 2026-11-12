# Source-verified recorded Microsoft oracle

## What actually runs

This console test runner targets net8.0 and net10.0 and references only the Linux clone projects, not Microsoft's Windows-only DirectoryServices implementation. It copies the clone-side operation sequence from 16 original Facts. Four Facts retain the structured JSON oracle, while 12 additional mirrors use values hardcoded directly from the supplied Microsoft run.

- Security mask setter state: 19 observed integers.
- Virtual list view constructors: 36 observations across six constructions.
- Virtual list view validation and derived state: 18 observations across three states.
- Virtual list view response setter/update sequence: six observations.
- Principal and extension surface reflection: 54 hardcoded observations across four Facts.
- Offline entry, empty-result, and synchronization controls: five hardcoded observations across three Facts.
- Validation exception types: 19 hardcoded observations across five Facts.

Total: **16 partial Facts, 157 scalar checks per runtime**. No LDAP binds, AD reads/writes, credentials, environment-specific identifiers, or live server are used. The `System.DirectoryServices.Protocols` dependency belongs to the clone, but these operations never use it.

## Evidence and admission

Source: [commit 93f1f9c](https://github.com/eliiran1231/active-directory-for-linux/tree/93f1f9c6b593d9f4dd38d23616632dc6a015f4ca), [job 130806631589](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/43105205156/job/130806631589).

`observations.jsonl` contains only the 158 public scalar records admitted here. They were originally labeled unverified assertion operands, correctly: logging alone does not prove Microsoft origin. Admission here is narrower and source-reviewed:

- Original source SHA-256 is pinned in `extract_oracle.py`; relocation must not change those bytes.
- Lines 142/149/156 explicitly read `(int)microsoft.SecurityMasks`.
- `AssertViewsEqual` lines 241–245 read five properties of its Microsoft-typed `microsoft` argument. Line 247 reads whether its context is null. Every call in these four Facts passes a Microsoft-created object.
- The site hash includes the fully qualified Fact name, source filename, source member, original line, expected-operand role, and origin label. Clone-side operands, literals, and other sites are never admitted.
- Each Fact has exactly one execution per framework, with no theory parameters. Occurrences are ordered by the recorder's record number within that execution. Expected occurrence counts are fixed; duplicates, missing observations, changed source, wrong types, or multiple executions fail admission.
- Frameworks remain separate. No values are inferred from Linux results or copied between frameworks.

The original Windows source remains the reference. Runtime logs and source are evidence, not cryptographic proof of the runner's honesty. The extractor deliberately does not automatically admit other assertions. The 78 additional hardcoded observations are limited to booleans, integers, and exception type names whose Microsoft-expected operands were identifiable in both framework captures. Both frameworks produced identical values at all 78 admitted sites; the source method and line are retained in each hardcoded key.

## Limits

These are partial adaptations of 16 Facts, not fully reproduced tests. Redacted strings (including VLV Target), opaque tuples/types, enum-name loops, unrecorded parameter names, and other unavailable operands are not guessed or claimed as comparisons. Invalid setter/constructor attempts in the added mirrors compare only their recorded exception type names. Unexpected behavior fails the runner.

The full Windows run had 1,398 execution files per framework and 2,986 explicit scalar pairs. This Linux subset uses source-proven assertion operands instead. Most remaining tests need recorded theory inputs, fixture-aware normalization, strings/collections or live Linux AD execution. They are **not silently counted as passing**. Re-running the full original Windows suite on Linux unchanged would not be valid.

## Run

From the repository root, with .NET SDK 10 and runtimes 8 and 10:

```sh
python3 -m unittest discover -s tests/linux/RecordedMicrosoft -p 'test_*.py'
dotnet restore tests/linux/RecordedMicrosoft/RecordedMicrosoft.csproj
DOTNET_ROLL_FORWARD=LatestPatch dotnet run --project tests/linux/RecordedMicrosoft/RecordedMicrosoft.csproj -c Release -f net8.0 --no-restore
DOTNET_ROLL_FORWARD=LatestPatch dotnet run --project tests/linux/RecordedMicrosoft/RecordedMicrosoft.csproj -c Release -f net10.0 --no-restore
```

To reproduce the fixture without any network:

```sh
python3 tests/linux/RecordedMicrosoft/extract_oracle.py tests/linux/RecordedMicrosoft/observations.jsonl /tmp/oracle.json
```

The runner rejects non-Linux execution, missing/unconsumed/extra observations, and any scalar mismatch. Successful output explicitly says the remaining suite is not covered. `Linux recorded Microsoft oracle (partial)` is a manual-only workflow; it receives no repository AD secrets.
