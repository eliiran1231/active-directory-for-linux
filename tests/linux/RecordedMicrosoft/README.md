# Source-verified recorded Microsoft oracle

## What actually runs

This console runner targets net8.0 and net10.0 and references only the Linux clone projects. It adapts **44 distinct source methods**, all partially: 14 Facts and 30 Theories. The theories exercise 190 source-declared input rows and compare per-method multisets of complete admitted scalar sequences. Their recorded execution GUIDs are not mapped to input rows.

| Adapter group | Scalar observations per runtime | Scope |
| --- | ---: | --- |
| Structured, source-pinned four-Fact oracle | 79 | Security mask and VLV state |
| Existing hardcoded Microsoft operands | 78 | Surface reflection, offline controls and validation exceptions |
| Existing eight theory multisets | 1,369 | Searcher, synchronization and VLV sequences |
| Eight new explicit-comparison theory multisets | 197 | Context validation, detached filters/searchers, disposal guards and schema indexers |
| Fourteen new source-reviewed assertion theory multisets | 172 | Detached searcher validation, collection cursors, invalid collection inputs and schema indexers |
| **Total** | **1,895** | **44 distinct partial methods; 190 source-declared theory rows** |

The initial runner reported 24 methods by adding adapter counts, but two Facts occur in both structured and hardcoded groups. That starting state contained **22 distinct methods**. This expansion adds **22 distinct methods and 369 scalar observations**, giving 44 distinct methods. The observation totals were not double-counted.

The runner sets `ADFL_OFFLINE_TESTS=1` before clone operations, enabling the repository's pre-connection guard. These adaptations use no LDAP binds, AD reads/writes, credentials or live server. Invalid context-constructor rows retain their source rejection guard, and entries are disposed before potentially binding validation operations.

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

The theory fixture contains only `reviewed-scalar-pair` Microsoft operands from the supplied run. Public logs retained the method hash and execution GUID but not the theory arguments. The mirror therefore compares complete observation sequences as a multiset for each framework and method; it does not invent an execution-to-input mapping. Framework fixtures remain separate where Microsoft produced different sequences.


## New reproducible fixtures

`offline-observations.jsonl` retains only Microsoft operands from reviewed explicit `Comparison.Check` sites. `extract_offline_oracle.py` pins all eight original source files, method/site identities, framework, execution count, scalar count and types. The site-tagged sequence includes the original source line to prevent comparing values at the wrong observation site.

`reviewed-assertions.jsonl` retains only reviewed Microsoft `assert-equal-expected` operands. Such wrappers alone do not prove Microsoft origin. `reviewed-assertions-spec.json` pins the source file bytes, method, helper member, original line, operand role and origin hash. `extract_reviewed_assertions.py` excludes clone-side roles and expected literals. All admitted values are Microsoft object properties, Microsoft-generated errors, or prior values read from Microsoft objects. Generated JSON fixtures are framework-specific and never use Linux values as expected results.

The schema indexer tests use the original Windows suite's delegate-backed in-memory `SchemaNameCollection` fixture as the reference; they do not prove live ADSI marshaling behavior. The Linux side uses its normal entry/children/schema-filter API.

The admission tests reproduce fixtures and reject changed source/provenance, unreviewed or clone-side sites, literal-only expected sites, missing/duplicate observations, missing executions and wrong typed values. Public log ordering is normalized only by each observation's recorder number within its execution; no theory-input identities are invented.

## Full-suite ledger

[coverage-inventory.json](coverage-inventory.json) accounts for every one of the current 359 source declarations: **0 fully mirrored, 44 partially mirrored, 315 not mirrored**. Each declaration includes its source location, adapter membership, public scalar metadata and reason for remaining partial or absent. [capture-inventory.json](capture-inventory.json) retains payload-free metadata and the public capture summaries. Source declarations, runtime execution files and scalar observations are different units.

The capture summaries report 1,398 execution files and 5,666 redacted or unsupported observations per runtime. Raw execution files are private, the run exposes no downloadable artifacts, and theory arguments are unresolved. Thus **full coverage cannot be reconstructed from the available public recording alone**. Other offline methods with usable scalar records still need source review and adapters; their ledger status remains `not_mirrored`, never passing. Live-fixture/scenario dependencies need a controlled equivalent or clearly scoped AD authorization. No such live execution has been attempted.

To complete the full mirror, obtain a sanitized complete oracle with explicit theory input identities and reviewed representations for strings, collections, typed state and fixture-dependent values; then implement and validate the remaining scenarios. This ledger is an honest checkpoint, not a claim that remaining offline adaptation work is exhausted.

## Limits

These are partial adaptations, not fully reproduced tests. Redacted strings (including VLV Target, cookies, attribute names, and exception parameter names), opaque tuples/types, enum-name loops, and other unavailable operands are not guessed or claimed as comparisons. Invalid setter/constructor attempts in the added mirrors compare only their recorded exception type names. Unexpected behavior fails the runner.

The full Windows capture summary reports 1,398 execution files per framework and 2,986 explicit scalar pairs. This Linux subset uses source-proven assertion operands instead. Most remaining tests need recorded theory inputs, fixture-aware normalization, strings/collections or live Linux AD execution. They are **not silently counted as passing**. Re-running the full original Windows suite on Linux unchanged would not be valid.

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
python3 tests/linux/RecordedMicrosoft/extract_offline_oracle.py /tmp/offline-oracle.json
python3 tests/linux/RecordedMicrosoft/extract_reviewed_assertions.py /tmp/reviewed-assertions-oracle.json
python3 tests/linux/RecordedMicrosoft/coverage_inventory.py /tmp/coverage-inventory.json
```

The runner rejects non-Linux execution, missing/unconsumed/extra observations, and any scalar mismatch. Successful output explicitly says the remaining suite is not covered. `Linux recorded Microsoft oracle (partial)` is a manual-only workflow; it receives no repository AD secrets.
