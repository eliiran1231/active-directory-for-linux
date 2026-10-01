# Compatibility coverage branch

Base: `dev` at `8023db6d6e63752420628a1ad94871f4dbe2edf0` (2026-10-01).
Only tests and their documentation are added. Microsoft System.DirectoryServices
9.0.0 is the runtime oracle; new cases do not prescribe guessed exception contracts.

## Batch 1: boundaries, state transitions and copy contracts

| Class | Discovered cases | Execution requirement | Coverage |
| --- | ---: | --- | --- |
| `CompatibilitySearcherStateComparisonTests` | 39 | Windows, no AD | Three timeout properties at exact tick/Int32-second limits; cache/VLV, scope/attribute and paging/DirSync rejection, reset and recovery sequences |
| `CompatibilityVlvStateComparisonTests` | 21 | Windows, no AD | Derived percentages, overflow/rounding boundaries, zero and changing totals, failed setters, target and context identity |
| `CompatibilitySynchronizationComparisonTests` | 20 | Windows, no AD | Full-width 64-bit masks through constructors/setter, independent copies, reset options and buffer aliasing |
| `CompatibilitySearchResultCopyComparisonTests` | 78 | Disposable Windows AD lab | Typed and ICollection copies of 0/1/2 rows; index/capacity/type/rank/lower-bound boundaries; destination contents after failure |

Total: **158 new cases**, including **80 offline** and **78 live** cases.
Cases compare state after individual operations, exception types and parameter
names. Copy tests also compare every destination slot and identity within each
source collection; they do not depend on server result ordering. Live source
queries are restricted to GUID-suffixed fixture accounts, and cardinality is
checked before copy observations.

## Batch 2: result and enumerator lifecycle, deferred errors, VLV responses

| Class | Discovered cases | Coverage |
| --- | ---: | --- |
| `CompatibilitySearchResultLifecycleComparisonTests` | 30 | Reference identity before/after materialization, Contains/IndexOf, cached and unmaterialized collection access after disposal |
| `CompatibilityChildEnumeratorComparisonTests` | 10 | Current boundaries, Reset before/within/after traversal, repeated replay in empty and three-child private subtrees |
| `CompatibilityDeferredSearchErrorComparisonTests` | 12 | Malformed filters and valid empty controls across cached/uncached/asynchronous search; failure stage, type, HResult, parameter and recovery on the same searcher |
| `CompatibilityVlvResponseComparisonTests` | 3 | Real sorted VLV searches at positions 1/2/3 of three fixture rows; response state and retained configuration identity |

All **55 batch-2 cases require the disposable Windows AD lab**. Cumulative:
**213 cases (80 offline, 133 live)**. Batch 2 builds both target frameworks with
zero warnings/errors; discovery reports all 213 cases, and fixture registration
passes 19/19 without constructing fixtures. Windows oracle/AD execution remains
unrun. The child enumerator tests create and finally delete a unique private
subtree; the other new tests reuse the fixture's existing rows.

Source-backed hypotheses, not runtime-confirmed findings:

- Microsoft's [SearchResultCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs)
  separately materializes its inner list and creates public result enumerators;
  the clone reuses row objects. Cached collection access after disposal may also
  differ. Comparisons normalize DNs and never require matching LDAP order.
- Microsoft's [DirectoryEntries](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntries.cs)
  has an explicit resettable child enumerator, whereas the clone returns a C#
  iterator. Actual Microsoft Current and Reset outcomes remain the oracle.
- Invalid filters can fail at ExecuteSearch or during the first row retrieval.
  The tests record the failing stage rather than treating any exception anywhere
  as parity. A corrected empty search must subsequently succeed.
- Microsoft's [DirectorySearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs)
  assigns response Offset, ApproximateTotal and TargetPercentage; the final
  percentage assignment recalculates Offset. The clone applies a different
  update sequence. These cases use real response controls, unlike the existing
  synthetic setter-sequence test, and retain the exact 3/3 control.

## Findings and prior-work check

All newly covered gaps remain **suspected/unconfirmed** until the Windows oracle
runs. Particularly useful probes are VLV arithmetic beyond small integer totals,
DirSync high-bit validation, and SearchResultCollection's manual copy loops
(validation timing and partial writes). Passing controls are deliberately retained.

Reviewed recent PRs through #201 via the GitHub connector. #167 already fixes
negative PageSize and result-property lookup; existing tests cover these, so this
batch does not report them as new gaps. #200 remains open at
`a7b6ea56879756e7ba3c76d4d9052e6363f4edf2` and contains credential-wrapper/unbound
commit changes plus staged-attribute coverage for unsaved children. Those cases
are excluded here. Prior collection, schema, extension-cache and disposal fixes
in #172–#198 were checked against current test files before selecting this batch.
No workflow was dispatched, listener activated, issue opened, or production fix
made. No AD operation was executed locally.

## Validation

On Linux with temporary .NET SDK 10.0.401:

```sh
dotnet build tests/AdForLinux.DifferentialTests -c Release
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --list-tests --filter 'Category=CompatibilityCoverageOffline|Category=CompatibilityCoverageLive'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --filter 'FullyQualifiedName~FixtureRegistrationTests'
dotnet test tests/AdForLinux.FunctionalTests -c Release -f net10.0 --filter 'FullyQualifiedName~DirectoryEntryLocalStateTests|FullyQualifiedName~CollectionCompatibilityTests'
git diff --check
```

Both differential target frameworks build with zero warnings/errors. Discovery
reports all 158 new cases. The selected existing functional checks pass 27/27.
Fixture registration checks validate live-test wiring without constructing AD
fixtures. These checks validate compilation/registration, not oracle parity.

Windows differential execution and live AD behavior are **unrun** here. On Windows,
the offline batch needs no credentials or AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests -c Release --filter 'Category=CompatibilityCoverageOffline' --logger 'trx;LogFilePrefix=compatibility-offline'
```

Only after verifying a disposable isolated AD lab and configuring the existing
fixture settings should `Category=CompatibilityCoverageLive` run. The fixture
creates and deletes all its entries, including computers, in its configured
`UsersContainer`. Verify the effective container including any
`AD_USERS_CONTAINER_DN` override; never use production or shared directories.
Do not run the entire suite as an offline
check. Keep net8.0-windows and net10.0-windows outcomes separate when reporting
failures, and preserve the Microsoft/clone observations from each failing case.
