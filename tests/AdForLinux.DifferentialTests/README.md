# Differential tests (run these on Windows)

For the current expanded compatibility results, implementation changes and
remaining limitations tracked by #203, see
[COMPATIBILITY-COVERAGE.md](COMPATIBILITY-COVERAGE.md#issue-203-implementation-status-2026-10-03).
Historical failure counts below describe their original test batches.

These tests compare **the real Microsoft library** with **our Linux clone**.

They cannot run on Linux, because `System.DirectoryServices` and
`System.DirectoryServices.AccountManagement` only work on Windows. So this
project is **not** part of the Linux/Docker test run. You run it yourself on a
Windows machine.

> The project *compiles* on Linux (that is checked in CI-style by building it),
> but every Microsoft call throws `PlatformNotSupportedException` at runtime
> there. Windows is required to actually run it.

## What they do

Each test runs the *same* operation twice:

1. with Microsoft's library (aliased as `Ms` in the code)
2. with our library (aliased as `Ours`)

then compares the answers. Because the two libraries use different namespaces,
both can be referenced at the same time with no clash.

Differences are collected and reported together, so one failure shows you every
property that disagreed, not just the first.

### What is covered

| File | Compares |
| --- | --- |
| `UserPrincipalComparisonTests` | user properties, account state (dates, flags, lockout), `FindByIdentity`, date-based finders, `ValidateCredentials` |
| `GroupPrincipalComparisonTests` | group properties, `Members`, `GetMembers`, `GetGroups`, `GetAuthorizationGroups` |
| `DirectoryEntryComparisonTests` | `DirectoryEntry` properties, `DirectorySearcher` `FindOne`/`FindAll` |
| `DirectoryEntryAuthenticationComparisonTests` | invalid `AuthenticationTypes` combinations against the Windows LDAP ADSI provider |
| `DirectoryEntryCopyComparisonTests` | real-AD `CopyTo` matrix for user, group, computer, and OU objects, both overloads, identity/security/source state, and failure results |
| `ObjectSecurityComparisonTests` | live DACL round trips, partial `SecurityMasks`, and cached versus immediate `ObjectSecurity` writes |
| `PrincipalSearcherComparisonTests` | query-by-example search, including wildcards |
| `PublicApiSurfaceComparisonTests` | every exported type in the two claimed namespaces, including declared members, modifiers, accessors, contract attributes, generic constraints, and usable nullable metadata |

### Reflection-oracle scope and allowlist

`PublicApiSurfaceComparisonTests` compares every exported type whose namespace is
exactly one of the following pairs:

- `System.DirectoryServices` and `AdForLinux.DirectoryServices`
- `System.DirectoryServices.AccountManagement` and
  `AdForLinux.DirectoryServices.AccountManagement`

The exact-namespace check deliberately excludes
`System.DirectoryServices.ActiveDirectory`; AdForLinux does not currently claim
that API. It also excludes the implementation-only `AdForLinux.DirectoryServices.Ldap`
namespace.

For each claimed type, the oracle compares type kind, visibility, base type,
interfaces, abstract/sealed modifiers, generic constraints, and every declared
externally visible constructor, method, property, event, and field. Property and
event accessors are inspected with non-public reflection so a private or protected
accessor change is visible. Contract custom attributes and DirectoryServices
nullable metadata are included. The Microsoft AccountManagement reference
assembly reports all nullable states as `Unknown`, so nullable comparison for
that namespace is intentionally disabled until the reference provides usable
metadata.

Intentional differences live in the `IntentionalDifferences` set in the test.
Entries are exact descriptors rather than member-name wildcards, and stale
entries fail the test. The current groups are:

- Linux/LDAP conveniences: `DirectoryEntry.DistinguishedName`, portable SID and
  connection properties, and `PrincipalSearcher.GetLdapFilter`.
- generic enumeration/readonly-list conveniences used by Linux and LINQ callers.
- four documented metadata-only differences: the Windows designer converter,
  honest nullable metadata for `DirectoryEntry.Parent`,
  `DirectoryEntry.Options` nullability, and normalized `DirectorySearcher.Filter`
  getter nullability. `Parent` intentionally stays nullable because an LDAP
  naming-context root has no parent.

Any new extension, including a future LINQ API, therefore requires an explicit,
reviewable allowlist entry; unrelated public-surface drift fails with side-by-side
Microsoft/AdForLinux descriptors.

## How to run

1. Use a Windows machine that can reach a domain controller.
2. Set these environment variables (PowerShell):

   ```powershell
   $env:AD_HOST    = "your-dc.example.com"
   $env:AD_PORT    = "636"
   $env:AD_USE_TLS = "true"
   $env:AD_BIND_DN = "administrator@example.com"
   $env:AD_BIND_PW = "yourPassword"
   $env:AD_BASE_DN = "OU=MyIsolatedRun,OU=CI,DC=example,DC=com"
   ```

   Use an isolated writable OU for `AD_BASE_DN`; mutation tests create their
   temporary objects directly below it. For a legacy domain-root run, the suite
   instead uses `CN=Users,<AD_BASE_DN>`. Set `AD_USERS_CONTAINER_DN` explicitly
   only when a different writable principal container is required.

   Set `AD_USE_TLS=false` with port 389 for a disposable test DC that permits
   simple LDAP binds. The ObjectSecurity fixture does not set a password, so it
   can exercise Microsoft and AdForLinux behavior without requiring LDAPS.

3. Run:

   ```powershell
   dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows
   dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows
   ```

The tests create their own temporary user and two groups in the configured
writable container and delete them at the end.

### Offline compatibility regressions

The following comparisons require Windows but no domain controller or `AD_*`
environment variables. They were verified against the referenced Microsoft
9.0.0 package on both `net8.0-windows` and `net10.0-windows`.

| Trigger | Microsoft behavior | Current AdForLinux behavior |
| --- | --- | --- |
| Mutate `SchemaNameCollection` after starting enumeration (add, replace, remove, clear) | Existing enumerator remains usable | Next `MoveNext()` throws `InvalidOperationException` |
| Read/write schema-filter index -1 or Count | `IndexOutOfRangeException` | `ArgumentOutOfRangeException` |
| Negative `DirectorySearcher.SizeLimit`, or incompatible `AttributeScopeQuery` / `SearchScope` assignment | `ArgumentException.ParamName` is null | `ParamName` is `value` |
| Access/audit rule construction with inheritance -1 or 5 | `InvalidEnumArgumentException.ParamName` is `inheritanceType` | `ParamName` is `value` |

The schema collection tests reuse the existing delegate-backed Microsoft fixture,
so they isolate collection behavior from ADSI. Structural mutations replace its
backing array; an existing enumerator retains the old contents. Indexer replacement
updates the array in place in this fixture and is visible to that enumerator.
These tests do not establish how a particular live ADSI provider marshals arrays.
The validation tests compare exception types and parameter names, not localized
exception messages, and the searcher tests also compare state after rejection.

Run just these classes (repeat with `net8.0-windows`):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~SchemaNameCollectionComparisonTests|FullyQualifiedName~SearcherValidationContractComparisonTests|FullyQualifiedName~SecurityRuleValidationComparisonTests"
```

At the time these regressions were added, each framework reported 15 new failing
cases exposing the differences above and 3 passing existing schema-collection
cases. The tests intentionally assert compatibility, so the new cases remain red
until the implementation is corrected.

### Constructor, principal collection, and deferred-error regressions

These additional offline comparisons were run on Windows against the referenced
Microsoft 9.0.0 packages on both `net8.0-windows` and `net10.0-windows`.
Each framework reported **23 failing cases and 7 passing controls (30 total)**.
They assert equality with Microsoft, so failures are intentional until the
implementation is corrected. No production implementation changes accompany them.

| Test class / trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| `SearcherConstructorFilterComparisonTests`: pass null or empty filter to any of the six filter-taking constructors | Preserves the supplied null/empty value; a later setter assignment normalizes it to `(objectClass=*)` | Normalizes during construction as well | 12 |
| `PrincipalValueCollectionOfflineComparisonTests`: call non-generic `IList.Add` on a string collection | Returns the new Count (1, 2, 4 in these cases) | Returns the zero-based index (0, 1, 3) | 3 |
| Same class: read generic enumerator `Current` before starting, after finishing, or after Reset | Throws `InvalidOperationException` | Returns null | 3 |
| Same class: read `Current`, call `MoveNext`, or call `Reset` after enumerator disposal | Throws `ObjectDisposedException` | Allows the operation | 3 |
| `ResultPropertyDeferredErrorComparisonTests`: index a result value containing a deferred exception | Rethrows the stored exception instance | Returns the exception as an ordinary value | 2 |

The six nonempty constructor-filter cases and the positioned-enumerator case
are passing controls. The deferred-error tests also check adjacent readable
values, Contains, IndexOf, and CopyTo before comparing indexed error access.

The collection fixtures invoke Microsoft's normal non-public constructors,
as other offline collection tests do. They do not edit private fields or use
uninitialized objects. Operations under comparison are public APIs. In
particular, the deferred-error fixture supplies the payload normally produced by
ADSI value decoding; it proves collection behavior, not which live directory
attributes will trigger a conversion failure. The principal collection fixture
avoids PrincipalContext discovery and does not test persistence to AD.

The relevant Microsoft source is
[DirectorySearcher.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs),
[ValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs),
[TrackedCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollectionEnumerator.cs), and
[ResultPropertyValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ResultPropertyValueCollection.cs).
The tests use the actual Microsoft assembly as the oracle rather than hardcoding
replacement behavior from these sources.

Run just these new comparisons (repeat with `net8.0-windows`):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~SearcherConstructorFilterComparisonTests|FullyQualifiedName~PrincipalValueCollectionOfflineComparisonTests|FullyQualifiedName~ResultPropertyDeferredErrorComparisonTests"
```

### Principal collection edge cases and search projection state

`PrincipalValueCollectionEdgeCaseComparisonTests` runs without AD. Against the
Microsoft 9.0.0 package, both `net8.0-windows` and `net10.0-windows` reported
**14 failing cases and 13 passing controls (27 total)**. These are additional
regressions beyond the collection tests above:

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Copy an empty collection at `index == array.Length`, including a zero-length array, through either CopyTo API | Throws `ArgumentException` | Succeeds | 4 |
| CopyTo with both a null array and negative index | Throws `ArgumentOutOfRangeException` for `index` | Throws `ArgumentNullException` | 2 |
| Generic indexer assignment with both an invalid index and null value | Throws `ArgumentOutOfRangeException` for `index` | Throws `ArgumentNullException` for `value` | 2 |
| Continue enumeration after Remove of a missing value, invalid Insert/RemoveAt, or null Insert/indexer assignment | Invalidates the enumerator; subsequent MoveNext/Reset throws `InvalidOperationException` | Enumerator remains usable | 6 |

Each comparison checks exception type and parameter name, or the returned value,
and checks collection/destination contents where applicable. Controls cover
ordinary copying, nonzero array lower bounds, numeric widening, non-generic
indexer validation, and successful mutation/read behavior. Microsoft collection
instances use the normal internal empty constructor, as in the existing offline
tests. No private fields are changed. The enumerator tests wait for a UTC clock
tick before mutation because Microsoft's change tracking uses timestamps.

`SearcherProjectionStateComparisonTests` adds **8 live AD cases**, covering
FindOne and FindAll with an explicit projection, lowercase `adspath`, already
present `ADsPath`, and an empty projection. Each search runs twice and compares
`PropertiesToLoad`; FindAll also compares `PropertiesLoaded`. Microsoft's source
adds canonical `ADsPath` to a nonempty projection if that exact spelling is
absent, while AdForLinux leaves the projection unchanged. These tests build on
both frameworks but **have not been run against AD locally**; the four explicit
and lowercase-projection cases are expected to expose that difference. The
existing fixture supplies the temporary user; the searches do not modify it.

Source references:
[ValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs),
[TrackedCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollection.cs),
[TrackedCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollectionEnumerator.cs), and
[DirectorySearcher.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs).

Run the new comparisons (repeat with `net8.0-windows`):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~PrincipalValueCollectionEdgeCaseComparisonTests|FullyQualifiedName~SearcherProjectionStateComparisonTests"
```

To run without AD, filter only `PrincipalValueCollectionEdgeCaseComparisonTests`.
The tests assert compatibility and intentionally remain red until fixes land.

### Result-property lookup and PageSize regressions

`ResultPropertyLookupComparisonTests` and the new `PageSize` case in
`SearcherValidationContractComparisonTests` add nine offline cases. Against the
Microsoft 9.0.0 package on Windows, both `net8.0-windows` and `net10.0-windows`
reported **7 new failures and 2 passing controls**. Including the three existing
searcher validation cases, the command below reports 7 failures and 5 passes.

| Trigger | Microsoft behavior | AdForLinux behavior |
| --- | --- | --- |
| Assign null through `ResultPropertyCollection`'s public `IDictionary`, then read the typed indexer | Returns null for the present key | Returns an empty collection |
| Assign a string or integer through `IDictionary`, then read the typed indexer | Throws `InvalidCastException` | Silently returns an empty collection |
| Read missing properties repeatedly, under different keys, or from different result collections | Returns distinct empty collections | Returns the same static empty collection |
| Set `DirectorySearcher.PageSize` to -1 after a valid assignment | Throws `ArgumentException` with null `ParamName` | Throws `ArgumentException` with `ParamName == "value"` |

The first two behaviors share the same type-test fallback in AdForLinux's
indexer. The missing-property identity difference is observable through
`ReferenceEquals`; these tests do not claim that empty values differ in content.
Controls cover a correctly typed dictionary value and lookup after removal.
The PageSize case also checks that rejection preserves searcher state.

The result fixture invokes Microsoft's normal internal empty constructor, as
the existing dictionary mutation tests do; it does not modify private fields.
All operations under comparison are public. This establishes collection behavior
after caller mutation, not which payloads a directory server returns. No domain
controller or `AD_*` variables are needed, and no production code was changed.

Source references:
[ResultPropertyCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ResultPropertyCollection.cs)
and
[DirectorySearcher.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs).

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~ResultPropertyLookupComparisonTests|FullyQualifiedName~SearcherValidationContractComparisonTests"
```

Repeat with `net8.0-windows`. The tests assert compatibility and intentionally
remain red until the implementation is corrected.

### Searcher disposal and synchronization cookie identity

`PrincipalSearcherDisposalComparisonTests` and
`SynchronizationCookieIdentityComparisonTests` add 16 offline comparisons using
only public constructors and APIs. On Windows with the Microsoft 9.0.0 packages,
both `net8.0-windows` and `net10.0-windows` reported **8 failing cases and 8 passing
controls**. They require no AD configuration and intentionally assert equality
with Microsoft, so the incompatibilities remain red until fixed.

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Read `PrincipalSearcher.QueryFilter` after `Dispose()` | Throws `ObjectDisposedException` | Returns null | 1 |
| Assign null to `PrincipalSearcher.QueryFilter` after `Dispose()` | Throws `ArgumentNullException` for `QueryFilter` | Throws `ObjectDisposedException` | 1 |
| Read an empty `DirectorySynchronization` cookie twice | Returns distinct empty arrays | Returns the same empty array | 6 |

The disposal cases use an ordinary, unconfigured searcher. Controls check the
same getter and null assignment before disposal, plus five other members after
disposal. The cookie cases cover default construction, empty/null input, and
parameterless/null/empty reset after a nonempty cookie. Nonempty cookie reads
are a passing control. Both returned cookie contents and reference identity are
compared: the empty-cookie difference is observable via `ReferenceEquals`, not
a difference in bytes or evidence of data corruption.

The relevant Microsoft sources are
[PrincipalSearcher.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs)
and
[DirectorySynchronization.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySynchronization.cs).
The tests use the actual assemblies as their oracle. No production code changes
accompany these tests.

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~PrincipalSearcherDisposalComparisonTests|FullyQualifiedName~SynchronizationCookieIdentityComparisonTests"
```

Repeat with `net8.0-windows`.

### Extension attributes and property collection regressions

`ExtensionAttributeConstructionComparisonTests` and
`PropertyCollectionValidationComparisonTests` add 18 offline comparisons. With
the Microsoft 9.0.0 packages on Windows, both target frameworks reported
**10 failing cases and 8 passing controls**:

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Null constructor argument for `DirectoryPropertyAttribute`, `DirectoryRdnPrefixAttribute`, or `DirectoryObjectClassAttribute` | Stores null | Throws `ArgumentNullException` | 3 |
| Integer or object key for `PropertyCollection` through `IDictionary` indexer or `Contains` | Throws `InvalidCastException` | Returns null or false | 4 |
| Null key for `PropertyCollection` through `IDictionary` indexer | Throws `ArgumentNullException` for `propertyName` | Returns null | 1 |
| Null key for the typed property indexer | `ArgumentNullException.ParamName` is `propertyName` | Parameter is `key` | 1 |
| Negative index for `PropertyCollection`'s `ICollection.CopyTo` | `ArgumentOutOfRangeException.ParamName` contains the localized lower-bound error text | Parameter is `index` | 1 |

Controls cover empty and nonempty attribute constructor values, null CopyTo
destinations, and multidimensional destinations. Exception types and parameter
names are compared directly against Microsoft in the same process; localized
text is not hardcoded. The Microsoft property collection comes from an unbound
`DirectoryEntry`. These invalid operations fail before binding. Our collection
uses its normal internal constructor, following the existing dictionary tests,
to isolate validation from our eager-binding `DirectoryEntry.Properties` getter.
No private fields are changed.

`PropertyCollectionMissingLookupComparisonTests` adds **3 live AD cases** for
`Contains`, `Count`, and `PropertyNames` after reading an absent attribute. The
Microsoft source keeps cached value wrappers separate from the provider's
property list; our implementation adds the empty wrapper to the dictionary that
also supplies membership, count, and names. These cases build on both frameworks
but **have not been run against AD locally**. They reuse the registered fixture,
perform only reads, and compare count/name changes relative to each library's own
baseline so unrelated initial projection differences cannot cause a failure.

Source references:
[ExtensionAttributes.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ExtensionAttributes.cs)
and
[PropertyCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyCollection.cs).

Run all new comparisons with AD configured (repeat with `net8.0-windows`):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~ExtensionAttributeConstructionComparisonTests|FullyQualifiedName~PropertyCollectionValidationComparisonTests|FullyQualifiedName~PropertyCollectionMissingLookupComparisonTests"
```

For an offline run, omit `PropertyCollectionMissingLookupComparisonTests` from
the filter. These tests assert compatibility and intentionally remain red until
the implementation is corrected. This change adds tests only, with no production
fixes.

### Collection compatibility regressions without AD

`PrincipalValueCollectionComparisonTests` and `SchemaNameCollectionComparisonTests`
exercise managed collection behavior without a domain controller or environment
variables. Run just these classes on Windows:

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows --filter "FullyQualifiedName~PrincipalValueCollectionComparisonTests|FullyQualifiedName~SchemaNameCollectionComparisonTests"
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~PrincipalValueCollectionComparisonTests|FullyQualifiedName~SchemaNameCollectionComparisonTests"
```

The regression cases expose these differences against Microsoft package 9.0.0:

| Operation | Microsoft | AdForLinux before fixes |
| --- | --- | --- |
| `PrincipalValueCollection<T>` through `IList.Add` | Returns the new count | Returns the inserted index (one less) |
| Generic enumerator `Current` before the first item or after the last | Throws `InvalidOperationException` | Returns `default(T)` |
| Disposed principal-value enumerator: `Current`, `MoveNext`, `Reset` | Throws `ObjectDisposedException` | Still allows operations |
| Empty principal-value collection copied at `index == array.Length` | Throws `ArgumentException` | Succeeds |
| Typed principal-value indexer assigned null at an invalid index | Throws `ArgumentOutOfRangeException` for `index` | Throws `ArgumentNullException` for `value` |
| Schema-name enumeration after add, remove, or clear | Continues over its captured array | Throws `InvalidOperationException` |
| Schema-name indexer read/write outside bounds | Throws `IndexOutOfRangeException` | Throws `ArgumentOutOfRangeException` |

These are equality tests against the actual Microsoft implementation, so they
intentionally fail until compatibility is restored. The cases also check matching
collection contents and include valid-position, non-generic, and in-bounds copy
controls. They do not assert localized exception messages.

On Windows, the September 25, 2026 run against the implementation at `af949cc`
produced the same result on both target frameworks: 25 failing regression cases
and 13 passing cases across these two classes. All eight fixture-registration
checks also passed. This change adds 35 cases and leaves production code unchanged.

Construction is isolated from AD: reflection invokes the normal internal
principal-value constructors and supplies in-memory getter/setter delegates to
Microsoft's schema-name constructor, as in the existing schema tests. All tested
operations use public APIs. These tests establish managed collection behavior;
they do not exercise ADSI binding, schema filtering on a server, or persistence.

Reference implementations for the pinned package are
[ValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs),
[TrackedCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollection.cs),
[TrackedCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollectionEnumerator.cs), and
[SchemaNameCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SchemaNameCollection.cs).

### Fixture registration check without AD

The fixture registration guard can run on both runtimes on Linux or Windows. It
checks that every test class requesting `TestDataFixture` registers it with
xUnit, without constructing a fixture or calling either directory API:

```sh
dotnet test tests/AdForLinux.DifferentialTests --filter FullyQualifiedName~FixtureRegistrationTests
```

The full differential suite still requires Windows and the AD lab. If the
workflow fails in **Create per-run test OU** with rejected client credentials,
no comparison tests have run. Verify the `ad-lab` environment's
`AD_LAB_BIND_DN` and `AD_LAB_ADMIN_PASSWORD`, account status, and access to the
configured CI root OU before rerunning. Use a UPN or `DOMAIN\username` identity
that also works with Windows authentication; a successful LDAP simple bind
alone does not verify the credentials used by AD Web Services or Microsoft's
forest discovery.

## `DirectoryEntry.CopyTo` protocol limitation

The real-AD matrix found that Microsoft's Windows LDAP ADSI provider returns
`E_NOTIMPL` (`NotImplementedException`, HRESULT `0x80004001`) for both
`CopyTo(parent)` and `CopyTo(parent, newName)`. This was observed for valid user,
group, computer, and organizational-unit sources and valid destination
containers. No destination object is created, and the source DN, object class,
attributes, identity fields, account state, and security descriptor remain
unchanged. Consequently, copied/defaulted attributes, a resulting name/DN, and
copied security are not applicable; there is no Microsoft LDAP copy result to
reproduce.

`System.DirectoryServices.DirectoryEntry.CopyTo` delegates to ADSI
`IADsContainer.CopyHere`. LDAP itself defines no server-side copy operation. A
portable read-plus-Add emulation cannot reproduce server decisions for schema
defaults, object identity and uniqueness, SPN/DNS fields, account state,
security descriptor inheritance, or transactional/subtree behavior. The
library therefore matches the observed LDAP provider by throwing
`NotImplementedException` instead of creating a materially different object.

### Advanced-filter deferral and native GUID representation

`AdvancedFilterDeferralComparisonTests` adds 33 offline comparisons using the
Microsoft 9.0.0 package as the oracle. Both `net8.0-windows` and
`net10.0-windows` produced **22 failing cases and 11 passing controls**:

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Configure any of the six built-in advanced filters with `MatchType` -1 or 6 | Accepts the criterion during configuration | Immediately throws `InvalidEnumArgumentException` | 12 |
| Configure any of the five date filters with UTC January 1 in year 1 or 1600 | Stores the date during configuration | Immediately converts to FILETIME and throws `ArgumentOutOfRangeException` | 10 |

The controls use `MatchType.Equals` and the UTC FILETIME epoch (1601-01-01).
Every case also compares replacing the criterion with a valid value. Normal
protected constructors are exposed through small test subclasses; no reflection,
private-field mutation, PrincipalContext, or directory connection is involved.
These tests establish when configuration throws, not whether a later search
accepts the criterion. The clone's eager conversion also prevents callers from
replacing a placeholder date before executing a query.

`NativeGuidRepresentationComparisonTests` adds **3 live AD comparisons** for
the fixture's user, group, and computer. They first verify equal nonempty `Guid`
values, then compare `NativeGuid` verbatim. The clone uses `Guid.ToString("B")`,
whereas Microsoft's LDAP provider returns its native hexadecimal string. Parsing
or normalizing the strings would hide the suspected representation mismatch.
These cases compile on both targets but **have not been run against AD locally**.
They only read existing fixture objects and register `TestDataFixture` normally;
the offline fixture-registration checks passed on .NET 8.

Source references:
[AdvancedFilters.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AdvancedFilters.cs)
and
[DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs).

Run the new comparisons with AD configured (repeat with `net8.0-windows`):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~AdvancedFilterDeferralComparisonTests|FullyQualifiedName~NativeGuidRepresentationComparisonTests"
```

For an offline run, use only `FullyQualifiedName~AdvancedFilterDeferralComparisonTests`.
The assertions intentionally require parity, so the confirmed incompatibilities
remain red. This change adds tests and documentation only.

### Principal extension cache and equality after disposal

`PrincipalExtensionCacheComparisonTests` and
`PrincipalEqualityDisposalComparisonTests` add 21 offline comparisons. On Windows,
with the pinned Microsoft 9.0.0 packages, both `net8.0-windows` and
`net10.0-windows` produced **17 failing cases and 4 passing controls**.
The 11 existing fixture-registration checks also passed on both targets.

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Mutate an array supplied to `ExtensionSet`, or an array returned by `ExtensionGet` | Later reads observe the mutation | Copies isolate the cache from the mutation | 5 |
| Write `description`, then `Description` or `DESCRIPTION` | Keeps separate cached values for the two spellings | Case-insensitive cache overwrites the first value | 2 |
| Read an already cached extension, or write an extension, after disposal | Accepts the cached operation | Throws `ObjectDisposedException` | 2 |
| Null attribute name, empty collection, or nested collection passed to the extension API | Throws `ArgumentException` with null `ParamName` | Supplies `attribute` or `value` as `ParamName` | 6 |
| Compare two distinct principals when the left operand is disposed | Returns `false` for these principals without stored identities | Throws `ObjectDisposedException` when reading the left operand's `Guid` | 2 |

The tests use small subclasses exposing normal protected `Principal`
constructors and `ExtensionGet`/`ExtensionSet`. No reflection, private-field
mutation, `PrincipalContext`, directory discovery, or AD connection is needed.
The cache tests establish managed staging behavior, not server attribute-name
matching or persistence. The disposal control for an uncached read confirms that
both libraries still throw when that read would need the underlying object.
Exact-spelling replacement and comparisons with a live left operand are the
other passing controls.

Each assertion compares the actual Microsoft result with the clone. Failures are
intentional compatibility regressions; this change does not fix production code.
Reference implementation:
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs)
and
[ExtensionCache.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ExtensionCache.cs).

Run these comparisons on both target frameworks without configuring AD:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PrincipalExtensionCacheComparisonTests|FullyQualifiedName~PrincipalEqualityDisposalComparisonTests"
```

### Rejected null mutations and principals without a context

The added cases in `PrincipalValueCollectionEdgeCaseComparisonTests` and the new
`PrincipalMissingContextComparisonTests` add **14 offline comparisons**. Against
Microsoft 9.0.0 on Windows, both target frameworks produced **9 failing new cases
and 5 passing controls**. Running both complete classes plus
`FixtureRegistrationTests` produced 9 failures and 43 passes per framework.

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Generic `PrincipalValueCollection<string>.Add(null)` or `Remove(null)`, followed by `MoveNext` or `Reset` on an existing enumerator | Rejects the mutation with `ArgumentNullException`; traversal remains usable | Rejects the mutation but invalidates traversal with `InvalidOperationException` | 4 |
| Read `ContextType` on a custom principal before assigning a context | `InvalidOperationException` | `NullReferenceException` | 1 |
| Set `Description`, `DisplayName`, `UserPrincipalName`, or `SamAccountName` before assigning a context | Setter and subsequent getter throw `NullReferenceException` | Accepts and returns the staged value | 4 |

The null-mutation cases also compare the mutation exception and unchanged
collection contents. Equivalent non-generic `IList` calls are four passing
controls. The fifth control checks that disposal takes precedence over the
missing context when reading `ContextType`.

The custom principals invoke the normal protected constructor and expose only
inherited public behavior. These cases describe observable compatibility at an
incomplete initialization boundary, not a recommendation to use Microsoft's
contextless property setters. No private fields or uninitialized objects are
used. The collection fixture invokes the normal internal constructor as in the
existing offline tests. No domain controller or `AD_*` settings are required.

The source paths responsible are `PrincipalValueCollection.cs` (`Add` and
`Remove` increment `_version` before checking null) and `Principal.cs`
(`ContextType` dereferences `ContextRef`; property setters stage values without
consulting a store context). Reference implementations:
[ValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs)
and
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs).

Run the comparisons on both target frameworks:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PrincipalMissingContextComparisonTests|FullyQualifiedName~PrincipalValueCollectionEdgeCaseComparisonTests"
```

These assertions require parity and intentionally remain red until the
implementation is corrected. This change contains tests and documentation only.

### Object-constructor validation and principal result boundaries

These tests contain **19 offline cases and 6 live-directory cases**. Before the
#179 fixes, AD workflow run 36774963542 reported **11 failures and 510 passes**
per framework: ten direct comparison failures and one incorrect assertion about
the Microsoft oracle. The table below records the behavior before the fixes.

| Trigger | Microsoft behavior | AdForLinux behavior |
| --- | --- | --- |
| `DirectoryEntry(object)` with null | `ArgumentException`, null `ParamName` | `ArgumentNullException`, `ParamName` = `adsObject` |
| Same overload with a plain object, boxed integer, or string typed as object | `ArgumentException`, null `ParamName` | `PlatformNotSupportedException` |
| `GetUnderlyingObjectType()` on a custom principal before assigning a context | `NullReferenceException` observed on the AD runner for both frameworks | Returns `DirectoryEntry` |

The earlier `InvalidOperationException` oracle assumption for this last case was
incorrect on the AD runner (run 36774963542). The test now compares the actual
Microsoft exception and returned type directly and records both libraries'
outcomes, the loaded Microsoft assembly identity/location, and runtime details.
The fixes for #179 reject non-IADs constructor inputs, validate search-result
enumerator positions independently of storage, and match the observed missing-context
exception while preserving disposal precedence.

`DirectoryEntryObjectValidationComparisonTests` passes only inputs that do not
implement ADSI's IADs interface. It does not require COM-object support or make a
directory connection. The new `PrincipalMissingContextComparisonTests` method
uses normal protected constructors; its disposed-principal case is a passing
control.

`PrincipalSearchResultPositionComparisonTests` checks generic and non-generic
`Current` before traversal, after exhaustion, and after reset. Its empty-result
cases all pass, including both array and list storage. The Microsoft fixture
uses the normal internal `EmptySet` and result constructors, as in the existing
lifecycle tests; it does not fabricate fields or use uninitialized objects.

`PrincipalSearchResultLivePositionComparisonTests` adds six corresponding cases
for a **populated** `PrincipalSearcher.FindAll()` result. Each verifies the seeded
user and single-row result before asserting the boundary behavior. These cases
failed on both frameworks in run 36774963542: Microsoft's
`FindResultEnumerator.Current` explicitly rejects invalid positions, whereas the
old AdForLinux implementation delegated to generic `List<Principal>.Enumerator.Current`,
which returns null at those positions for a nonempty list. Empty-list enumeration
uses a different enumerator, explaining why the offline controls passed. The fix
tracks valid position explicitly for both generic and non-generic access.

Run just the new cases on both targets (the live class requires the AD settings
documented above):

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~DirectoryEntryObjectValidationComparisonTests|FullyQualifiedName~Underlying_object_type_without_context|FullyQualifiedName~PrincipalSearchResultPositionComparisonTests|FullyQualifiedName~PrincipalSearchResultLivePositionComparisonTests"
```

For an offline-only run, omit the `PrincipalSearchResultLivePositionComparisonTests`
filter term. All 19 offline cases pass on both frameworks with the #179 fixes.

Reference implementations:
[DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs),
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs),
and [FindResultEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/FindResultEnumerator.cs).

### Custom advanced-filter validation, cache state, and disposal

`AdvancedFilterExtensionComparisonTests` adds 20 offline cases using normal
protected constructors and the supported subclass APIs. Against Microsoft 9.0.0,
both `net8.0-windows` and `net10.0-windows` reported **17 failures and 3 passing
controls**. The assertions require compatibility and intentionally remain red.

| Trigger | Microsoft behavior | AdForLinux behavior | Cases |
| --- | --- | --- | --- |
| `AdvancedFilterSet` with a null attribute | `ArgumentException`, null `ParamName` | `ArgumentNullException`, `ParamName` = `attribute` | 1 |
| Empty attribute, null value, or null object type | Accepts configuration | Rejects configuration | 3 |
| Empty object array, byte array, or list; nested object array | Rejects immediately with `ArgumentException` | Accepts configuration | 4 |
| Read `ExtensionGet` after configuring a custom filter, with or without a prior extension value | Returns null because the cache entry now represents a filter | Returns the old value or an empty array | 2 |
| Configure a retained filter after disposing its principal (six built-in methods and the custom setter) | Accepts configuration | Throws `ObjectDisposedException` | 7 |

The three controls configure a scalar, nonempty object array, and nonempty byte
array. Argument tests also check that a subsequent valid assignment succeeds;
disposal tests first verify the same operations on the same live instances.
These tests compare configuration and cache behavior only, not whether a server
will accept or execute the resulting query. No AD settings or private-state
manipulation are needed.

The relevant implementation is `AdvancedFilters.AdvancedFilterSet` and
`Principal.SetAdvancedFilter`: AdForLinux keeps custom criteria separately from
the extension cache and checks disposal while storing them. Microsoft's
[AdvancedFilters.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AdvancedFilters.cs)
and [Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs)
show the reference validation and shared-cache behavior. The tests use the
loaded Microsoft assembly as the oracle.

Run just these comparisons on both targets:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter FullyQualifiedName~AdvancedFilterExtensionComparisonTests
```

### Unsaved account state and authenticable-principal construction

`UnsavedAccountStateComparisonTests` adds 22 cases for public property state
before `Save`. It uses the configured AD context for Microsoft's discovery and
property validation, but never saves an object or modifies the directory.
`AuthenticableConstructorComparisonTests` adds two offline cases exposing the
protected constructors through ordinary subclasses.

The tests compare the actual Microsoft assembly with AdForLinux. The original
[AD run 36884032891](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36884032891)
confirmed 22 failures and two passing expiration controls on each framework.
The table records the behavior before the #183 fix:

| Trigger | Microsoft reference behavior | AdForLinux implementation |
| --- | --- | --- |
| Read unassigned `DelegationPermitted` on a new user/computer | Returns false from independent property state | Returns true by negating an absent `NOT_DELEGATED` bit |
| Assign another account flag before assigning `Enabled` | `Enabled` remains null | Initializes `userAccountControl`, making `Enabled` true |
| Assign `Enabled = true` with a queued password, including the credential constructor | Getter returns the requested true value | Getter exposes the temporary disabled creation state |
| Assign a local/unspecified expiration date | Preserves ticks and `DateTime.Kind` before save | Immediately converts through UTC FILETIME |
| Assign the FILETIME epoch as expiration | Preserves the assigned date before save | Reads FILETIME zero as null |
| Assign a pre-1601 expiration date | Caches the date before save | Throws during assignment and retains the previous date |
| Pass a null context to either protected `AuthenticablePrincipal` constructor | `ArgumentException`, null parameter name | `ArgumentNullException`, parameter `context` |

The expiration tests compare ticks **and Kind**, capture exception type and
parameter name, and verify recovery with a valid assignment. Ordinary UTC dates
and clearing the date are controls. Flag tests also exercise explicit false/true
`Enabled` assignments. No assumptions about server acceptance of unusual dates
or password persistence are made.

Reference source: Microsoft's
[AuthenticablePrincipal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AuthenticablePrincipal.cs)
and [AccountInfo.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs).
The corresponding clone code is in `AuthenticablePrincipal.cs` and `AdFileTime.cs`.

Run both new classes on both target frameworks with the usual AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~UnsavedAccountStateComparisonTests|FullyQualifiedName~AuthenticableConstructorComparisonTests"
```

For an offline-only run, filter to `AuthenticableConstructorComparisonTests`.
Both offline cases now pass against Microsoft 9.0.0 on `net8.0-windows` and
`net10.0-windows`. The fix keeps unsaved Enabled and delegation assignments
independent from the shared UAC flags, preserves the requested Enabled value
while a password is queued, and defers expiration conversion until persistence.
The create-disabled / set-password / enable sequence remains unchanged.

The complete [validating AD run 36887208728](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36887208728)
passed on both `net8.0-windows` and `net10.0-windows`: **565 passed, zero failed,
zero skipped per framework**. Its TRX artifacts confirm all 24 cases in these
two classes pass, including the two expiration controls, along with all 541
other comparisons. Test OU creation, artifact upload, and cleanup also passed.

The PR review identified a persistence path missing from those unsaved tests:
assigning `PasswordNeverExpires` and then queuing a password without assigning
`Enabled`. `DeferredPasswordBehaviorComparisonTests` now covers both flag/password
assignment orders through `Save`, comparing freshly loaded Enabled and password
flags with Microsoft and verifying that the password was initialized. Password
staging always sets ACCOUNTDISABLE for creation, independently of the public
Enabled state; only an explicit Enabled assignment requests later enablement.
The [post-review AD run 36897105277](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36897105277)
validated commit `993a206`: **567 passed, zero failed or skipped per framework**,
including both new persistence cases and all 565 previous comparisons. Test OU
cleanup also succeeded.

### Principal collection traversal state and copy bounds

`PrincipalValueCollectionTraversalAndCopyComparisonTests` adds 18 offline cases.
They invoke the normal internal collection constructor (as the other offline
collection tests do), then compare only public operations against Microsoft 9.0.0.
No AD configuration is required, and no implementation changes accompany them.

| Trigger | Microsoft behavior | AdForLinux behavior | Affected targets |
| --- | --- | --- | --- |
| Read a positioned enumerator's `Current` after clearing the collection or removing its last/current element | Returns the cached element | Throws `InvalidOperationException` | net8.0-windows |
| Exhaust an enumerator, append an element, then read `Current` without advancing again | Throws `InvalidOperationException` | Returns null | net8.0-windows |
| `CopyTo` with an index beyond the destination length, or insufficient remaining space | `ArgumentException` with null `ParamName` | `ArgumentException` with `ParamName = destinationArray` | Both targets |

The enumeration mismatch depends on the underlying runtime's `List<T>`
enumerator behavior: the clone delegates position validation to it, whereas
Microsoft tracks its own cached value and end state. Both generic and
non-generic `Current` are checked. The tests deliberately do not advance or
reset after mutation, so timestamp-based mutation detection is not involved.

Copy tests exercise both public copy interfaces and also check the destination
and unchanged source contents. Passing controls cover appending while positioned,
a valid copy, negative indices, and the exact destination boundary. Each test
logs both libraries' observations; assertions require equality and intentionally
remain red for the differences above.

Local validation on Windows with Microsoft 9.0.0: **10 failed / 8 passed** on
.NET 8.0.29, and **4 failed / 14 passed** on .NET 10.0.10. Both targets build.

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter FullyQualifiedName~PrincipalValueCollectionTraversalAndCopyComparisonTests
```

Reference implementation:
[TrackedCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollectionEnumerator.cs)
and [TrackedCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollection.cs).

### Copy failures and in-place logon-hours changes

`PrincipalValueCollectionCopyFailureComparisonTests` adds eight offline cases.
Local Windows runs against Microsoft 9.0.0 confirmed **two failures and six
passing controls per framework**, on .NET 8.0.29 and .NET 10.0.10:

| Trigger | Microsoft | AdForLinux |
| --- | --- | --- |
| Copy an empty `PrincipalValueCollection<string>` to an `int[]` through `ICollection.CopyTo` | Succeeds without changing the destination | Throws `ArgumentException` |
| Copy a nonempty string collection to an `int[]` | Throws `InvalidCastException` | Throws `ArgumentException` |

The reference copies individual elements with `Array.SetValue`, while the clone
delegates to `List<T>.CopyTo`. The controls check both copy interfaces with
covariant arrays (including partial writes before failure), successful copying,
and multidimensional destination rejection. Reflection only invokes the normal
internal Microsoft collection constructor, as in the existing offline tests.

`PermittedLogonTimesMutationComparisonTests` adds four **AD-dependent cases that
have been compiled but not run locally**. They create two disabled temporary
users in `DifferentialSettings.UsersContainer`, save a 21-byte logon-hours
bitmap, edit the returned array in place, save twice, and read each result using
a fresh principal. Both the original saved principal and a newly loaded
principal are exercised. Explicit setter reassignment supplies two controls.
Both temporary users are deleted in `finally`.

The suspected incompatibility is missing change tracking for in-place
`PermittedLogonTimes` edits. Microsoft compares the mutable bitmap against its
previous contents. The clone returns the entry's cached array, but its save path
only writes property collections marked changed by a setter or collection
mutation. Editing a byte does not mark that collection changed. The AD run is
needed to confirm the resulting persistence difference; these tests do not
claim a locally verified server result.

Reference source:
[TrackedCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollection.cs)
and [AccountInfo.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs).
No production code changes accompany these comparisons.

Run both new classes on both target frameworks with the usual AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PrincipalValueCollectionCopyFailureComparisonTests|FullyQualifiedName~PermittedLogonTimesMutationComparisonTests"
```

For an offline-only run, filter to `PrincipalValueCollectionCopyFailureComparisonTests`.

### Group constructor validation and member enumeration

`GroupConstructorValidationComparisonTests` adds four offline comparisons.
Local Windows runs against Microsoft 9.0.0 confirmed **four failures on each
target framework**, `net8.0-windows` and `net10.0-windows`:

| Null-context constructor call | Microsoft | AdForLinux |
| --- | --- | --- |
| `new GroupPrincipal(null)` | `ArgumentException`, null parameter name | Succeeds |
| Named overload with null or empty name | `ArgumentException`, null parameter name | `ArgumentNullException`, parameter `value` |
| Named overload with a nonempty name | `ArgumentException`, null parameter name | `NullReferenceException` |

`GroupMemberEnumeratorComparisonTests` adds 13 AD-dependent comparisons,
**compiled but not run locally**. They use normally constructed Domain contexts
and unsaved, empty groups. They never save a group or modify directory objects.
The following differences are predicted from the two implementations and await
the AD differential run:

| Operation | Microsoft source behavior | AdForLinux source behavior |
| --- | --- | --- |
| Generic or non-generic `Current` before starting or after exhaustion | Throws `InvalidOperationException` | Returns null from its underlying C# iterator |
| `Reset` before starting or after exhaustion | Resets traversal successfully | Throws `NotSupportedException` from its underlying C# iterator |
| `MoveNext` after clearing the collection, including after exhaustion | Throws `InvalidOperationException` | Does not detect the mutation and returns false |

Five controls cover unchanged empty enumeration and operations after enumerator
disposal. Clear tests wait for the clock to advance after enumerator construction
because Microsoft's change detection compares UTC timestamps. All tests log both
observations and assert compatibility; they are intended to fail until the
implementation is corrected. No production changes accompany them.

Reference implementation:
[Group.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Group.cs),
[PrincipalCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollection.cs),
and [PrincipalCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollectionEnumerator.cs).

Run both classes on both frameworks with the usual AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~GroupConstructorValidationComparisonTests|FullyQualifiedName~GroupMemberEnumeratorComparisonTests"
```

For an offline run, filter to `GroupConstructorValidationComparisonTests` only.

### Result-value enumeration and schema-name array copying

`ResultValueEnumeratorComparisonTests` adds 12 offline comparisons, and
`SchemaNameCollectionComparisonTests.CopyTo_element_conversion_and_partial_writes_match`
adds six. Local Windows runs against Microsoft 9.0.0 on .NET 8.0.29 and
.NET 10.0.10 confirmed **9 failures and 9 passing controls per framework**
among these 18 additions. The tests assert compatibility and intentionally
remain red; no production implementation changes accompany them.
Running both complete classes also passed all 21 pre-existing schema cases,
for a combined result of 9 failures and 30 passes per framework.

| Trigger | Microsoft | AdForLinux |
| --- | --- | --- |
| Direct result-value enumerator `Current` before starting | Throws `InvalidOperationException` | Returns null |
| Direct result-value enumerator `Current` after exhaustion | Throws `InvalidOperationException` | Returns the last value on .NET 8, null on .NET 10 |
| Direct result-value enumerator `Reset`, before starting, while positioned, or after exhaustion | Resets and allows replay of all values | Throws `NotSupportedException` |
| Copy an empty schema-name collection to `int[]` through `ICollection.CopyTo` | Succeeds | Throws `ArrayTypeMismatchException` |
| Copy schema names containing a string or null to `int[]` | Throws `InvalidCastException` | Throws `ArrayTypeMismatchException` |

The enumeration tests preserve concrete `GetEnumerator()` call sites because
the clone hides the inherited method with a LINQ iterator. Casting the collection
to non-generic `IEnumerable` takes the inherited path and passes all six control
cases. A positioned direct enumerator also passes. Reset tests compare subsequent
position validation and the remaining values, as well as the reset exception.

The schema tests compare exception types, parameter names, source contents, and
destination contents after success or failure. String and object destinations
are passing controls. Microsoft's collection stores an `object[]`, while the
clone stores a `string[]`, changing array-copy conversion behavior.

These tests need no AD settings. They use the existing delegate-backed schema
fixture and the normal internal result-value constructor; reflection only sets
up the collections, and all operations under comparison are public APIs. They
establish collection behavior independently of live ADSI provider marshaling.

Reference implementation:
[ResultPropertyValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ResultPropertyValueCollection.cs)
and [SchemaNameCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SchemaNameCollection.cs).

Run only these 18 new cases on both frameworks:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~ResultValueEnumeratorComparisonTests|FullyQualifiedName~CopyTo_element_conversion_and_partial_writes_match"
```

### Property-value cache failures and empty schema appends

These additions contain **16 cases per framework** and no production changes.
All compile for `net8.0-windows` and `net10.0-windows` against Microsoft 9.0.0.

`SchemaNameCollectionComparisonTests.AddRange_detaches_existing_enumerator_before_later_indexer_write`
has four offline cases. Local Windows runs on .NET 8.0.29 and .NET 10.0.10 each
confirmed **two failures and two passing controls**. Both empty `AddRange`
overloads leave an existing enumerator attached to the clone's current array.
Changing index zero afterward changes that enumerator's result from `user` to
`computer`. Microsoft replaces the array even for an empty append, so its old
enumerator still returns `user`. Nonempty appends pass. This uses the existing
delegate-backed fixture and establishes collection behavior independently of
live ADSI array marshaling.

`PropertyValueCacheComparisonTests` has **12 AD-dependent cases, compiled but
not run locally**. The following predictions require confirmation by the live run:

| Trigger | Microsoft source behavior | AdForLinux source behavior |
| --- | --- | --- |
| Concrete property-value enumerator `Current` before starting or after exhaustion | Throws `InvalidOperationException` | LINQ iterator does not validate position |
| Concrete enumerator `Reset` | Restarts enumeration | Throws `NotSupportedException` |
| Create concrete enumerator, append a value, then call its first `MoveNext` | Detects mutation and throws | Defers capturing the underlying enumerator until first `MoveNext`, so traversal succeeds |
| `AddRange((object[])null)` | `ArgumentNullException.ParamName` is `value` | Parameter name is `values` |
| Assign a multidimensional array to a previously persisted property, catch the error, then commit | Clears the cached attribute before array conversion fails; commit persists that clear | Clears the local list without recording a change; conversion fails and commit leaves the old server value |

The four non-generic `IEnumerable` cases, null collection-overload case, and
explicit-clear persistence case supply six controls. Tests log both outcomes
and assert compatibility, including exception parameter names and cache state.
The persistence tests create two disabled temporary users, seed both through
Microsoft, compare fresh Microsoft reads after each library commits, and
attempt cleanup of both users in `finally`. Other cases modify only cached
values on the standard fixture user and never commit those changes.

The reference source is
[PropertyValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs)
and [SchemaNameCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SchemaNameCollection.cs).

Run only these additions on both target frameworks with the usual AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PropertyValueCacheComparisonTests|FullyQualifiedName~AddRange_detaches_existing_enumerator_before_later_indexer_write"
```

For an offline-only run, filter to the `AddRange_detaches_existing_enumerator_before_later_indexer_write`
method.

### Property binding, dictionary enumeration, and shared schema filters

These three classes add **26 cases** using public operations on both libraries.
They assert compatibility and deliberately remain red when behavior differs;
there are no production changes.

| Test class | Behavior under comparison | Validation status |
| --- | --- | --- |
| `PropertyCollectionBindingComparisonTests` (6 cases) | Access `Properties`, `PropertyNames`, `Values`, `IDictionary.IsReadOnly`, or a null property key before completing connection configuration | Run on both target frameworks: 5 failures, 1 passing control each |
| `PropertyDictionaryEnumeratorComparisonTests` (17 cases) | Read `Current`, `Entry`, `Key`, and `Value` before starting, after finishing, and after Reset; compare wrapper identity on repeated positioned reads; continue enumeration after an uncommitted attribute addition | Builds on both frameworks; live AD run pending |
| `SchemaFilterBindingComparisonTests` (3 cases) | Read and mutate filters through multiple wrappers for the same parent, with independently opened entries as a control | Builds on both frameworks; live AD run pending |

The offline binding test uses `Signing` without `Secure`, an intentionally
incomplete configuration that AdForLinux rejects locally before making any
network request. Microsoft allows all four wrapper/metadata reads and rejects
the null key with `ArgumentNullException("propertyName")`. AdForLinux instead
throws `PlatformNotSupportedException` from its eager `Properties` getter in
all five cases. Constructing and reading connection settings passes on both.
No AD environment variables are needed for this class.

The live enumeration tests target these source-level differences:

- Microsoft's property dictionary enumerator rejects unpositioned reads;
  AdForLinux exposes the default key/value of its backing dictionary enumerator.
- Microsoft constructs a fresh `PropertyValueCollection` for each positioned
  value read; AdForLinux returns the cached collection, also shared by its indexer.
- Microsoft enumerates through a separately bound clone; AdForLinux enumerates
  its mutable dictionary, so adding a pending attribute invalidates traversal.

Those tests reuse `TestDataFixture` and locate the seeded `description` by name
instead of relying on LDAP attribute order. The pending `info` write is cached
and never committed. The positioned key/value case is a passing control expected
to distinguish collection semantics from fixture or connection failures.

Microsoft's `SchemaFilter` getter creates new wrappers over the parent ADSI
container's filter. AdForLinux keeps one independent filter on each `Children`
wrapper. The live filter tests compare wrapper identity and propagation of Add
and Clear in both directions, including a newly requested `Children` wrapper.
They require access to `AD_USERS_CONTAINER_DN` (or the configured default), but
only modify local enumeration settings, not directory data. The independent-entry
control guards against treating the filter as globally shared by directory path.

Source references for the pending live findings:
[PropertyCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyCollection.cs),
[DirectoryEntries.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntries.cs), and
[SchemaNameCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SchemaNameCollection.cs).
The actual Microsoft 9.0.0 assembly supplies the oracle for every test.

Run only these new cases (omit `-f` to run both configured frameworks):

```powershell
dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows --filter "FullyQualifiedName~PropertyCollectionBindingComparisonTests|FullyQualifiedName~PropertyDictionaryEnumeratorComparisonTests|FullyQualifiedName~SchemaFilterBindingComparisonTests" --logger "trx;LogFilePrefix=property-schema-compatibility"
```

### Disposed entry wrappers and Unicode path equivalence

These additions use only public APIs and require Windows but no domain controller
or `AD_*` configuration. Against Microsoft 9.0.0, local runs on .NET 8.0.29 and
.NET 10.0.10 each produced **14 failures and 3 passing controls (17 cases)**.
Fixed in [issue #197](https://github.com/eliiran1231/active-directory-for-linux/issues/197):
all **17 cases pass on both targets**, with the Microsoft-oracle tests unchanged.
The [validating real-AD workflow](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36922466953)
passed **693/693 tests on each target**, with zero failures or skipped tests.
The [Linux CI workflow](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36922466801)
also passed the build and full Samba functional suite on .NET 8 and .NET 10.

| Test class | Resolved incompatibility |
| --- | --- |
| `DirectoryEntryDisposedWrapperComparisonTests` | After `Dispose()`, both implementations permit `Properties`, its `PropertyNames` and `Values` wrappers, and `IDictionary.IsReadOnly`. A null property key throws `ArgumentNullException("propertyName")`. Actual directory reads still reject disposal before connecting. |
| `DirectoryEntryPathEquivalenceComparisonTests` | Assigning a path differing only by a soft hyphen, composed/decomposed accent, character width, or hiragana/katakana now preserves the original path text and property wrapper in both implementations. |

The disposal control verifies that `Close()` replaces the wrapper without
disposing the entry. The path controls cover a case-only change and an actually
different name. The Unicode cases compare local setter behavior, not server-side
DN equality; they perform no binding or attribute reads. Microsoft's setter uses
Windows linguistic comparison through `Utils.Compare`. The clone uses portable
en-US `CompareInfo` with matching case, nonspacing-mark, kana, width, and string-sort
options before resetting its binding state. Functional tests also cover these
comparisons under a Turkish current culture and verify that disposed-entry
wrappers cannot read directory data or reconnect after `Close()` or a path change.

Reference sources:
[DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs)
and [Utils.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/Utils.cs).
The tests use the actual Microsoft assembly as the oracle.

Run these cases on both configured target frameworks:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~DirectoryEntryDisposedWrapperComparisonTests|FullyQualifiedName~DirectoryEntryPathEquivalenceComparisonTests" --logger "trx;LogFilePrefix=entry-path-disposal"
```

### Credential cache invalidation and unbound commits

`DirectoryEntryCredentialCacheComparisonTests` and
`DirectoryEntryUnboundCommitComparisonTests` use public APIs only and need Windows
but no domain controller or `AD_*` variables. Local runs against Microsoft 9.0.0
on .NET 8.0.29 and .NET 10.0.10 each produced **15 failures and 5 passing controls
(20 cases)**. They assert compatibility and intentionally remain red until the
implementation is corrected.

| Trigger | Microsoft behavior | AdForLinux behavior | Failing cases |
| --- | --- | --- | --- |
| Change `Username`, `Password`, or `AuthenticationType` after obtaining `Properties` | Invalidates the wrapper; the next getter returns a new collection | Keeps returning the old collection | 9 |
| Call `CommitChanges()` on a fresh, wrapper-accessed, or closed unbound entry | Returns without binding | Attempts binding and throws for incomplete authentication configuration | 3 |
| Set `UsePropertyCache = false` in those unbound states | Succeeds and stores `false` | Attempts binding, throws, and leaves the flag `true` | 3 |

The credential cases cover replacement, empty, and null credentials, plus changed
authentication flags. Reassigning the original username, password, or flags gives
three passing controls. The other two controls perform the commit/cache-mode
operations after disposal. Wrapper tests establish public collection identity;
they do not claim to verify cached attribute contents or persistence to AD.

The unbound tests use `Signing` without `Secure`, which the clone rejects locally
before network access. Microsoft's unbound operations never need to validate
binding configuration. This exposes premature binding without relying on DNS,
connection timeouts, or an available directory server.

The source-level causes are in `DirectoryEntry`: the clone's credential and
authentication setters call `ResetConnection()` without clearing `_properties`,
whereas Microsoft's setters call `Unbind()`. The clone's `CommitChanges()` calls
`GetConnection()` on a clean unbound entry; Microsoft returns when `Bound` is
false. `UsePropertyCache` invokes `CommitChanges()` before storing the new flag.
See Microsoft's
[DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs).
The tests use the actual assembly as their oracle, not hardcoded replacement
behavior from the source.

Run both configured frameworks:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~DirectoryEntryCredentialCacheComparisonTests|FullyQualifiedName~DirectoryEntryUnboundCommitComparisonTests" --logger "trx;LogFilePrefix=entry-cache-compatibility"
```

### Extension property isolation and generic collection contracts

This batch adds comparisons against the Microsoft 9.0.0 assemblies. Production
code is unchanged; the assertions require compatibility and expose differences
as failures.

| Test class | Behavior under comparison | AD required? |
| --- | --- | --- |
| `PrincipalExtensionPropertyIsolationComparisonTests` | After assigning an ordinary property on an unsaved user, `ExtensionGet` for its LDAP attribute should still return an empty array. The clone instead returns the ordinary property's pending value, including a single null for an explicitly cleared Description. | Yes, for context/property validation; no principals are saved |
| `PrincipalValueCollectionEqualityDispatchComparisonTests` | `Contains`, `IndexOf`, and `Remove`, through generic and non-generic interfaces, dispatch equality differently: Microsoft uses `object.Equals`; the clone's `List<T>` uses `IEquatable<T>` when available. | No |
| `PrincipalValueEnumeratorExceptionComparisonTests` | After enumerator disposal, `Current`, `MoveNext`, and `Reset` must match `ObjectDisposedException.ObjectName`, not just the exception type. | No |

The 18 offline cases were run on Windows with .NET 8.0.29 and .NET 10.0.10:
each target reported **12 failures and 6 passing controls**, with no skips.
Six failures expose equality dispatch and six expose the disposed object name:
Microsoft reports `ValueCollectionEnumerator`, while the clone reports its
namespace-qualified nested `Enumerator` implementation type. Both targets build
without warnings or errors. The seven AD-dependent cases have not been run.

The equality fixture deliberately gives `object.Equals` reference semantics and
`IEquatable<T>.Equals` key semantics to make the dispatch observable. This is an
edge case for arbitrary generic element types, not a claim about ordinary string
workstation values. Same-instance probes are passing controls, and removal tests
also compare the remaining elements. Reflection invokes only Microsoft's normal
internal collection constructor; compared operations use public interfaces.

The extension tests cover Description (including null), DisplayName,
SamAccountName, UserPrincipalName, and GivenName. An unrelated attribute is a
control; explicit extension writes are also checked to remain independent of the
ordinary property. These seven cases are compiled but await a configured AD run.

Reference implementations:
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs),
[TrackedCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollection.cs),
[ValueCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs),
and [TrackedCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/TrackedCollectionEnumerator.cs).

Run the new batch on both target frameworks with the usual `AD_*` settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PrincipalExtensionPropertyIsolationComparisonTests|FullyQualifiedName~PrincipalValueCollectionEqualityDispatchComparisonTests|FullyQualifiedName~PrincipalValueEnumeratorExceptionComparisonTests" --logger "trx;LogFilePrefix=extension-collection-contracts"
```

### Context name, additional scalar caches, and advanced-filter ownership

This batch adds **19 cases per framework**, using the Microsoft 9.0.0 assemblies
as the runtime oracle. No production implementation changes accompany it.

| Test class | Compatibility gap | Validation status |
| --- | --- | --- |
| `PrincipalContextNameComparisonTests` | Microsoft retains the supplied `host:port` in `Name`; the clone returns only the parsed host. Container, username, and options are controls. | Compiled; one AD-dependent case awaits execution |
| `UserScalarCacheRetentionComparisonTests` | `GivenName`, `Surname`, `EmailAddress`, and `Description` still read the underlying entry on every access in the clone. Microsoft keeps a separately loaded principal value. | Compiled; 16 AD-dependent cases await execution |
| `AdvancedFiltersOwnerComparisonTests` | The protected constructor accepts a null owner in Microsoft; the clone throws `ArgumentNullException("p")`. | Both frameworks: one confirmed failure and one passing non-null control |

The scalar cases cover replacing a loaded value, clearing it, setting a value
after initially loading an absent attribute, and leaving the cache unchanged.
Each case verifies the raw entry values before and after mutation, then compares
two subsequent principal reads. This extends the existing DisplayName tests to
properties that still use `GetString` rather than `GetCachedString` in the clone.
The existing owned-user fixture creates independent disabled users and cleans
them up even on assertion failure. No Save or Commit follows the cache edits.
The context-name case performs no directory writes. The constructor comparison
uses ordinary protected subclass constructors and requires neither AD nor reflection.

Source-level evidence is in Microsoft's
[Context.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Context.cs),
[User.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/User.cs),
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs),
and [AdvancedFilters.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AdvancedFilters.cs).
The two live findings remain predictions until the differential run confirms them.

Run this batch on both configured frameworks with the usual `AD_*` settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~PrincipalContextNameComparisonTests|FullyQualifiedName~UserScalarCacheRetentionComparisonTests|FullyQualifiedName~AdvancedFiltersOwnerComparisonTests" --logger "trx;LogFilePrefix=context-scalar-owner"
```

### Advanced-filter instance ownership and collection conversion

This batch adds **27 cases per framework**, with no production changes:

| Test class / cases | Finding | Validation |
| --- | --- | --- |
| `AdvancedFilterInstanceComparisonTests` (12) | Microsoft's six built-in criterion methods work on an `AdvancedFilters` subclass constructed with a null owner; the clone dereferences the owner and throws `NullReferenceException`. Each case also replaces the criterion. | Both .NET 8 and .NET 10: 6 confirmed failures, 6 passing non-null-owner controls |
| `AdvancedFilterIsolationComparisonTests` (12) | A separately constructed filter instance stores built-in criteria independently in Microsoft. The clone stores them on the principal, so configuring the separate instance is predicted to add or overwrite the principal's query criterion. | Compiled; awaits AD-backed execution |
| `CompatibilityAdvancedExtensionQueryComparisonTests` (3 new cases) | For `byte[]`, `int[]`, and `ArrayList`, Microsoft's advanced extension setter wraps the collection as one element, which query conversion stringifies. The clone recursively expands its elements into separate conditions. | Compiled; awaits AD-backed execution |

The ownership cases use normal protected subclass constructors; no reflection
or private-state mutation is involved. The live isolation cases compare the
public native searcher's `Filter` before and after two detached-instance updates,
both with and without an existing criterion on `principal.AdvancedSearchFilter`.
They also verify that updating the principal's actual filter changes its query
and restores parity. The three collection cases extend the existing scalar and
`object[]` controls and check replacement with a scalar criterion afterward.
All live cases in this batch render filters only: initialization may bind to AD,
but the tests never execute the rendered queries or create/save directory objects.

Source evidence: Microsoft's pinned
[AdvancedFilters.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AdvancedFilters.cs),
[Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs),
and [ADStoreCtx_Query.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs).
The runtime Microsoft assembly remains the oracle; the 15 new live cases are
predictions until the differential run confirms them.

With the usual `AD_*` settings, run the batch on both configured frameworks
(34 cases per framework, including 7 existing extension-query cases):

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~AdvancedFilterInstanceComparisonTests|FullyQualifiedName~AdvancedFilterIsolationComparisonTests|FullyQualifiedName~CompatibilityAdvancedExtensionQueryComparisonTests" --logger "trx;LogFilePrefix=advanced-filter-ownership"
```

For the 12 offline cases alone, use
`--filter FullyQualifiedName~AdvancedFilterInstanceComparisonTests`.
These tests assert parity and intentionally fail where the incompatibility is present.

## Things to know before you read a failure

- **The account running the tests needs rights** to create and delete objects in
  the configured writable container, to set a password, and to read the SACL for
  the disposable ACL test object. The SACL read is required to prove that a
  DACL-only update does not replace security-descriptor sections that were not
  requested.
- **`GetAuthorizationGroups` has two independent checks.** The differential
  comparison verifies that every directory-backed group we return also appears
  in Microsoft's answer. The Linux functional suite separately compares the
  result exactly with every `tokenGroups` SID that resolves to a group object;
  well-known SIDs without directory objects are intentionally outside that LDAP
  result.
- **Times.** Directory-read comparisons generally compare the instant rather
  than `DateTime.Kind`. The unsaved expiration tests explicitly compare Kind
  as well: an in-memory assignment must preserve Microsoft's public property
  state before any conversion for persistence.
- **Self-signed certificates.** Against a test server with a self-signed
  certificate, Windows may refuse the TLS connection for *both* libraries. Use a
  DC with a trusted certificate, or install the test CA on the Windows machine.
