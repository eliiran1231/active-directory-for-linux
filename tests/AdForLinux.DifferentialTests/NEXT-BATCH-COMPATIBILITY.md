# Principal state and membership compatibility probes

This batch contains **52 cases per framework for 11 distinct root causes**.
Every test asserts parity with the actual Microsoft 9.0.0 assembly. The tests
and their oracle comparisons are unchanged by the issue #213 production fix.

## Confirmed baseline

The [complete Windows differential run 37124202219](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37124202219)
executed all cases on both `net8.0-windows` and `net10.0-windows`:

- Complete suite, per target: **1,262 executed, 1,222 passed, 40 failed, zero skipped**.
- This batch, per target: **52 executed, 16 passed, 36 failed**.
- All 11 candidate root causes below were confirmed, including the previously
  provisional live-AD cases. The failing-case sets were identical across targets.
- [Issue #213](https://github.com/eliiran1231/active-directory-for-linux/issues/213)
  covers **33 failures across ten gaps**. The three undefined-GroupScope failures
  belong to [#60](https://github.com/eliiran1231/active-directory-for-linux/issues/60)
  and are excluded from this fix. The four other suite failures belong to
  [#203](https://github.com/eliiran1231/active-directory-for-linux/issues/203) and
  [#56](https://github.com/eliiran1231/active-directory-for-linux/issues/56).

## Verified issue #213 fix

Validated production commit `76c4af279c71eba650bd27367798d8b746d5d42f` on
2026-10-03; the subsequent report update changes documentation only.

- [Full Windows/AD differential run 37126652280](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37126652280):
  **1,262 executed, 1,255 passed, 7 failed, zero skipped on each framework**.
  Both TRX artifacts were inspected; their remaining failing-case sets match.
- **All 33 in-scope failures now pass**, and all **16 previously passing batch
  controls remain passing** on each target. The batch is **49 passed / 3 failed**;
  only the three undefined-GroupScope cases for #60 remain.
- The four failures outside this batch are unchanged: the two retained entry
  options cases (#203) and the two protected-Negotiate inheritance cases (#56).
  The workflow remains red solely for these seven explicitly excluded cases.
- Per-run OU creation, result upload, and OU cleanup all succeeded.
- [Linux/Samba CI run 37126653686](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37126653686):
  build succeeded; **526 functional tests passed, zero failed or skipped on each
  of .NET 8 and .NET 10**.
- Local targeted checks also passed on both frameworks: 20 generic-finder
  oracle comparisons and 28 existing query-filter functional cases.

The fix validates constructor contexts and generic finder types, separates
nullable group assignment state, retains scalar writes until Save, returns
pending Name assignments, retains pending member objects until persistence,
queries stored membership independently of collection edits, and converts
ordinary wrapped extension values without recursive expansion. Advanced
extension conversion and the existing Microsoft-oracle tests are unchanged.

## Review follow-up: membership lifecycle

Production/test commit `0b07d77` addresses both PR #214 review findings:
retained members match reloaded wrappers by principal equality after acquiring a
stored identity, and group disposal no longer disposes inserted member objects.

`MembershipLifecycleComparisonTests` adds four public-API oracle cases outside
the original 52-case batch: Add an unsaved member, Save that member, look it up,
and test Contains/Remove/duplicate Add; then identity-based Add, enumeration,
group disposal, and a retained member property read. The existing owned-user
fixture accepts an optional before-Save callback; its cleanup is unchanged.
Groups stay unsaved and all created users are deleted by fresh exact-DN lookup.

- [Fresh full AD run 37128090803](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37128090803):
  **1,266 executed, 1,259 passed, 7 failed, zero skipped per framework**.
  All four new cases pass on both .NET 8 and .NET 10. The original batch remains
  49 passed / 3 failed, and the remaining seven suite failures are exactly the
  #60/#203/#56 exclusions listed above. Both TRX files were inspected.
- OU creation, artifact upload, and cleanup all succeeded.
- [Fresh Linux/Samba CI 37128092898](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37128092898):
  build passed; **526 passed, zero failed or skipped per framework**.
- The final follow-up commit only records these verified results.

## Run

With the usual `AD_*` settings from [README.md](README.md), run the entire batch
on both frameworks:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~NextBatch" --logger "trx;LogFilePrefix=next-batch"
```

For the offline cases alone:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~NextBatchGenericFinderComparisonTests" --logger "trx;LogFilePrefix=next-batch-offline"
```

Traits also distinguish `CompatibilityNextBatchOffline` and
`CompatibilityNextBatchLive`. A nonzero test exit is expected where parity fails.
Please retain both target frameworks' TRX files: constructor and provider behavior
should be evaluated separately from test setup failures.

## Root causes and reproducers

Names below are test method names; parameter variants and controls are not
counted as additional root causes.

| # | Test / cases | Microsoft contract and confirmed baseline defect |
| --- | --- | --- |
| 1 | `Generic_finder_validates_subtype_before_null_context` / 20 | `CheckFindByArgs` rejects a generic type that is not an `AuthenticablePrincipal` before checking context. The clone's protected date finders go straight to context/date conversion without validating `T`. Confirmed: `ArgumentException` with no parameter versus `ArgumentNullException("context")`. Five methods × three invalid types fail; five valid-user subtype controls pass. |
| 2 | `Principal_constructor_checks_disposed_context` / 6 | Microsoft's constructors assign through `ContextRaw`, which checks context disposal. The clone's `AuthenticablePrincipal` and `GroupPrincipal` constructors assign `ContextRef` directly. Covers user/computer/group, each with a live-context control. |
| 3 | `Named_group_constructor_validates_name_like_microsoft` / 3 | Microsoft's named group constructor explicitly rejects a null account name with `ArgumentException`. The clone passes it to `Name`, producing `ArgumentNullException("value")`. Empty and valid names distinguish this constructor check from the property setter. |
| 4 | `Group_scope_validation_timing_and_retained_value_match` / 4 | Microsoft stages even undefined `GroupScope` values in `HandleSet`. The clone applies `Enum.IsDefined` immediately, rejects the assignment, and retains the previous value. Covers three invalid values, one valid control, and subsequent valid recovery. No invalid value is saved. |
| 5 | `Unsaved_group_scope_and_security_have_independent_assignment_state` / 4 | Microsoft tracks whether scope and security status were assigned separately. The clone uses one staged `groupType` with default bits; assigning either property makes the other appear initialized. Neither/both-assigned cases are controls. |
| 6 | `Staged_principal_scalar_is_independent_of_entry_cache_and_refresh` / 2 | Microsoft stages a principal setter independently until `Save`. The clone's `SetString` immediately edits `DirectoryEntry.Properties`; refreshing that entry can discard the write while the principal getter still reports the staged value. Checks raw cache visibility and a fresh server lookup after Save, with/without RefreshCache. This tests write staging, not the already-covered retention of previously read scalar values. |
| 7 | `Persisted_name_assignment_is_returned_before_save` / 1 | Microsoft reads the newly assigned principal Name. The clone writes `cn` but its persisted Name getter reads `name`, so setter/getter and ToString disagree. No rename or Save occurs; original directory identities must remain intact. |
| 8 | `Unsaved_member_operations_do_not_require_a_directory_identity` / 3 | Microsoft's pending membership lists can operate on unsaved principal objects. The clone eagerly requires a DN/SID through `RequireMembershipValue`, rejecting Contains/Add/Remove before persistence. All principals stay unsaved. |
| 9 | `Pending_membership_enumeration_retains_the_inserted_principal_instance` / 1 | Microsoft retains the Principal inserted into its pending membership list. The clone stores `MemberReference` data and re-queries every DN in `EnumerateMembers`, returning another wrapper and losing unsaved member property changes. Tests saved members to isolate this from cause 8. |
| 10 | `GetMembers_queries_persisted_membership_rather_than_pending_collection` / 4 | Microsoft returns an empty query result for an unsaved group, regardless of pending Members or recursion. The clone's direct branch materializes pending Members, while its recursive branch requires a saved entry. Both stem from the missing unsaved/store-query distinction in `GetMembersCore`, and are counted together. Empty direct enumeration is a control. |
| 11 | `Ordinary_extension_query_preserves_collection_as_one_wrapped_value` / 4 | Microsoft wraps a non-object-array extension collection as a single value and converts that value without recursive expansion. The clone's ordinary `ExtensionAssertions` recursively expands `int[]` and `ArrayList`. The previously covered advanced-filter path uses a separate converter and was already corrected; this probes the remaining ordinary setter path. Scalar/object-array and scalar replacement are controls. |

## Source evidence

Microsoft source is pinned to the same v9.0.0 release as the package references;
the running assemblies, rather than copied expected filter strings, are the oracle.

- Causes 1–2: [AuthenticablePrincipal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AuthenticablePrincipal.cs),
  `CheckFindByArgs` and constructors; [Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs), `ContextRaw`.
- Causes 2–5 and 10: [Group.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Group.cs),
  constructors, nullable property load states, and `GetMembers`.
- Causes 6–7: [Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs),
  `Name`, `HandleGet`, and `HandleSet`.
- Causes 8–9: [PrincipalCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollection.cs),
  `Add`, `ContainsNativeTest`, and pending Principal lists;
  [PrincipalCollectionEnumerator.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollectionEnumerator.cs).
- Cause 11: [Principal.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs), `ExtensionSet`;
  [ADStoreCtx_Query.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs), `ExtensionCacheConverter`.

The corresponding clone code is in `AuthenticablePrincipal.cs`, `Principal.cs`,
`GroupPrincipal.cs`, `PrincipalCollection.cs`, and `PrincipalQueryFilter.cs` under
`src/AdForLinux.DirectoryServices.AccountManagement`.

## Fixture scope

The constructor, group property, unsaved-member, and extension-query cases create
no directory objects. Native searcher initialization may bind, but rendered
extension queries are never executed.

The other live cases reuse `WithSavedUsers`: two independently owned disabled
users, checked absent before creation and cleaned up through fresh exact-DN
lookups even on assertion failure. Only the scalar-staging test calls Save after
initial creation, writing a description on those owned users. Groups remain
unsaved, membership changes never reach AD, and pending Name/DisplayName edits
are never committed. No reflection or private-state injection is used.
