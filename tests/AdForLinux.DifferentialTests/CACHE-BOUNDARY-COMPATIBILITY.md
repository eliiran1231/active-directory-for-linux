# Cache boundary differential probes

This batch adds **30 cases per framework**: 3 offline and 27 requiring the
existing AD fixture. It targets **14 distinct candidate root causes**, counting
related overloads and controls together. One cause is confirmed locally; the
other thirteen remain predictions pending the Windows/AD differential run.
No production code is changed. Tests assert parity with the actual Microsoft
9.0.0 assemblies, so incompatibilities intentionally produce failing tests.

Run with the usual `AD_*` configuration from [README.md](README.md):

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter "FullyQualifiedName~CacheBoundary" --logger "trx;LogFilePrefix=cache-boundary"
```

This runs both `net8.0-windows` and `net10.0-windows`. Send both TRX files.
For offline cases alone, use `FullyQualifiedName~CacheBoundaryOffline`.

## Findings and individual reproductions

Method names below belong to `CacheBoundaryLiveComparisonTests` except row 1,
which belongs to `CacheBoundaryOfflineComparisonTests`. Expected behaviors in
rows 2–14 are source-based predictions, not claimed runtime observations.

| ID | Test method | Suspected root cause and distinguishing observation |
| --- | --- | --- |
| 1 | `Values_enumerator_creation_and_reset_defer_binding` | `PropertyView.GetEnumerator` eagerly calls `EnsureLoaded`. Microsoft's Values cursor constructor and Reset are local. **Confirmed:** after disposal, Microsoft succeeds; the clone throws `ObjectDisposedException`. Two failing variants, one separate passing PropertyNames control. |
| 2 | `First_lookup_preserves_requested_property_name` | `ReplaceLoaded` pre-creates wrappers using server spelling. Microsoft creates the managed wrapper on first indexer lookup, preserving the caller's spelling. Uppercase/mixed-case requests plus lowercase control. |
| 3 | `Contains_after_clearing_a_present_attribute` | `OnChanged` leaves a cleared attribute in `_byName`; Contains checks dictionary membership rather than the provider's current values. Clear and unchanged control. |
| 4 | `Dictionary_enumeration_created_after_staging_uses_matching_name_source` | Microsoft enumerates property names on a newly bound clone; our enumerator snapshots the current local dictionary. A pending new `info` attribute should not enter Microsoft's enumeration even when staged before enumerator creation. This differs from existing coverage that stages after creation. |
| 5 | `Positioned_dictionary_value_observes_later_cache_edits` | The clone snapshots values along with names. Microsoft creates a fresh value wrapper against the original parent on each Value read. Editing an existing attribute after positioning distinguishes value access time independently of row 4's name source. |
| 6 | `View_cursor_can_advance_again_after_end` | Dictionary key/value cursors replace Microsoft's index cursor. Microsoft's cursor resets its index to -1 at end; the next MoveNext can restart. Both views exercise the same cursor cause. |
| 7 | `Dictionary_CopyTo_allocates_wrappers_independent_of_indexer_cache` | CopyTo returns `_byName` wrappers directly instead of using the public dictionary enumerator. Compare reference identity and the retained indexer wrapper after mutating a copied wrapper. |
| 8 | `View_CopyTo_short_array_preserves_matching_partial_progress` | View CopyTo delegates to dictionary collection copying, with upfront capacity validation. Microsoft writes one element at a time with `Array.SetValue`. Compare exception/parameter and whether the first slot changed before failure; never compare unspecified attribute order. |
| 9 | `Dictionary_CopyTo_capacity_error_has_matching_parameter` | The capacity guard supplies `array` as ParamName; Microsoft's guard has no parameter name. Test both index zero and integer overflow boundary. Separate from row 8's view implementation. |
| 10 | `Child_wrappers_inherit_parent_cache_mode` | Add and Find construct children without carrying the parent's `UsePropertyCache`. Microsoft explicitly passes this setting. False cases plus true controls; no child is committed. Counted as one connection-state propagation cause. |
| 11 | `SchemaEntry_returns_the_same_provider_schema_object` | SchemaEntry searches for a `classSchema` directory object instead of returning the ADSI schema provider path. Compare the returned public Path without binding the schema wrapper. |
| 12 | `Refresh_of_absent_server_attribute_preserves_matching_staged_state` | Partial refresh unconditionally removes a requested cache entry when the server omits it. ADSI can retain a pending value for an absent server attribute. Targeted `info` refresh plus unrelated `description` control. |
| 13 | `First_partial_refresh_does_not_hide_other_existing_attributes` | `MarkLoaded` treats a partial response as a complete managed dictionary; later lookups cannot fetch missing attributes. Compare requested values and a known populated, unrequested `sAMAccountName`. This is the least certain provider-dependent hypothesis and may pass. |
| 14 | `Ranged_refresh_invalidates_base_attribute_wrapper` | Refresh removes only the literal ranged key. Microsoft also removes the non-range key from its managed wrapper table. Compare retained `member` wrapper identity after `member;range=0-0`, with unrelated refresh as control. Existing ranged tests check unrelated attributes, not this base-wrapper identity. |

Rows 4, 5 and 7 have related collection code but distinct corrective actions:
choose the right name source, read values at the right time, and return the
right wrapper ownership from CopyTo. Rows 12–14 distinguish missing server
values, completeness of first load, and ranged-key invalidation.

## Isolation and interpretation

The live class registers `IClassFixture<TestDataFixture>` and uses the existing
fixture's seeded user/group. Each case opens fresh wrappers for both libraries.
Changes stay in the entry caches. Child Add constructs an unsaved request only;
there is no subsequent property edit or commit. Fixture setup/cleanup retains
its existing creation, password, and deletion requirements.

Positive preconditions ensure that expected seed attributes/members are present
and `info` is absent. Exceptions, parameter names, identities and values are
compared without localized message matching. Set comparisons ignore directory
attribute ordering. Setup/bind failures are test failures, not evidence of a
compatibility bug. Passing live probes should be retained as controls or removed
from the findings count when interpreting the results.

## Local validation (2026-10-03)

Both targets compile without new warnings. The offline batch reports **2 failed,
1 passed** on each framework, confirming row 1. All **24 fixture-registration
checks pass** per framework, including the new live class. The combined local
validation therefore reports 2 failed, 25 passed per framework. Live cases were
not executed; no claim of ten confirmed bugs is made before that run.

## Source evidence

The oracle remains the pinned Microsoft assemblies. Relevant reference code:

- [PropertyCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyCollection.cs): indexer, Contains, dictionary enumeration, CopyTo and nested view cursors.
- [DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs): CloneBrowsable, SchemaEntry and RefreshCache.
- [DirectoryEntries.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntries.cs): child wrapper construction.

Corresponding clone code is in `src/AdForLinux.DirectoryServices/PropertyCollection.cs`,
`DirectoryEntry.cs` and `DirectoryEntries.cs`.
