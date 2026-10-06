# Issue 226 — morning review acceptance matrix

This is a partial implementation for [issue 226](https://github.com/eliiran1231/active-directory-for-linux/issues/226), submitted in [draft PR 228](https://github.com/eliiran1231/active-directory-for-linux/pull/228). It does not complete or close the issue. Production code last changed at `bf493e71d21621bbccdcfd286afac2a24a870562`; this handoff adds documentation and one preservation test. The PR records the final tested head and actual Windows run URL.

“Validated” below means the specified recorded or invariant cases, not universal Microsoft parity. “Refused” means no candidate is published. “Deferred” identifies an unresolved policy or parity requirement. Unrecorded accepted-input risks are called out separately below; they are not approved deviations.

## Requirements and evidence

| Issue requirement | Status and implemented boundary | Source and tests |
| --- | --- | --- |
| Internal Add/Set/Reset/Remove/RemoveSpecific/RemoveAll for DACL and SACL | Implemented; successful recorded operations in both ACL kinds. Multi-entry SACL gate below limits subsequent edits. | [Engine](../../src/AdForLinux.DirectoryServices/Security/Core/AclMutationEngine.cs), [literal replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.cs), [seeded replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.Seeded.cs) |
| Purge, access/audit wrappers, protection, owner/group | Implemented and validated for explicit SID targeting, inherited-entry retention/removal and detached protection behavior. Owner/group changes preserve unrelated opaque ACLs. | Engine; literal `Recorded_state_call_matches_bytes`, `Recorded_B4_protection_preserve_inheritance`; seeded sequences; [safety tests](../../tests/AdForLinux.FunctionalTests/AclMutationEngineTests.cs) |
| C1–C3 mask OR, complementary scopes, audit merging | Partial parity: same-shape merges and recorded asymmetric Stage 1 object-mask absorption work. Qualifier and common/object families remain separate. Later GUID/audit/scope merge risks are detailed below. | Engine `Add`, `CanAbsorbObjectMask`; literal replay; 42 recorded Stage 1 observations and seeded stateful replay |
| E1/E2 split removal, false on unrepresentable narrowing, true no-match | Implemented for recorded mask/audit/DS propagation and GUID precedence. Includes OI preservation in untouched residuals, recomputed propagation, global versus qualified rights, IOT disjointness and atomic late failure. | Engine `Remove`, `Scope`, `Split`; literal E1/E2; seeded replay; safety tests |
| D1/D2/F1 ordering | Validated explicit deny/allow then inherited order, object placement within qualifier groups. No global object-last rule or inherited reorder. Unreviewed SID/import ordering is refused. | Engine `Prepare`; [projector](../../src/AdForLinux.DirectoryServices/Security/Core/MicrosoftObservableProjector.cs); literal D1/D2/F1 and [projection tests](../../tests/AdForLinux.FunctionalTests/MicrosoftObservableProjectorTests.cs) |
| Set/Reset/Purge/RemoveAll across GUIDs, explicit only | Implemented and recorded; inherited entries survive. Same-SID SACL Set/Reset may replace every explicit entry without sorting surviving entries. | Engine operation dispatch; literal state calls and seeded sequences |
| G1–G3 noncanonical rejection | Implemented atomic `InvalidOperationException`; original image and intent retained. | Literal `Recorded_noncanonical_add_and_purge_refuse_atomically`; safety tests |
| B1–B6 / D14 absent, NULL and empty behavior | Raw distinction retained; operation-specific DACL materialization, SACL no-op removals, protection and owner/group effects validated. Literal B4/B6 plus operation sequences; not a claim that every original probe row is independently replayed. | Engine; [codec tests](../../tests/AdForLinux.FunctionalTests/SecurityDescriptorCodecTests.cs); literal state calls; seeded replay |
| D4/D13 read projection separate from mutation intent | Implemented exact six-family, correct-kind, known-flag and exact-size inactive IO predicate; IO with OI/CI does not drop. NP clearing and approved DACL partition supported. Raw original retained; read projection creates no intent. | Projector `Project`/`ProjectAcl` versus `NormalizeForEdit`; projection tests exhaust 256 flag bytes × six families × two ACL kinds |
| Immutable validate-then-publish, no-op/failure intent | Implemented, bounded invariant coverage: fresh descriptor validation, snapshots, staged false/exception, previous intent, recovery after failure, size boundaries and deterministic safe algebra. | [Rewriter](../../src/AdForLinux.DirectoryServices/Security/Core/DescriptorRewriter.cs); safety `Mixed_success_false_exception_noop_and_recovery_preserve_every_snapshot`; seeded accumulated-intent sequence tests |
| Unknown/opaque ACEs and recognized trailing bytes | Approved preservation/refusal boundary: untouched sections copied exactly; mutation of a containing ACL refuses before publication. No silent opaque movement or loss. Narrower than Microsoft H2 unrelated-add behavior. | Engine `Prepare`; projector; safety and projection malformed/unknown/trailing tests |
| Overlapping storage / comment 6025043919 / J6 | Compact referenced overlap successfully unshared into independently validated storage. Original J6 examples with orphan bytes refuse because relocation policy is unresolved. Shared bytes are never edited in place. | Rewriter; safety overlap tests; projection `Recorded_imports_match_or_refuse_unapproved_normalization` |
| I2 SACL ordering | Policy deferred. More than one existing explicit audit ACE refuses, except complete same-SID Set/Reset replacement. Recorded Windows sorting is not an automatic allowlist. | Engine `Prepare`; [I2 replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.I2.cs): 15 approved DACL outcomes, seven DACL refusals, nine SACL refusals |
| Import compaction, gaps/tails, unapproved movement/loss | Deferred/refused: complementary common-ACE raw import compaction, descriptor orphan/gap relocation, active zero-mask/no-audit loss and unapproved SID/object ordering. Live split-restore pairs are distinguished from new raw imports. | Projector; rewriter; seeded `Requested_raw_import_compaction_is_refused_without_changing_live_replay`; 37 literal I2/J4/J6 projection rows |
| Offline recorded replay on Linux/Windows, .NET 8/10 | Implemented with five explicit fixture-free classes. Fresh detached Microsoft 9 observations compared to committed observations on Windows; portable tests replay actual recorded bytes and outcomes on both OSes. | [Workflow](../../.github/workflows/acl-offline-windows.yml), [oracle provenance](../research/acl-windows-oracle/README.md), [recorder](../research/acl-windows-oracle/SeededSequences.cs) |
| J probe scope and public behavior | Selected J4/J6 import/storage evidence covered. Public modified flags/instrumentation, constructor/exception parity, public ten-type API, DirectoryEntry/LDAP, resolver, Microsoft interop and effective access are not covered by this internal task. Internal section intent is not a public write-mask promise. | Internal engine/projector tests only; existing directory workflows untouched |

## Concrete accepted-input risks awaiting Windows recording

No mismatch remains in the 666 committed Microsoft observations. That does **not** establish correctness for all accepted inputs. Independent pinned-source review identified the following two concrete candidates. A temporary in-memory diagnostic confirmed that the portable engine accepts each and emits two ACEs (two checks passed on Linux .NET 8); these were not added as assertions endorsing that behavior. Neither candidate has a recorded Microsoft Windows outcome yet.

Use the same SID and mask `0x10` in each pair, with distinct nonempty GUIDs G1/G2:

1. **Stage 3 inherited-GUID/scope merge:** existing AllowObject flags `0x00`, object flags `1`, OT=G1, no IOT; incoming AllowObject flags `0x0A`, object flags `3`, OT=G1, IOT=G2. Microsoft's pinned `AceFlagsAreMergeable` and Stage 3 `MergeAces` suggest one ACE with flags `0x02`, object flags `1`, OT=G1. Portable `SameShape` currently retains two.
2. **Stage 2 audit GUID-presence merge:** existing AuditObject flags `0x42`, object flags `3`, OT=Guid.Empty, IOT=G2; incoming AuditObject flags `0x82`, object flags `2`, no OT, IOT=G2. Microsoft's pinned GUID-value comparison and Stage 2 audit merge suggest one ACE with flags `0xC2`, preserving the existing GUID shape. Portable `SameShape` currently retains two.

Source basis: [Microsoft .NET 9 ACL.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs), `AccessMasksAreMergeable`/`AceFlagsAreMergeable` and `MergeAces` (approximately lines 1264–1306 and 1562–1588). These are source-supported potential parity defects on accepted inputs, not intentional refusals, confirmed Windows mismatches, or approved policy deviations. Record the detached Microsoft outcomes before fixing/generalizing the later merge stages. Other combinations beyond the measured GUID, audit and propagation matrix remain untested breadth.

## Validation inventory

| Offline xUnit group | Cases |
| --- | ---: |
| Mutation replay (including 666 newly recorded steps, sequence and cross-runtime checks) | 780 |
| Read projection | 78 |
| Mutation safety and preservation | 62 |
| Lossless codec | 139 |
| SID | 21 |
| Total per OS/runtime | 1080 |

The safety group also executes 100 deterministic disjoint-mask iterations with seed 2262026. Exhaustive projector flag loops and sequence steps are not additional xUnit cases. Newly recorded steps include 256 seeded operations, operation/state boundaries, removal precedence, 32 IOT cases, 64 common OI cases, 192 object OI cases, 24 combined sequence steps and 42 asymmetric object-mask Add cases; exact case definitions and provenance are in the recorder/README. Recordings use Microsoft System.DirectoryServices 9.0.0 on Windows runtimes 8.0.31 and 10.0.12; local replay uses runtimes 8.0.0 and 10.0.12.

The final documentation/test commit must pass 1080 cases on Linux .NET 8/10 and Windows .NET 8/10, with all 666 fresh Windows observations matching. Consult PR 228 for its exact head and run evidence rather than treating the inventory as a CI status assertion.

## Acceptance decision

- Internal operation entrypoints exist and perform meaningful successful edits, but full requested semantic parity remains partial.
- Recorded replay is validated for the enumerated cases; selected I2/J rows intentionally verify refusals rather than adopting unreviewed Microsoft output.
- Failure/no-op immutability and read/intent separation have substantial deterministic coverage, including mixed success/failure/recovery snapshots.
- Not all deviations are approved or resolved: later-stage accepted-input merge candidates require Windows evidence/fixes; SACL sorting and import/gap policies remain decisions.

Keep issue 226 open and PR 228 draft. No merge or automatic issue closure is requested.
