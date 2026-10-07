# Issue 226 — morning review acceptance matrix

This is a partial implementation for [issue 226](https://github.com/eliiran1231/active-directory-for-linux/issues/226), submitted in [draft PR 228](https://github.com/eliiran1231/active-directory-for-linux/pull/228). It does not complete or close the issue. The concrete merge leads and their reported analogues have been recorded, and Add now uses the evidenced three-stage algorithm. The PR records the final tested head and actual Windows run URL.

“Validated” below means the specified recorded or invariant cases, not universal Microsoft parity. “Refused” means no candidate is published. “Deferred” identifies an unresolved policy or parity requirement. The separately approved [ordering/projection policy](issue-226-ordering-policy.md) now permits known-ACE ordering and projection-only import compaction; raw-write reconciliation remains bounded.

## Requirements and evidence

| Issue requirement | Status and implemented boundary | Source and tests |
| --- | --- | --- |
| Internal Add/Set/Reset/Remove/RemoveSpecific/RemoveAll for DACL and SACL | Implemented; successful recorded operations in both ACL kinds. Known multi-entry SACL operations now have recorded coverage. | [Engine](../../src/AdForLinux.DirectoryServices/Security/Core/AclMutationEngine.cs), [literal replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.cs), [seeded replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.Seeded.cs) |
| Purge, access/audit wrappers, protection, owner/group | Implemented and validated for explicit SID targeting, inherited-entry retention/removal and detached protection behavior. Owner/group changes preserve unrelated opaque ACLs. | Engine; literal `Recorded_state_call_matches_bytes`, `Recorded_B4_protection_preserve_inheritance`; seeded sequences; [safety tests](../../tests/AdForLinux.FunctionalTests/AclMutationEngineTests.cs) |
| C1–C3 mask OR, complementary scopes, audit merging | Partial parity: same-shape merges and recorded asymmetric Stage 1 object-mask absorption work. Qualifier and common/object families remain separate. The three-stage merge algorithm and directed evidence are detailed below; broader combinations remain outside the parity claim. | Engine `Add`; literal replay; 42 recorded Stage 1 observations and seeded stateful replay |
| E1/E2 split removal, false on unrepresentable narrowing, true no-match | Implemented for recorded mask/audit/DS propagation and GUID precedence. Includes OI preservation in untouched residuals, recomputed propagation, global versus qualified rights, IOT disjointness and atomic late failure. | Engine `Remove`, `Scope`, `Split`; literal E1/E2; seeded replay; safety tests |
| D1/D2/F1 ordering | Validated explicit deny/allow then inherited order, object placement within qualifier groups. No global object-last rule or inherited reorder. Known explicit family/SID ordering and measured equal-key movement are supported; inherited order is preserved. | Engine `Prepare`; [projector](../../src/AdForLinux.DirectoryServices/Security/Core/MicrosoftObservableProjector.cs); literal D1/D2/F1 and [projection tests](../../tests/AdForLinux.FunctionalTests/MicrosoftObservableProjectorTests.cs) |
| Set/Reset/Purge/RemoveAll across GUIDs, explicit only | Implemented and recorded; inherited entries survive. SACL Set/Reset replaces explicit entries and applies recorded known-entry ordering. | Engine operation dispatch; literal state calls and seeded sequences |
| G1–G3 noncanonical rejection | Implemented atomic `InvalidOperationException`; original image and intent retained. | Literal `Recorded_noncanonical_add_and_purge_refuse_atomically`; safety tests |
| B1–B6 / D14 absent, NULL and empty behavior | Raw distinction retained; operation-specific DACL materialization, SACL no-op removals, protection and owner/group effects validated. Literal B4/B6 plus operation sequences; not a claim that every original probe row is independently replayed. | Engine; [codec tests](../../tests/AdForLinux.FunctionalTests/SecurityDescriptorCodecTests.cs); literal state calls; seeded replay |
| D4/D13 read projection separate from mutation intent | Implemented exact six-family, correct-kind, known-flag and exact-size inactive IO predicate; IO with OI/CI does not drop. NP clearing and approved DACL partition supported. Raw original retained; read projection creates no intent. | Projector `Project`/`ProjectAcl` versus `NormalizeForEdit`; projection tests exhaust 256 flag bytes × six families × two ACL kinds |
| Immutable validate-then-publish, no-op/failure intent | Implemented, bounded invariant coverage: fresh descriptor validation, snapshots, staged false/exception, previous intent, recovery after failure, size boundaries and deterministic safe algebra. | [Rewriter](../../src/AdForLinux.DirectoryServices/Security/Core/DescriptorRewriter.cs); safety `Mixed_success_false_exception_noop_and_recovery_preserve_every_snapshot`; seeded accumulated-intent sequence tests |
| Unknown/opaque ACEs and recognized trailing bytes | Approved preservation/refusal boundary: untouched sections copied exactly; mutation of a containing ACL refuses before publication. No silent opaque movement or loss. Narrower than Microsoft H2 unrelated-add behavior. | Engine `Prepare`; projector; safety and projection malformed/unknown/trailing tests |
| Overlapping storage / comment 6025043919 / J6 | Referenced compact overlap unshares into independent storage. Gapped layouts retain original unknown-byte positions; contained aliases can allocate at a known end, while crossing overlap/trailer reclassification refuse. Shared source bytes are never edited in place. | Rewriter; safety overlap tests; projection `Recorded_imports_match_or_refuse_unapproved_normalization` |
| I2 SACL ordering | Approved for fully understood entries. Multi-entry mutations match the new operation matrix; equal-key tie movement matches recorded sorting. | [Canonicalizer](../../src/AdForLinux.DirectoryServices/Security/Core/AclCanonicalizer.cs), engine; [I2 replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.I2.cs): 16 DACL and nine SACL outputs; six excluded DACL refusals |
| Import compaction and raw reconciliation | Single-pass known-ACE import compaction is projection-only. Unrelated raw entries survive writes. Retained live state and occurrence provenance reproduce all 258 fresh bridge outcomes plus eight 26-step sequences. All projected rule operations, purge and protection preserve unrelated originals; explicit raw/re-import boundaries prevent stale provenance. | Projector; engine `ModifyProjected`; [ordering safety](../../tests/AdForLinux.FunctionalTests/AclMutationEngineTests.Ordering.cs); seeded raw-import boundary assertions |
| Gaps/tails and excluded loss | Bounded fixed-offset edits, terminal resizing and contained-alias unsharing preserve unreferenced bytes. Interior resizing, unknown-trailer allocation and crossing overlap refuse. Observable repacking is separate from raw writes; unknown ACE and ACL-tail policies remain protected. | Rewriter and existing negative tests |
| Offline recorded replay on Linux/Windows, .NET 8/10 | Implemented with five explicit fixture-free classes. Fresh detached Microsoft 9 observations compared to committed observations on Windows; portable tests replay actual recorded bytes and outcomes on both OSes. | [Workflow](../../.github/workflows/acl-offline-windows.yml), [oracle provenance](../research/acl-windows-oracle/README.md), [recorder](../research/acl-windows-oracle/SeededSequences.cs) |
| J probe scope and public behavior | Selected J4/J6 import/storage evidence covered. Public modified flags/instrumentation, constructor/exception parity, public ten-type API, DirectoryEntry/LDAP, resolver, Microsoft interop and effective access are not covered by this internal task. Internal section intent is not a public write-mask promise. | Internal engine/projector tests only; existing directory workflows untouched |

## Concrete merge leads and coherent Add predicates

The original two leads were confirmed and fixed with eight directed/repeat observations in [run 37542059850](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37542059850). Follow-up review identified qualifier analogues and Stage 1 present-empty OT mask merging. Rather than retain case-specific helpers, [run 37543448512](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37543448512), head `f0305cda0cd62a0fd3cd46293608012448bdde0d`, recorded 101 additional observations:

- 13 Deny/Audit scope cases: forward/reverse plus repeats, covering success, failure and both audit bits. Reverse audit stops after its first Add because a further edit would enter the deferred existing-multi-entry SACL policy.
- Four present-empty versus absent OT mask cases: forward/reverse and repeat, with success+CI and RP/WP masks. Actual Microsoft rule bytes expose reverse constructor normalization.
- An 84-case matrix: 12 directed OT/IOT value/presence pairs, Stage 1 with Allow/Deny/Audit, Stage 2 with Audit, and Stage 3 with Allow/Deny/Audit. It includes matching/different nonempty values, absent/present-empty values and asymmetric absence controls.

All 101 return true/modified=true and preserve requested descriptor imports. Outputs comprise 44 changed one-ACE results, 50 changed two-ACE results, six one-ACE no-ops and one two-ACE no-op. Both runtimes agree, and the prior 674 observations remain unchanged. The recording run deliberately failed freshness against the older baseline while portable tests passed. Before consolidation, 25 new individual observations plus stateful replay failed.

`Add` now follows three ordered stages for matching explicit type/SID, retaining the existing ACE's raw GUID layout:

1. Identical flags and inherited-GUID **values**: OR masks when OT values match, or when the existing OT flag is absent and its mask already covers every incoming qualified bit.
2. Equal masks, inheritance flags and OT/IOT **values**: combine audit flags.
3. Equal masks/audit flags and OT values: union valid DS scopes when IOT values match or the existing IOT flag is absent. Only this stage recalculates propagation flags.

GUID-value comparisons are local to the shared merge predicate. Presence bits still govern asymmetric absorption; no global absent-versus-empty equivalence, raw rule identity change, GUID cleanup was introduced by those merge changes. The later ordering/compaction slice has its own approved policy. Same ACE type keeps Allow/Deny/Audit separate. Existing no-op, atomicity and preservation gates remain intact.

The original self/no-IOT plus same-OT descendants/IOT lead now works for Allow, Deny and each audit outcome; reverse direction retains two ACEs. The present-empty OT audit lead combines audit flags and, with identical flags, disjoint masks while preserving its existing layout. Raw-input, independent-step, stateful sequence, return/modified and accumulated-intent assertions cover the observations. Six additional safety cases check metadata, opaque neighbors, snapshots, prior intent, repeated Add and unchanged specific-removal identity.

Source basis: [Microsoft .NET 9 ACL.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs), GUID matching helpers and `MergeAces`. No confirmed mismatch remains in the 1,492 recorded observations (1,437 operation/getter steps and 55 import projections). This is not proof that all accepted inputs match Microsoft: unrecorded accepted combinations may still differ. Refusals document known preservation/policy boundaries, not a guarantee that every unsupported parity case fails closed.

## Validation inventory

| Offline xUnit group | Cases |
| --- | ---: |
| Mutation replay (including 1,492 recorded observations and 258 projected reconciliation cases, sequence and cross-runtime checks) | 1950 |
| Read projection | 78 |
| Mutation safety and preservation | 112 |
| Lossless codec | 139 |
| SID | 21 |
| Total per OS/runtime | 2300 |

The safety group also executes 100 deterministic disjoint-mask iterations with seed 2262026. Exhaustive projector flag loops and sequence steps are not additional xUnit cases. Newly recorded steps include 256 seeded operations, operation/state boundaries, removal precedence, 32 IOT cases, 64 common OI cases, 192 object OI cases, 24 combined sequence steps, 42 asymmetric object-mask Add cases and eight initial later-stage merge/repeat observations plus 101 qualifier/value-presence observations and 144 ordering/import observations; exact case definitions and provenance are in the recorder/README. Recordings use Microsoft System.DirectoryServices 9.0.0 on Windows runtimes 8.0.31 and 10.0.12; local replay uses runtimes 8.0.0 and 10.0.12.

The final revision must pass 2300 cases on Linux .NET 8/10 and Windows .NET 8/10, with all 1,492 fresh Windows observations matching. Consult PR 228 for its exact head and run evidence rather than treating the inventory as a CI status assertion.

## Acceptance decision

- Internal operation entrypoints exist and perform meaningful successful edits, but full requested semantic parity remains partial.
- Recorded replay is validated for the enumerated cases; selected I2/J rows intentionally verify refusals rather than adopting unreviewed Microsoft output.
- Failure/no-op immutability and read/intent separation have substantial deterministic coverage, including mixed success/failure/recovery snapshots.
- Not all deviations are approved or resolved: the concrete merge leads and analogues are fixed, but general accepted-input parity is not established; known-ACE SACL sorting and projection compaction are implemented, while retained projected state resolves the eight pairing-shift cases without policy relaxation; unknown data and unproved layout relocation remain bounded/refused.

Keep issue 226 open and PR 228 draft. No merge or automatic issue closure is requested.

Layout evidence adds 107 actual Microsoft observations, 84 separate raw-preservation replay
cases, byte-exact comparison of 11 independently imported candidates, and ten directed
layout safety cases. See the [layout policy and next public dependencies](issue-226-layout-policy.md).
