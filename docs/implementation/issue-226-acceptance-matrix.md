# Issue 226 — morning review acceptance matrix

This is a partial implementation for [issue 226](https://github.com/eliiran1231/active-directory-for-linux/issues/226), submitted in [draft PR 228](https://github.com/eliiran1231/active-directory-for-linux/pull/228). It does not complete or close the issue. The two concrete later-stage merge leads have now been recorded and fixed within narrow predicates. The PR records the final tested head and actual Windows run URL.

“Validated” below means the specified recorded or invariant cases, not universal Microsoft parity. “Refused” means no candidate is published. “Deferred” identifies an unresolved policy or parity requirement. Confirmed later-stage mutation defects and their bounded fixes are recorded separately below; they did not change import or ordering policy.

## Requirements and evidence

| Issue requirement | Status and implemented boundary | Source and tests |
| --- | --- | --- |
| Internal Add/Set/Reset/Remove/RemoveSpecific/RemoveAll for DACL and SACL | Implemented; successful recorded operations in both ACL kinds. Multi-entry SACL gate below limits subsequent edits. | [Engine](../../src/AdForLinux.DirectoryServices/Security/Core/AclMutationEngine.cs), [literal replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.cs), [seeded replay](../../tests/AdForLinux.FunctionalTests/AclMutationReplayTests.Seeded.cs) |
| Purge, access/audit wrappers, protection, owner/group | Implemented and validated for explicit SID targeting, inherited-entry retention/removal and detached protection behavior. Owner/group changes preserve unrelated opaque ACLs. | Engine; literal `Recorded_state_call_matches_bytes`, `Recorded_B4_protection_preserve_inheritance`; seeded sequences; [safety tests](../../tests/AdForLinux.FunctionalTests/AclMutationEngineTests.cs) |
| C1–C3 mask OR, complementary scopes, audit merging | Partial parity: same-shape merges and recorded asymmetric Stage 1 object-mask absorption work. Qualifier and common/object families remain separate. The two later-stage directed merge fixes are detailed below; broader combinations remain outside the parity claim. | Engine `Add`, `CanAbsorbObjectMask`; literal replay; 42 recorded Stage 1 observations and seeded stateful replay |
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

## Two concrete accepted-input leads recorded and fixed

Both source-supported leads were confirmed by detached Microsoft Windows recording, then fixed. [Recording run 37542059850](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37542059850), head `0df679d6f03146f166e3199a86101434ee3d4799`, added four directed cases with a repeated Add each: eight observations, identical on .NET 8/10. The original 666 observations are unchanged. The run deliberately failed the freshness comparison against the then-committed 666-case baseline; its portable test steps passed. Before the fix, the new replay produced four individual failures plus one stateful sequence failure.

Use the same SID and mask `0x10` in each pair, with distinct nonempty GUIDs G1/G2:

1. **Stage 3 inherited-GUID/scope merge:** existing AllowObject flags `0x00`, object flags `1`, OT=G1, no IOT; incoming AllowObject flags `0x0A`, object flags `3`, OT=G1, IOT=G2. Microsoft produces one ACE with flags `0x02`, object flags `1`, OT=G1. Reverse direction retains two ACEs. The fix supports that forward direction and repeated Add against its already merged `0x02` state, preserving the existing GUID shape. It is limited to AllowObject, equal mask/type/SID, matching nonempty OT and the recorded flags/presence patterns.
2. **Stage 2 audit GUID-presence merge:** existing AuditObject flags `0x42`, object flags `3`, OT=Guid.Empty, IOT=G2; incoming flags `0x82`, object flags `2`, no OT, IOT=G2. Microsoft produces one ACE with flags `0xC2`, preserving the existing present-empty OT. The fix permits this equal-mask audit merge with matching inherited GUID and CI scope. In reverse, the requested empty OT normalizes to absent in the actual Microsoft rule; the existing same-shape merge already produces one ACE with flags `0xC2`, object flags `2`.

All eight calls return true/modified=true. Each repeat leaves bytes unchanged and creates no new internal intent. Every requested descriptor imports unchanged; requested versus effective rule bytes explicitly expose the reverse-audit constructor normalization. These are mutation outcomes, not SACL sorting or import compaction. Raw-input, return/modified, independent-step and stateful accumulated-intent assertions remain in the replay suite. Two added metadata/snapshot tests cover prior intent, exact neighboring opaque ACLs, ACL tails/reserved bytes and repeat no-ops; four negative boundary tests retain distinct masks/OT/IOT scopes.

Source basis: [Microsoft .NET 9 ACL.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs), `ObjectTypesMatch`, `AceFlagsAreMergeable` and `MergeAces`. No confirmed mismatch remains in the 674 recorded observations. Other GUID/audit/propagation combinations remain untested breadth; this does not claim general later-stage parity.

## Validation inventory

| Offline xUnit group | Cases |
| --- | ---: |
| Mutation replay (including 674 newly recorded steps, sequence and cross-runtime checks) | 788 |
| Read projection | 78 |
| Mutation safety and preservation | 68 |
| Lossless codec | 139 |
| SID | 21 |
| Total per OS/runtime | 1094 |

The safety group also executes 100 deterministic disjoint-mask iterations with seed 2262026. Exhaustive projector flag loops and sequence steps are not additional xUnit cases. Newly recorded steps include 256 seeded operations, operation/state boundaries, removal precedence, 32 IOT cases, 64 common OI cases, 192 object OI cases, 24 combined sequence steps, 42 asymmetric object-mask Add cases and eight directed later-stage merge/repeat observations; exact case definitions and provenance are in the recorder/README. Recordings use Microsoft System.DirectoryServices 9.0.0 on Windows runtimes 8.0.31 and 10.0.12; local replay uses runtimes 8.0.0 and 10.0.12.

The final revision must pass 1094 cases on Linux .NET 8/10 and Windows .NET 8/10, with all 674 fresh Windows observations matching. Consult PR 228 for its exact head and run evidence rather than treating the inventory as a CI status assertion.

## Acceptance decision

- Internal operation entrypoints exist and perform meaningful successful edits, but full requested semantic parity remains partial.
- Recorded replay is validated for the enumerated cases; selected I2/J rows intentionally verify refusals rather than adopting unreviewed Microsoft output.
- Failure/no-op immutability and read/intent separation have substantial deterministic coverage, including mixed success/failure/recovery snapshots.
- Not all deviations are approved or resolved: the two concrete later-stage leads are now fixed, but general merge parity is not established; SACL sorting and import/gap policies remain decisions.

Keep issue 226 open and PR 228 draft. No merge or automatic issue closure is requested.
