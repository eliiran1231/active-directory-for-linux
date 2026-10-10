# PR 228 readiness and remaining compatibility

## Latest raw formatting contract correction

The [bounded raw contract follow-up](issue-226-raw-formatting-contract.md) closes
all 12 malformed-condition exception facets and six raw unaudited-ACE validation
facets from the retained-export matrix. They now require exact native equality;
they were compatibility gaps, not loss evidence. Raw AU/OU/XU formatting preserves
unaudited ACEs, while the existing retained-facade guard still rejects active
unaudited projection loss. The 80 native observations agree across runtimes;
55 portable rows match completely and 25 pin only demonstrated loss/refusal facets.
The prior empty-callback correction deliberately sacrifices native formatting parity
for reconstructibility; no new parser defect was found in that composition matrix.

## Latest callback composition evidence

The [empty callback composition follow-up](issue-226-callback-composition.md)
records 48 native rows, including exact closure cases 857–859. Formatting already
matched native; both native and portable reparsing reject the missing condition.
Selected empty-callback export now refuses under the existing reconstructibility
policy. No condition or ordinary ACE replacement is synthesized. There is no new
parser acceptance gap in this matrix. The 12 exception-type and six raw
unaudited-ACE facets were genuine compatibility gaps, not loss evidence; the raw
contract follow-up above now closes them.

## Latest retained-export evidence

The [retained contributor correction](issue-226-retained-sddl-export.md) replaces
the narrow RA/FL guard with shared raw-format validation for both selected ACLs
and byte/occurrence preservation for contributors outside reviewed normalization.
ML/SP/TL, stripped audit flags, opaque/tail data and valid callback projection loss
are covered. Ordinary known ordering, compaction and approved inactive controls
remain supported. The 296 native rows agree across runtimes; 218 portable rows
match completely, while 78 have individually pinned export-facet differences.
At that head, twelve unsupported-condition exception facets and six raw unaudited-ACE
validation facets were compatibility differences. The latest follow-up closes all
18, leaving 224 exact rows and 72 pinned refusal rows in the same 296-row matrix.
These counts overlap earlier evidence.

## Latest SDDL boundary evidence

See [measured boundary findings](issue-226-sddl-boundary-findings.md): surrogate code-unit
preservation and unrepresentable ACE-size error mapping are corrected, but 25 initial size mismatches and 243 directed follow-up
parse mismatches remain unresolved. These are distinct from deliberate loss refusals;
successful test and native-freshness runs do not establish full size compatibility.

The [bounded callback-size precedence follow-up](issue-226-sddl-ace-size-precedence.md)
confirms the additional oversized XD/XU/ZA layouts and corrects ZA malformed-GUID
error mapping. The allocation matrix is frozen pending a testable causal model; the
[64 ordinary-sized mixed-ACE/section-operation follow-up](issue-226-sddl-mixed-operations.md)
is recorded. Sixty complete portable rows match; four selected RA/FL exports now refuse
proven information loss. Original raw bytes remain separate from native normalization.
The 25 initial, 243 directed and overlapping 623 expanded allocation gaps remain open.

This inventory assesses implementation head `2e4f6a2ca3aa54dc988f3c2468cfe5f79f318b03`
(tree `7d01e15c6fec4fb384f238082b36e531964e3a22`). It supersedes historical staging
statements in the linked slice documents, not their original measurements. It is an inventory
of known boundaries and untested families, not proof that no undiscovered mismatch exists.
No class is classified as mastered from declaration coverage or test counts.

The coordinated portable AD/rule/AccountManagement/DirectoryEntry cutover and optional
`AdForLinux.DirectoryServices.MicrosoftInterop` source package are implemented. Neither
remains an exposure decision. The latest production correction preserves every accepted
pending section in snapshots independently of retrieval coverage, and validates current
binding lifetime/read origin through atomic edit publication, including no-ops. Independent
review cleared those corrections, including lock order and revocation races. Detached setters
retain their behavior; partial export and out-of-coverage assignment still refuse.


Access-filter follow-up: [measured FL representation](issue-226-sddl-progress.md#access-filter-fl-representation-follow-up)
now implements SACL text import with measured mask/flag/trustee/condition rules. Native ordinary
SDDL export omits FL; 118 new pinned preservation refusals bring the SDDL total to 154.
The prior exact-head validation below remains historical evidence for its stated head; the
FL commit's exact-head results are recorded in PR 228. No broader compatibility boundary changed.

## Known compatibility inventory

“Full goal blocker” means the user's complete portable compatibility objective remains open.
A preservation difference cannot be fixed by silently discarding data. “Staged boundary” means
it can be disclosed in a deliberately limited release; it is not a claim of full compatibility.

| Family | Concrete boundary at this head | Classification and readiness effect |
| --- | --- | --- |
| Public/protected security surface | The exact recorded closure has 39 roots, 55 types and 702 declarations: 42 mapped implementations and 13 retained framework enums. No known missing declaration in that target. Compiler/nullable attributes and private implementation details are not binary-signature parity assertions. This is not a whole-library or future-runtime surface audit. | No known shape blocker within the pinned Microsoft 9 target. All behavioral rows below still apply. Consumers must rebuild for portable identity/base-type substitution. |
| Base persistence and factories | Base ObjectSecurity name/handle Persist and DirectoryObjectSecurity GUID factories throw by measured native default behavior. Privilege-enabled detached persistence needs an explicit platform override. Concrete AD factories and raw entry persistence exist. | Native defaults are not missing implementations. Portable platform persistence/privilege behavior is not supplied; no implicit privilege adjustment is authorized. |
| Identity values and collections | Numeric SID, well-known classification, pointer, collection and exception contracts are recorded. Standalone cross-kind Translate cannot acquire a resolver; same-type translation is available. | Explicit-context policy is intentional, not universal LSA parity. A public authority mechanism/helper for standalone cross-kind translation is still unresolved; it blocks claiming every required method supports every native use. Copies never transfer authority. |
| Resolver topology and authority | Entry and PrincipalContext bindings are implemented internally. Resolution is bounded to verified AD domain scope; GC, trust/cross-domain routing, foreign-security-principal display-name inference and ambient identity-pinned mutation are not implemented. LA/LG need explicit machine authority (also inside condition/resource SID values). | Full identity compatibility blocker. Scope refusals are deliberate safety boundaries. Provider/OS evidence is needed for ambient identity continuity; username labels are not proof. No public helper naming decision may be inferred from the companion approval. |
| SDDL intentional export differences | 146 recorded native-success exports lose stored information: 118 FL omissions plus the previous 28 resource/label/opaque/flag/no-GUID-ZA omissions. Portable export refuses without changing binary data. | Intentional preservation difference; blocks exact native text behavior under the ordinary API. A separately designed loss-bearing representation/diagnostic contract would be needed, not a preservation relaxation. Exact IDs remain in [SDDL status](issue-226-sddl-progress.md). |
| SDDL authority differences | Eight recorded LA/LG rows refuse instead of borrowing Windows machine identity. | Missing explicit authority support, distinct from the 28 loss refusals. Together with the 118 new FL omission cases, there are 154 pinned SDDL refusals, not successful parity. |
| Unfinished SDDL codec | Access-filter `FL` text import is implemented for the measured SACL representation; ordinary native export drops it and portable export refuses. Conditional binary encodings outside the implemented token/layout subset and nonrepresentable payloads refuse. Resource parsing is implemented; its ordinary export loss boundary remains above. | Offline implementation/probe work remains a full-goal blocker. Establish native accepted contexts, payload bytes and errors before expanding support. No effective-access evaluator is required or authorized. |
| Untested SDDL inputs | The 2,400 SDDL observations cover selected syntax, errors and encodings, not all nested expressions, resource value/count/string boundaries, rights/flag/context combinations, malformed payloads, maximum lengths or runtime-specific exception details. | Evidence gap; directed native probes remain necessary. Linear rendering/allocation tests do not establish semantic completeness or bounds for every parser path. |
| ACE/ACL projection and mutation | Known common/object access/audit ACEs have tested canonicalization, compaction and retained contributors. Unknown/wrong-kind ACEs, callback/opaque payloads, reserved fields and ACL tails do not gain general projection/mutation semantics from binary import support. Eight facade callback-clear cases refuse native data loss. | Intentional preservation boundary plus unimplemented semantics outside the understood subset. Raw copies preserve data; unrelated supported section edits may succeed. Do not label all ACE or ACL classes complete. |
| Failed mutation behavior | 41 recorded facade outcomes roll back atomically where Microsoft leaves a partial failed mutation. | Intentional, pinned safety difference; no exact-native-parity claim and no reason to weaken atomicity. |
| Raw descriptor layout | Fixed-offset edits, terminal resizing and contained aliases are supported under proof. Interior resizing across unexplained storage, trailer growth/allocation, deleting referenced components in gapped images, resizing ACLs with tails and crossing overlaps refuse. | Intentional preservation constraints; broader safe algorithms require new layout proofs. Microsoft observable repacking is never persistence data. See [layout policy](issue-226-layout-policy.md). |
| Shared facades and operation combinations | Unbound ACL normalization may not reconcile when later attached. Unrecorded alias/sharing, nested callbacks, lock/reentrancy, mixed failure/success, inherited/GUID/mask and large-sequence combinations are not exhaustively characterized. | Offline evidence/implementation gap, not a known universally failing operation. Recorded invariants and races do not prove every accepted combination. |
| Strict Microsoft copy conversion | Complete verified directory-container descriptors only; partial retrieval, unexplained storage, unsupported control/reserved bits, hidden ACL data and unverified payloads refuse. Rule conversion refuses unknown subclasses, subtype/field loss, constructor normalization and unrecreatable GUID-presence/inherited states. | Deliberately strict staged companion boundary. Full conversion coverage is unfinished; native Windows execution is required. No native dependency is added to the core/AccountManagement packages. |
| Microsoft edit-back | Owner/group and proven unique-contributor mask edits/deletions plus independent non-merging explicit insertion compose atomically. Merged/duplicate/ambiguous replacements, splits, inherited edits, merging additions, reordering, control/revision/ACL-state changes and opaque edits refuse. | Concrete unfinished reconciliation, blocking a general native edit-back claim. Failed Apply retains the session but stale authority cannot be revived; successful Apply is one-use. No replacement fallback or authority transfer. |
| Entry assignment and Modify | Retrieved-section/raw-origin checks, net section flags, ordinary-property batching, lifecycle checks and uncertain-write readback are implemented through controlled transport tests. Direct property-cache descriptor writes refuse without section intent. | Raw-safe staged implementation, not proof of ADSI/server parity. Local generation checks do not provide server compare-and-swap or detect all other writers/same-DN replacement. |
| Explicit Add implementation | Omission leaves AD defaults. Explicit descriptors currently require all sections known, owner/group present, non-NULL DACL/SACL and both ACLs protected. Partial/omitted/NULL/inheriting explicit inputs are rejected. | Concrete full-goal blocker, not a permanent exclusion. Broader request planning and server evidence are distinct tasks. Uncertain Add stays quarantined: same-DN readback cannot prove which request created an object. |
| Real AD validation | Default descriptors, inherited access AND audit ACEs, protected/empty/NULL creation, privilege/owner constraints, server normalization, section readback, referrals/topology, move/rename, authenticated identity continuity, concurrent writers and accepted-then-timeout behavior lack current-PR end-to-end proof. | Live-only validation blocker for a production server-parity claim. The [15-cell Add plan](issue-226-add-validation-plan.md) remains unexecuted. Protected-empty DACL requires proven observer/GUID access and independent individual-delete authority before execution; ownership or admin membership alone is not proof. |
| Whole-solution consumers | Current compilation includes all six solution projects. The full functional and differential suites include directory-mutating fixtures and were not executed unfiltered in this no-live-AD task. Other library families are not certified by the security manifest. | Broader integration evidence remains a release-readiness gap. No unrun suite is called passing. |

## Exact validation scope

The implementation head above passed [Windows run 37998412270](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37998412270):

- .NET 8 and .NET 10 each: 11,119 core offline tests and 321 **unfiltered companion** tests;
  zero failures/skips. Full solution builds and local package dependency/isolation checks passed.
- Fresh native comparisons each: 1,845 mutation, 2,692 foundation and 3,589 closure observations;
  exact surface comparison of 39 roots/55 types. Closure outcomes: 2,542 exact successes,
  962 exact exceptions, 36 SDDL refusals, eight facade refusals and 41 atomic differences.
- Artifacts: [net8 / 11648137304](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37998412270/artifacts/11648137304)
  and [net10 / 11648506227](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37998412270/artifacts/11648506227).
  Actual job logs were inspected; artifact ZIPs were not downloaded.
- Existing Linux .NET 8/10 evidence: 11,119 core tests per runtime; companion four passed and
  14 Windows-only groups skipped. Those skips are not native test executions.

This readiness pass additionally rebuilt **AdForLinux.sln**, Release, without incremental
compilation: zero errors, 14 existing xUnit2013 warnings; all six projects/both TFMs built,
including DifferentialTests. Dependency restoration succeeded. The shell initially lacked
`dotnet` on PATH; using the already installed `/workspace/dotnet/dotnet` resolved it. A transient
executor disconnection recovered without resetting the checkout.

Additional Linux .NET 8/10 runs each passed 55 complete-class offline consumer cases
(`AccountManagementPublicTypesTests`, `CollectionCompatibilityTests`,
`PrincipalValueCollectionTests`, `DirectoryEntryLocalStateTests`) and 34
`FixtureRegistrationTests` cases. The companion project was rerun **without any filter**:
four passed, 14 Windows-only groups skipped per runtime. The consumer and fixture-registration
runs are explicitly filtered; they are not a full unfiltered functional/differential pass.
Local build/log/TRX evidence is in `/workspace/pr228-evidence/readiness-*`.

Unfiltered functional/differential execution is blocked by task scope: `TestSettings` defaults
to a Samba endpoint, and `TestDataFixture` creates users/computers/groups and cleans them up.
No authorized live fixture is available for this task. Network namespace isolation was also
unavailable (`unshare`: read-only uid_map); no test was redirected to real AD or run on an
assumption that missing configuration would skip it. Fixture registration is metadata-only,
not server validation. The existing Windows workflow intentionally filters the six offline
core classes; its green result cannot be promoted to unfiltered solution-test evidence.

## Readiness decision and next work

The complete implementation goal remains **open**: explicit identity authority/topology,
SDDL codec coverage and loss-bearing export design, broader safe interop reconciliation,
explicit Add variants, and the untested/server families above are concrete unfinished work.
Preservation-driven differences and measured native base-method exceptions must remain
separate from missing code. There is no remaining known declaration gap in the recorded
security closure, but that fact closes none of these behavioral gaps.

A clearly labeled staged PR could carry the current bounded implementation and intentional
refusals, after normal review and explicit maintainer acceptance of the base-type/API migration.
A staged release would also need an explicit supported-scope statement and release acceptance
of the unrun live suites; this inventory does **not** certify production directory parity or
approve publication. Neither a full compatibility release nor issue closure is justified.
No merge, release, package publication, live AD, credentials/security change or new feature
slice was performed in this readiness pass. The next slice should be chosen from this
inventory, with its native evidence and acceptance boundary specified first.
