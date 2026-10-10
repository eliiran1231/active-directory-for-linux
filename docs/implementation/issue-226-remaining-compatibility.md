# PR 228 readiness and remaining compatibility

## Current selected scope and verified user-run evidence

PR 228 remains open/draft at the verified starting head
`d0999a643108e8d40d7c96f6d65c9f188b073cab`. The user's
[manual differential run 38072859234](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38072859234)
passed **1,363 cases on each of .NET 8/10, zero failures/skips** at that head.
Actual job logs were checked. This supersedes the earlier statement that the differential
suite had not run; the functional suite and separate explicit-Add validation matrix have
not thereby been certified. No live workflow is launched by this implementation task.

Current priorities are bounded safe raw-layout editing, identity completion, and causal
investigation of large-SDDL allocation/order differences. Microsoft conversion is
**export-only for required future scope**: existing approved import/edit-back code remains
intact, with no expansion. Broader Add support is deferred. Approved preservation
refusals are acceptable differences, not mandatory targets for unsafe parity.

The proposed public identity helper is awaiting explicit approval. Until then no export is
added. The [identity assessment](issue-226-identity-next.md) distinguishes existing public
entry routes from helper, provider, topology and live-fixture decisions.

## Completed public surface correction

The user-run manual differential workflow at `b1681e4d8be3149b81f826109fe18ed445127621`
reported 15 failures and 1,346 passes per runtime. All 15 failures reproduce in the
31 reflection-only surface tests on Linux, without directory fixtures. The old
comparers did not account for the approved portable identity/access-control substitutions;
they also exposed a real extra public type, `DirectoryIdentityResolver`.

The correction makes that unapproved helper internal, preserves automatic entry/context
integration, and uses an exact 29-type substitution map in the existing comparisons.
Extra/missing type and member detection and existing intentional-difference entries remain
unchanged. Standalone translation errors no longer direct callers to an inaccessible helper.
Two regressions check the closed exported security inventory and reject broad namespace
substitution. The 33 metadata-only tests now run in routine offline Windows CI.

The former green offline workflow did not include these legacy differential surface checks.
The separate user-run live evidence is limited evidence, not completion of the explicit-Add
plan. Corrected-head offline validation subsequently passed in run 38071830859; the user-run
differential result above is additional evidence. New changes still require exact-head validation and review.
No full differential or directory-mutating suite is rerun for this correction.

Linux .NET 8/10 pass all 33 corrected metadata checks using the pinned Microsoft
9.0.0 Windows runtime assemblies (net8.0/net9.0 assets respectively). The default
non-Windows stubs omit eight Serializable attributes and Principal's DebuggerDisplay;
those nine stub differences are not allowlisted or removed from the assertions.
The actual Windows CI uses Windows runtime assets normally. Linux also passes
12,990 core, 55 fixture-free consumers, 34 registration and four applicable companion
cases per runtime; 16 Windows-only companion groups skip. Full solution build has
zero errors and 14 existing xUnit2013 warnings. These are bounded checks, not a
claim that the unfiltered differential suite is green.

The first corrected-head Windows run (38071554110) passed all 33 surface checks and
12,990 core cases per runtime, but exposed eight failures in the migrated companion
fixture. Binding resets restore the default mask without SACL; credential resets retain
the stale managed wrapper. The fixture now explicitly closes, requests all sections,
and rereads before checking a fresh session. It still checks refusal against the old
wrapper before reacquisition. This fixture correction changes no production behavior.

## Identical reassignment write/interop integration

The [controlled integration loop](issue-226-identical-write-integration.md) adds six
public DirectoryEntry write cases and six actual Windows MicrosoftInterop cases
for absent DACL and NULL SACL reassignment. It checks no added write mask, retained
owner intent, a later target-only ACL write, shared-alias rollback, old-session
invalidation after a real edit, and commit-acknowledgment attachment lifetime.
No additional production defect or policy relaxation is claimed. Offline fake
transport success does not establish real-server behavior; allocation gaps remain
frozen and the broader compatibility limits below stay open.

## NULL/absent/empty replacement follow-up

The [24-case state matrix](issue-226-replacement-states.md) records native NULL,
absent and empty transitions plus accepted Int8/16/32 callback controls. Eight rows
match completely; 16 pin 530 scalar preservation differences. Forty-eight portable
partial-coverage cases keep retrieved metadata separate from pending intent.
Identical absent-DACL/NULL-SACL assignment now preserves raw bytes and generation
while retaining native live effects. Incoming AR and unreviewed-data guards remain.
Unmeasured flag combinations, inherited-entry removal through protection, irregular
layouts, actual partial server reads and integer export remain open. Allocation
compatibility gaps remain frozen. This is a bounded slice, not completion.

## Latest selected-ACL replacement evidence

The [selected replacement matrix](issue-226-selected-replacement.md) measures 64
scenarios plus eight shared-alias cases (136 operation steps). All 72 native rows
agree across runtimes; 54 portable rows match completely and 18 pin deliberate
atomic refusal of non-identical replacement of unreviewed ACL contents. Binary and
SDDL setters, byte-identical reassignment, prior intent, malformed new unselected
input and shared alias coherence are covered. No production defect was demonstrated;
the replacement engine and its byte-identical exception remain unchanged.
This bounds a specific family, not every selected-ACL combination: NULL/absent ACLs,
protection/inheritance control transitions and partial retrieval/layout variants
remain outside this matrix. The known allocation gaps stay frozen.

## Latest alarm composition correction

The [alarm export/reparse follow-up](issue-226-alarm-composition.md) records 96
native observations across common/object and callback alarm families, SA/FA
combinations, inactive and unselected controls. Native formatting of AL/OL succeeds
but its own reparse rejects the text, including exact legacy strings 937/987.
Raw export now refuses AL/OL for all audit-flag combinations under the existing
reconstructibility policy. This deliberately sacrifices native formatting parity;
it is not a newly discovered formatting mismatch or parser defect. Facade behavior
is unchanged. The preceding 18 raw-contract fixes remain exact; that 80-row matrix
still has 55 complete portable matches and 25 pinned refusal rows, not 80 matches.

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
| Raw descriptor layout | Fixed-offset edits, contiguous fully referenced suffix resizing and contained aliases are supported under proof. Interior resizing across unexplained storage, trailer growth/allocation, deleting referenced components in gapped images, resizing ACLs with tails and crossing overlaps refuse. | Intentional preservation constraints; broader safe algorithms require new layout proofs. Microsoft observable repacking is never persistence data. See [layout policy](issue-226-layout-policy.md). |
| Shared facades and operation combinations | Unbound ACL normalization may not reconcile when later attached. Unrecorded alias/sharing, nested callbacks, lock/reentrancy, mixed failure/success, inherited/GUID/mask and large-sequence combinations are not exhaustively characterized. | Offline evidence/implementation gap, not a known universally failing operation. Recorded invariants and races do not prove every accepted combination. |
| Strict Microsoft copy conversion | Complete verified directory-container descriptors only; partial retrieval, unexplained storage, unsupported control/reserved bits, hidden ACL data and unverified payloads refuse. Rule conversion refuses unknown subclasses, subtype/field loss, constructor normalization and unrecreatable GUID-presence/inherited states. | Deliberately strict staged companion boundary. Full conversion coverage is unfinished; native Windows execution is required. No native dependency is added to the core/AccountManagement packages. |
| Microsoft edit-back | Owner/group and proven unique-contributor mask edits/deletions plus independent non-merging explicit insertion compose atomically. Merged/duplicate/ambiguous replacements, splits, inherited edits, merging additions, reordering, control/revision/ACL-state changes and opaque edits refuse. | Existing approved bounded code remains intact; expansion is outside the newly selected export-only scope. Failed Apply retains the session but stale authority cannot be revived; successful Apply is one-use. No replacement fallback or authority transfer. |
| Entry assignment and Modify | Retrieved-section/raw-origin checks, net section flags, ordinary-property batching, lifecycle checks and uncertain-write readback are implemented through controlled transport tests. Direct property-cache descriptor writes refuse without section intent. | Raw-safe staged implementation, not proof of ADSI/server parity. Local generation checks do not provide server compare-and-swap or detect all other writers/same-DN replacement. |
| Explicit Add implementation | Omission leaves AD defaults. Explicit descriptors currently require all sections known, owner/group present, non-NULL DACL/SACL and both ACLs protected. Partial/omitted/NULL/inheriting explicit inputs are rejected. | Broader Add support is deferred by the selected scope. Request planning and server evidence remain distinct tasks. Uncertain Add stays quarantined: same-DN readback cannot prove which request created an object. |
| Real AD validation | Default descriptors, inherited access AND audit ACEs, protected/empty/NULL creation, privilege/owner constraints, server normalization, section readback, referrals/topology, move/rename, authenticated identity continuity, concurrent writers and accepted-then-timeout behavior lack current-PR end-to-end proof. | Live-only validation blocker for a production server-parity claim. The [15-cell Add plan](issue-226-add-validation-plan.md) remains unexecuted. Protected-empty DACL requires proven observer/GUID access and independent individual-delete authority before execution; ownership or admin membership alone is not proof. |
| Whole-solution consumers | Current compilation includes all six solution projects. The user-run differential suite passes 1,363 cases per runtime at d0999a6. The full functional suite has not been run here. Both contain directory-mutating fixtures. Other library families are not certified by the security manifest. | Broader integration evidence remains a release-readiness gap. The separate Add plan and unrun functional suite are not covered by the differential pass. |

## Current baseline validation scope

At `d0999a643108e8d40d7c96f6d65c9f188b073cab`,
[offline Windows run 38071830859](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38071830859)
passed all four jobs: each runtime passed 12,990 core, 33 strict surface and 327 companion
tests, zero failures/skips, full builds/package checks and native oracle freshness.
Linux passed 12,990 core, 33 surface, 55 consumer, 34 registration and four applicable
companion tests per runtime; 16 Windows-only companion groups skipped. The six-project
Release build had zero errors and 14 existing xUnit2013 warnings. Linux surface checks
used the package's Windows runtime assemblies rather than its reduced platform stubs.

The separate user-run [manual differential workflow](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38072859234)
passed all 1,363 tests on both runtimes at the same head. That includes the actual fixture
setup/cleanup and tested live routes. It is legitimate bounded live evidence; it is not an
unfiltered functional-suite pass or execution of the distinct 15-cell Add plan. This task
runs only offline tests and does not initiate any further live workflow.

The implementation follow-up at `68bec3d8dc72fcb2c020df9b8d615078faf7332a` passed
[all four Windows jobs](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38083120604):
13,051 core, 33 surface and 359 companion cases per runtime, zero failures/skips.
Linux passes 13,051 core, 33 surface, 55 consumers, 34 registration and four applicable
companion tests per runtime (17 Windows-only groups skip), plus five bounded invariant
workers per runtime. The 32 new entry relocation cases all fail with the old rewriter.
Six additional research-only capacity variants and their exact native recordings do not
change production code. Full final-head freshness/artifacts are linked in PR 228.

This follow-up adds contiguous referenced-suffix relocation, public entry identity-route
coverage and fourteen bounded native SDDL assembly/capacity witnesses. Its exact-head results and artifact
links are published in PR 228 after the push-triggered offline workflow. Native freshness
alone is not proof of portable parity, and Linux companion skips are not native execution.

## Current readiness and next work

Independent review found a blocking contained-ACL relocation hole in `b95c2ed`: appended
aliases escaped the outer-anchor unknown-payload check. The correction checks every final
ACL destination and rejects resize/alias padding before mutation publication. See the
[concrete regressions and boundary](issue-226-layout-policy.md#contained-acl-relocation-correction).
The earlier green workflow did not cover these cases. Readiness remains on hold for review
of this correction; exact corrected-head validation is reported in PR 228 after publication.
The correction adds 68 directed cases. Linux .NET 8/10 each pass 13,119 core, 33 surface,
55 consumer, 34 registration and four applicable companion tests (17 Windows-only groups
skip). The full solution builds without errors. These checks retain the original oracle
recordings and do not substitute for exact-head Windows freshness or review.

Subsequent review found the same padding/commit mismatch for same-size edits. Twelve more
cases cover entry-bound preflight and rollback while retaining the existing detached raw
padding contract. The shared descriptor checks its destination-local baseline before
publication; copies receive no resolver, authority or inherited entry constraint. Final
corrected-head test counts and artifacts are reported in PR 228.

The selected implementation goals remain bounded: safe raw-layout editing, identity
completion and a causal explanation of the large-SDDL mismatch family. The new suffix
algorithm does not authorize moving unexplained bytes or relaxing atomic refusal.
Public helper approval and explicit authority/topology/provider evidence remain distinct
identity decisions. Existing preservation differences are acceptable under the selected
scope. Microsoft conversion is export-only for required new work; approved import/edit-back
code remains intact. Broader Add support is deferred.

No new public helper is exported while its approval is pending. No GC/trust routing,
credential forwarding, Basic fallback, ambient-mutation continuity assumption, merge,
release or live operation is introduced by this follow-up. The separate live scenarios
in the table still require specifically authorized fixtures; the existing user-run suite
must not be generalized to server parity or untested object-creation variants.
