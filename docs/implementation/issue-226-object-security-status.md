# Detached ObjectSecurity facade — measured implementation

`ObjectSecurity` and `DirectoryObjectSecurity` now live in the approved
`AdForLinux.Security.AccessControl` namespace in the existing DirectoryServices DLL.
The exact declared public/protected surface comparison covers **29 supporting types**.
The full 55-type target remains required. This slice does not rebind the AD rule hierarchy,
wire DirectoryEntry persistence, resolve account names, or evaluate effective access.

## Native evidence and dispatch

The offline Windows probe at `d7395389ba3760e1b0900aa713fc3a37672c0718`, run
[37953506781](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37953506781),
adds 227 facade observations. The follow-up at `5b1a5b3dab6031a9eab22d0b9b45c94faab939b3`,
run [37956444278](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37956444278),
adds 22 more and leaves all preceding 3,495 rows unchanged. Those probes established
**3,517 closure observations**, including **249 facade rows**. Recordings are exact
`CLOSURE_JSON` lines from authorized decoded Windows job logs; provenance files record
source heads/jobs and hashes. Both probe-only workflows passed their full builds and
8,714 preceding offline tests, then failed only the expected closure freshness check.

The probe source is also compiled against the portable types for replay. It measures
constructors, supplied-descriptor sharing, wrapper-local protected flags, recursive and
cross-wrapper locks, cross-thread lock independence, typed-helper dispatch, modification
return/out values, section setters and failures, enumeration, callback exclusion and
common/object factory dispatch. It uses numeric identities only. Persistence probes call
recording overrides or unsupported base paths; they perform no directory or privilege work.

Measured distinctions retained by the implementation:

- Supplied descriptor identity is shared. ACL assignments preserve supplied facade identity;
  indexer reads return snapshots. Edits are visible through other wrappers of that descriptor.
- Compatibility locks and the four protected dirty flags belong to each wrapper. Holding A's
  lock does not authorize B's flags. A's lock does not block B's lock on another thread.
- External owner/group/ACL edits do not set every wrapper's dirty flags. Native successful
  no-op methods can set a wrapper flag without creating raw write intent.
- Public modify calls dispatch through the public and protected virtual hooks. Typed helpers
  take the native private-overload path and bypass those overrides. There is no ResetAuditRule
  helper. Object-GUID factory defaults and base persistence paths throw NotImplementedException.
- Persist(false, name, sections) forwards to the virtual name hook. The true path requires an
  explicit platform persistence override and refuses in the detached base; it never adjusts
  privileges or derives ambient authority.

## Raw/live state and transactions

Common descriptors retain an immutable mutation engine with the original raw image, current
raw storage, retained live groups, contributor provenance and write intent. Binary constructors
keep gaps, tails, reserved fields and excluded raw data independently of native observable
serialization. Raw facade inputs retain their original encoding; an edited raw facade with
unreconciled unexplained storage refuses binding instead of silently discarding that storage.

Common ACL edits attached to descriptors run native-compatible value operations and reconcile
against the engine's retained projected operations. Candidate observable bytes must agree before
publication. Shared ACL edits stage each affected descriptor and roll every participant back if
any preservation check fails. Explicit section assignments use the same layout rewriter and
refuse replacement of unknown/unreviewed ACL content. Section setters also refuse incoming
unreferenced storage, resource-manager data or control fields their native assignment path does
not carry; complete binary constructors preserve those inputs.

An internal transaction gate serializes actual shared state operations. It is not the protected
compatibility lock. Virtual factories and protected modification overrides execute outside
that gate while retaining their native wrapper-lock discipline; callbacks can therefore allow
peer wrappers to make progress without creating a lock-order cycle. Individual ACL reads still
serialize against staged state changes. Base compound operations retain their transaction;
arbitrary user override code controls its own sequence of completed operations.
Nested operations have rollback savepoints so an override catching a failed
inner edit cannot leave that edit's staged state behind. Compound setter/helper failures restore
raw and live values, facade references, provenance, mutation versions and protected flags.

Each wrapper separately captures its immutable read snapshot and retrieved-section mask.
An independent per-section mutation ledger tracks pending changes since that wrapper was created;
it does not copy another wrapper's preexisting persistence intent. These data-only contexts carry
no credentials, connections, resolver or persistence capabilities. Descriptor copying starts a
new detached context. The ledger is not wired to DirectoryEntry writes.

## Explicit atomic-failure difference

Case **3398** (FacadeModify scenario 55) shows Microsoft creating an empty SACL before throwing
ArgumentOutOfRangeException("modification") for invalid enum value 6. The approved portable
atomic-failure policy restores the absent SACL instead. Replay pins the exact native post-failure
image and the independently recorded pre-edit image, then compares every other field unchanged.
This is an explicit safety difference, not native parity, an ignored row, or a changed oracle.
Eight further rows, **3509–3516**, clear an ACL containing a callback ACE before enumeration.
Microsoft discards that ACE; the existing raw preservation policy refuses the clear. Replay
pins the SHA-256 of each complete native row and the exact portable refusal, and a separate
regression checks unchanged raw bytes, facade identity, ledger and flags. These eight facade
refusals are distinct from the SDDL inventory. The other 240 facade observations require exact
native outcomes/exceptions.

## NULL/absent DACL transaction correction

The independent review reproduction was confirmed against `ff79e519`: all 40 null-SID and
zero-mask validation cases changed observable descriptor bytes while raw state, mutation
versions and write intent stayed unchanged. The eight direct Add/Set/Remove/RemoveSpecific
entry points cleared the synthetic Everyone-DACL marker before transaction capture; the
four rule overloads reached the same paths. Of 32 rejected-layout-growth cases, 30 failed
the rollback regression, including no-op removals that skipped reconciliation entirely.

The marker transition now occurs inside `Edit`, after capture and before change detection.
Protection uses the same ACL transaction to capture the marker and reconcile every shared
descriptor owner, preserving each owner's protection flags. Marker-only transitions therefore
materialize raw state on success and roll back atomically on validation, preservation or
enclosing-operation failure. Unexplained descriptor trailers still prevent layout growth.

Actual [Windows probe 37961748099](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37961748099)
at `e1275e8885281c9a16b8857e9439f5955294df0a` adds **72 rows**: 40 validation failures,
24 successful edits and eight protection combinations, with absent and NULL DACLs and shared
descriptor aliases. Both runtimes passed full builds and all 8,978 prior tests; only the
expected closure freshness check failed. The original 3,517 rows are unchanged.
[Provenance](../research/acl-windows-oracle/results/log-derived-37961748099-provenance.json)
records exact authorized job-log JSON hashes.

Windows materializes the synthetic ACL before all 40 validation exceptions. Cases **3517–3556**
pin the exact native before/after images and exception type/parameter, then require portable
rollback to the recorded pre-call image for both aliases. They are deliberate atomic-failure
differences, not native parity or changed recordings. All 32 successful/protection rows require
exact native outcomes. Local regressions additionally cover raw/live state, retained provenance,
version/section ledgers, wrapper flags, refused trailer growth and enclosing rollback: 137 tests.

The existing **36 SDDL refusals remain unchanged**. Current closure accounting is **3,589 rows**:
2,542 exact successful outcomes, 962 exact native exceptions, 36 pinned SDDL refusals, eight pinned
facade preservation refusals and 41 pinned atomic-failure differences. The 321 facade rows comprise
272 exact outcomes/exceptions, eight preservation refusals and 41 atomic differences.
Runtime differences remain only mapping-exception cases 2314/2317.

## Validation and remaining cutover dependencies

Local safety regressions cover retained contributors across shared wrappers and ACL aliases,
opaque opposite sections, shared-owner rollback, nested savepoints, no-op write intent,
wrapper-local snapshots, raw NULL versus absent DACL state, independent thread locks,
peer-wrapper mutation from factory/protected-hook callbacks,
refused incoming storage and failed unresolved-name edits without revision-upgrade residue.
Full Linux and exact-head Windows results and artifact links are maintained in draft PR228.

The [entry-bound resolver and raw-preparation slice](issue-226-identity-context-status.md) now
implements explicit context translation and binding without enabling the AD transport cutover.
Broader native facade combinations remain probe-driven compatibility work, including
unbound ACL value edits whose raw normalization cannot yet be reconciled when later attached.
Future resolver callbacks must also remain outside the shared state gate.
The complete AD/rule/consumer cutover still requires reviewed raw write preparation, explicit
retrieved-section/context binding and coordinated compile/reflection fixture migration. Public
observable binary output must never be treated as raw persistence bytes. The existing AD
hierarchy, transport and authentication paths remain unchanged; no merge or issue closure is
part of this stage.
