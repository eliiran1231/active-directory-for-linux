# Remaining compatibility inventory

Inventory updated for the approved optional MicrosoftInterop source implementation.
This separates missing behavior from undecided exposure and validation that cannot be
established by detached Windows objects or controlled LDAP request capture.

| Area | Concrete remaining boundary | Classification / next evidence |
| --- | --- | --- |
| Public/protected declarations | No missing declarations in the recorded 39-root, 55-type, 702-declaration target: 42 implemented types and 13 unchanged framework enums. | Complete recorded shape, not complete behavioral compatibility. Unrecorded inputs still need directed probes. |
| ObjectSecurity hooks | Base name/handle Persist and GUID rule factories throw by the measured native default contract. Concrete AD factories and entry persistence are implemented. Privilege-enabled detached Persist needs a platform override. | Defaults are not missing implementations. Platform persistence/privilege behavior needs an explicit platform implementation, not invented ambient authority. |
| Identity translation | Standalone cross-kind Translate has no attached resolver. Entry-bound resolution exists; numeric values and copies transfer no authority. Host-relative LA/LG need an explicit machine authority. | Public context-helper exposure is undecided; ambient identity pinning requires authenticated provider/OS evidence. |
| Recorded SDDL loss | 28 native-success exports omit resource/label/policy data, opaque bytes, audit flags or the no-GUID ZA tail. Portable export refuses. | Preserve binary data. A lossy diagnostic export or alternate loss-bearing representation is a separate contract; do not change ordinary export silently. |
| Recorded SDDL authority | Eight LA/LG rows depend on the Windows machine SID. | Requires an explicit authority mechanism; do not infer host/directory authority from a string. |
| Unrecorded SDDL | Additional conditional encodings, access-filter forms and resource boundaries are not established by the existing 1,681 SDDL observations. | Offline native probe work; successful binary import does not authorize a lossy text export. |
| Interop edit-back | Owner/group, proven unique mask edits/deletions and non-merging insertions can compose against original provenance. | Ambiguous replacements/splits/merges, opaque edits and unproven placement still refuse atomically; these need separate evidence, not fallback replacement. |
| Interop exposure | Approved optional MicrosoftInterop wrappers are implemented with strict conversion, defensive snapshots and checked one-success edit sessions. | Source/build/package tests only; no package release. Public identity-context helpers remain a separate decision. |
| LDAP Add request planning | Omission uses AD defaults. Explicit input currently requires all sections known, owner/group present, both ACLs non-NULL and protected. Raw bytes are sent without Modify SD-flags. | Broader explicit inputs are an implementation/validation gap, not a permanent exclusion. Request capture can prove bytes and atomicity, but cannot prove server creation semantics. |
| LDAP Add server behavior | Request-byte retention is covered for the existing complete protected subset; server acceptance/readback, defaulting, inheritance, owner constraints and SACL retrieval remain unvalidated. | [Source findings and 15-cell opt-in plan](issue-226-add-validation-plan.md). Requires a disposable OU, fixed parent fixtures, explicit accounts and separate observer/cleanup authority; no live run authorized. An uncertain Add remains quarantined; same-DN readback is not proof of creation identity. |
| Modify / concurrency | Raw section planning and successful binary recovery are implemented offline. Other directory writers, server normalization and authenticated identity continuity are not covered by that proof. | Live AD/provider validation only; no claim of server-side compare-and-swap. |

## Approved exposure contract

The [exact Microsoft companion contract](issue-226-microsoft-companion-proposal.md) is approved
and implemented under `AdForLinux.DirectoryServices.MicrosoftInterop`. The `.Microsoft`
alternative was not selected. Copy conversion is the simple path; checked edit-back remains
optional and CommitChanges remains separate. Approval covers source implementation and tests,
not live AD, package release or changes to preservation/authentication policy.

## Unchanged limits

All 36 SDDL refusals, eight callback-clear facade refusals and 41 atomic-failure differences
remain explicit. They are not counted as exact native behavior. No native recording is
fabricated or changed by a local regression. The coherent AD hierarchy/entry cutover is
already implemented; older documents that describe it as future work are historical slices.
See [current persistence status](issue-226-entry-persistence-status.md) and the
[approved contracts](issue-226-persistence-decisions.md). No live AD, merge, issue closure,
authentication/security-setting changes or effective-access evaluation is authorized here.


## Implemented in this focused pass

Internal edit-back now supports deletion of an explicit, uniquely identifiable live ACE
with exactly one proven raw contributor, including simultaneous supported mask edits.
Survivor order/content, hidden raw originals and unrelated merged contributors remain intact;
retained contributor state, shared identity and existing write intent remain coherent. The
final observable target must match exactly, or the whole operation rolls back. Thirty-one
new cases exercise this boundary, including actual Microsoft detached edits on Windows.
See [the precise edit-back contract](issue-226-interop-status.md#unique-contributor-deletion-follow-up).

The next pass implements unambiguous non-merging explicit insertion using stable raw
survivor anchors, as described in the [insertion follow-up](issue-226-interop-status.md#non-merging-explicit-insertion-follow-up).
The compound follow-up now combines unique original-contributor mask changes/deletions and
independent non-merging insertions atomically. Overlapping touched identities, ambiguous
replacement/split intent, revision changes, merged edits and reorderings still refuse. Explicit Add guards remain unchanged: Microsoft's
[SD Flags Control specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
confirms that Add ignores that control, but does not prove this client's omitted/NULL/default
or inheritance behavior. Broader request-plan tests and separately authorized server evidence
must be kept distinct. No public naming decision or live AD approval is needed for the
completed deletion slice.
