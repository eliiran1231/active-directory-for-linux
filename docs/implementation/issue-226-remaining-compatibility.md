# Remaining compatibility inventory

Inventory at published head `0fe25daa6e0e3bda233893963c32149755667c89`.
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
| Interop edit-back | Internal export validates actual target construction, wrapper/generation provenance and raw contributors. Unique mask edits work; structural changes and merged/ambiguous edits currently refuse. | Independent offline implementation work: start with explicit unique single-contributor deletion, proving survivor bytes and final projection. Additions/splits/reordering require separate proofs. |
| Interop exposure | Identity, nine AD-rule subtypes, ordered collections and descriptor snapshots are internal. The optional Microsoft companion is approved, but its final package/API names and friend-access arrangement are not settled. | Genuine exposure decision, not a reason to stop internal compatibility work. No public names are selected here. |
| LDAP Add request planning | Omission uses AD defaults. Explicit input currently requires all sections known, owner/group present, both ACLs non-NULL and protected. Raw bytes are sent without Modify SD-flags. | Broader explicit inputs are an implementation/validation gap, not a permanent exclusion. Request capture can prove bytes and atomicity, but cannot prove server creation semantics. |
| LDAP Add server behavior | Omitted/NULL/defaulted/inheriting descriptors, schema/parent defaults, SACL privileges, normalization and readback parity. | Separately authorized live AD comparison required. An uncertain Add remains quarantined; same-DN readback is not proof of creation identity. |
| Modify / concurrency | Raw section planning and successful binary recovery are implemented offline. Other directory writers, server normalization and authenticated identity continuity are not covered by that proof. | Live AD/provider validation only; no claim of server-side compare-and-swap. |

## Concrete exposure proposal

The [exact Microsoft companion contract](issue-226-microsoft-companion-proposal.md) now
proposes `AdForLinux.DirectoryServices.Microsoft` as NuGet package, assembly and namespace;
`MicrosoftConversions` extensions; immutable `SecurityDescriptorSnapshot`; and disposable
`MicrosoftSecurityEdit` with explicit one-success `ApplyTo(source)`. It includes complete
signatures, version/friend access, disposal/authority semantics, caller examples and migration
differences. These are proposed names, not implemented public declarations. The optional
companion/detached conversion/separate edit-back architecture is already approved and is not
being asked again. Internal compatibility work remains independent of the final naming decision.

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
Mixed insertion-plus-existing-ACE changes, revision-changing insertions, merged edits, splits
and reorderings still need their own contributor proofs. Explicit Add guards remain unchanged: Microsoft's
[SD Flags Control specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
confirms that Add ignores that control, but does not prove this client's omitted/NULL/default
or inheritance behavior. Broader request-plan tests and separately authorized server evidence
must be kept distinct. No public naming decision or live AD approval is needed for the
completed deletion slice.
