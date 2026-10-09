# Approved persistence contracts

The user approved these four recommendations in the implementation conversation on 2026-10-09:
“yeah these sound reasonable, is this not just what microsoft do tho?” This records approval
of the proposed project contracts. It is not a recording of Microsoft behavior or authorization
for live AD operations. The previous status notes calling these choices unanswered are superseded.

1. **Save only explicitly edited sections that were loaded.** Keep original raw bytes,
   retrieved-section knowledge and explicit edit intent separate from observable normalized
   serialization. Reading, projection and conversion alone do not authorize writes. Preserve
   unknown data or refuse atomically; never infer a loaded section from serializer defaults.
2. **Reassigning the same security object preserves pending edits.** Detached replacements need
   clear section intent and a loaded destination baseline. Cross-entry copies still transfer
   data only, never resolver credentials, connections, authority or source destination provenance.
3. **Creation without an explicit descriptor uses AD defaults.** Omit the descriptor attribute
   in that case. Explicit creation descriptors remain unsupported until validated. This is a
   temporary compatibility boundary to investigate, not a permanent omission from the target.
4. **Ambient credentials may support SID-to-name reads.** Name-based permission edits require
   a verified authenticated identity. Explicit credentials remain the supported route until
   ambient identity pinning is proven. The ambient-mutation limit is temporary and must remain
   visible as a validation dependency, not a claim that Microsoft universally refuses it.

## Approval, implementation and evidence are distinct

Approval removes the four policy-decision gates. The staged raw-write/context helpers and
coherent public hierarchy/consumer integration still need implementation, review and offline
failure/atomicity tests before publication as a complete persistence surface. This decision
does not itself wire portable facades into DirectoryEntry transport or change credentials,
authentication/TLS behavior, privileges or security settings.

The Windows detached-object oracle proves only its measured in-memory behaviors. These contracts
prioritize the approved preservation guarantees; do not describe them as exact Microsoft wire
parity. Commit masks, assignment intent, server creation defaults, concurrent directory changes
and ambient identity continuity require their own evidence. Existing explicit native/portable
preservation differences stay documented. No successful LDAP commit, creation or ambient
identity-pinning behavior is established by this approval or by offline descriptor tests.

Live AD binds, lookups and writes remain outside the current task authorization. Public companion
names/exposure and context-helper naming that genuinely remain undecided are not settled here.
No merge, credential/security-policy change or standalone effective-access evaluator is authorized.

## Explicit creation descriptors: compatibility target and validation plan

The user subsequently clarified that the target is Microsoft-compatible explicit descriptor
creation. The current refusal is an implementation/validation gap, not inherently a Linux-versus-
Windows limitation or a final release contract. Keep the safeguard until a correct, tested
implementation is ready; do not silently lose bytes to make creation appear supported.

Source inspection confirms that `DirectoryEntry.CommitChanges` already builds protocol
`AddRequest` objects, and its existing BCL-rooted `AddObjectSecurity` path can append an
`nTSecurityDescriptor` attribute. The current public descriptor's Windows-only base is a
separate hierarchy limitation. Inference: the future portable path can supply descriptor bytes
through the same protocol abstraction; correct creation semantics still need validation.

Microsoft's [MS-ADTS SD Flags Control specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
states that the server ignores this control on LDAP Add. Thus Modify's section-mask model cannot
establish creation intent or protect omitted creation fields. This is protocol evidence, not
an executed live-server result or proof of the complete Microsoft client behavior.

Next offline work should validate complete raw creation input and explicit intent, preserve
absent/NULL/empty and unknown-storage distinctions, and capture exact Add attributes without
reusing Modify mask assumptions. Detached Microsoft descriptor comparisons can establish
representability; controlled request/failure tests can establish local atomicity and retained
state. Neither establishes server-generated owner/group, schema defaults or inherited ACLs.

Separately authorized live AD comparison is needed for omitted versus explicit descriptors,
parent/schema defaults and inheritance, server-adjusted owner/group, SACL/privilege handling,
and successful/failed creation followed by readback against the Microsoft client. No such
operation is performed or authorized here. Ambient identity pinning remains a distinct
authentication-context/provider/OS validation issue, not a limitation of carrying bytes in Add.
