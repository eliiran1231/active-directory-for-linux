# ACL design decisions record

Issue #224 / PR #225. This file records **user decisions only**. A recommendation in another
design document is not a decision until it appears here. Each entry paraphrases the user's
statement closely and lists what it leaves open. Earlier decisions recorded elsewhere are
listed for reference and are not reopened.

## Earlier decisions (recorded in the linked documents)

| Date | Decision | Source |
|---|---|---|
| 2026-10-05 | A parallel portable public ACL API is rejected | [core design §1](portable-acl-core.md#1-summary-and-recommendation) |
| 2026-10-05 | Investigating the same ten class names with portable base/identity types is authorized | [same-name candidate](same-name-portable-acl-api.md) |
| 2026-10-06 | Cross-entry descriptor assignment copies data only, never resolver/credential authority | [resolver research](context-bound-identity-resolution.md#approved-cross-entry-assignment-copy-data-never-authority) |

## Decisions of 2026-10-06

### D1. One portable surface on Windows and Linux, with explicit snapshot bridges

Use the same portable security types on both platforms. For Windows interoperability, add
explicit `ToMicrosoftObject`/`FromMicrosoftObject`-style conversion helpers. Document that they
create **snapshots, not live adapters**, and that they do not restore BCL casts or binary
compatibility.

### D2. Export shape: option (a)

Provide two exports:
- a plain detached `ToMicrosoftObject()`;
- a separate provenance-carrying export, which is the only route for edit-back.

The plain Microsoft object is still mutable, so call it **detached**, not "read-only". Its
edits never synchronize automatically and cannot bypass import safeguards.

### D3. Conversion data loss

- **Default:** refuse data loss.
- **Diagnostic projection:** an explicitly requested diagnostic projection may allow loss with
  clear warnings, but it can **never** qualify for safe edit-back.
- **Normalization vs loss:** harmless, *verified* normalization is different from dropping an
  ACE or a condition.
- **Callback ACEs:** they are not universally unsupported by Microsoft. Test the actual
  conversion path rather than assuming.

Open: which specific normalizations count as "harmless, verified". The
[Windows oracle](../research/acl-windows-oracle/README.md) lists the observed changes; it does
not classify them.

### D4. `GetSecurityDescriptorBinaryForm` and original bytes

- `GetSecurityDescriptorBinaryForm` matches Microsoft's observable in-memory behavior,
  verified with oracle tests.
- Original server bytes are kept separately for section-preserving commits.
- Reading or normalization never creates write intent.
- Conversion and edit-back preserve unread sections and unknown data, or refuse safely.

### D5. Protected hooks are preserved

Don't drop protected hooks just to reduce scope.
- Preserve override points and familiar signatures using portable dependencies, including all
  `Persist` overloads.
- Preserve Microsoft's actual dispatch and sealed behavior.
- Don't silently reinterpret native persistence as LDAP.
- Design the remaining descriptor dependencies (the protected `CommonSecurityDescriptor`
  surface) explicitly.

### D6. Base `Persist(enableOwnershipPrivilege: true, …)`

Preserve the override. Do not claim one exception matches Microsoft universally, because
Microsoft's behavior depends on privilege handling and virtual dispatch. Keep native privilege
manipulation out of the portable core, and document the true-valued base path as
**unsupported for now**. This is a **compatibility limitation, not parity**.

### D7. Namespace and assembly

`AdForLinux.Security.*` lives inside `AdForLinux.DirectoryServices.dll`.

### D8. Microsoft interop packaging

Use the optional `MicrosoftInterop` companion assembly. The portable security types stay in the
main DLL. Linux users must not need Microsoft `System.DirectoryServices` just for the portable API.

Open: final assembly and package name, and the internal snapshot interface the companion uses.

### D9. `Principal.Sid`

Include `Principal.Sid`'s portable return type in the coordinated pre-release design, for both
platforms. Keep `SidValue`, and document migration and interoperability.

### D10. Release status

Nothing has been released. Settle these contracts before the first release; there is no
already-released API to version against.

### D11. Identity resolution and ambient Kerberos

- Allow ambient Kerberos for ordinary **SID → name** lookups. The earlier blanket refusal was
  too restrictive.
- Do **not** assume a newly opened connection uses the identity that originally read the
  descriptor.
- Invalidate lookup caches on rebind and on context changes.
- **Name → SID** resolution used for permission changes must go through a valid, unambiguous
  context before mutation.
- Stale descriptors require explicit context reacquisition.

This supersedes the blanket ambient refusal proposed in the
[resolver research](context-bound-identity-resolution.md). The research's other analysis stands.

Open: what makes a context "valid" for name → SID mutation under ambient authentication, the
exact cache-invalidation triggers, and the exception contract.

### D12. Next research step

Offline Windows oracle recordings are the right next step: merge/split, ordering,
null/empty/absent DACLs and conversion round-trips. Keep them in memory, with no AD writes and
no token or privilege changes. First recordings: [acl-windows-oracle](../research/acl-windows-oracle/README.md).

### D13. Accepted normalizations: a narrow, tested allowlist

Accept a narrow, tested allowlist, not the whole group of observed normalizations automatically:

| Observed Microsoft change | Decision |
|---|---|
| Repacking descriptor components with correct offsets | Reasonable |
| Clearing NoPropagate when neither inheritance flag is present | Reasonable |
| InheritOnly without inheritance flags (Microsoft drops the entire inactive ACE) | Do **not** clear just InheritOnly: that would activate the ACE |
| Moving object ACEs | Only within the appropriate explicit deny/allow groups, preserving inherited order. Never globally move object ACEs last |
| Loss of meaningful audit/label entries, conditions or unknown data | Keep refusing |

Each exception needs exact preconditions, and tests for access and inheritance effects, not
just matching bytes.

**Amendment (2026-10-06): inactive InheritOnly ACEs.** The user chose to allowlist the drop, as
a narrowly defined exception matching the verified Microsoft behavior (oracle I1 "IO only"):

- **Scope:** a recognized, fully understood ACE with InheritOnly set and **neither**
  ContainerInherit nor ObjectInherit set. Such an ACE applies neither to the current object nor
  to descendants, so dropping it from the Microsoft-compatible projection changes no access.
- **Never** clear just InheritOnly: that would activate the ACE.
- **Lossless representation:** the original ACE is kept in the raw bytes. Conversion alone must
  not create write intent.
- **Refuse instead** if the ACE has unknown flags, an unsupported type or an unvalidated payload.

This is an explicit allowlisted normalization, not general permission to discard ACEs.

**Second amendment (2026-10-06): allowlist scope after reviewing the
[I2 matrix](../research/acl-windows-oracle/README.md#inactive-inheritonly-matrix-i2).** The user
agreed to include inactive audit ACEs "under those exact restrictions", meaning the proposed
restrictions below, which were reviewed against I2. An inactive ACE qualifies for the drop only
if **all** of these hold:

| Restriction | Allowed |
|---|---|
| ACE type | Allow 0x00, Deny 0x01, Audit 0x02, Allow-object 0x05, Deny-object 0x06, Audit-object 0x07 |
| ACE flags | InheritOnly (0x08) set; ContainerInherit and ObjectInherit clear; otherwise only NoPropagate (0x04), Inherited (0x10), and for audit types Success (0x40) / Failure (0x80). Any other bit → refuse |
| Object ACEs | Object flags in {0, 1, 2, 3} only; each GUID present exactly when its flag says so |
| Body | Valid SID; ACE size matches the parsed content exactly (no trailing bytes) |

**Audit rationale (user):** InheritOnly prevents the ACE applying to the current object, and
without ContainerInherit/ObjectInherit it cannot propagate. This **does not** authorize dropping
meaningful audit entries; D13's refusal of meaningful audit and label loss stands.

**Still excluded, refuse instead:** callback, conditional and unknown-type ACEs, unknown ACE or
object flags, and trailing bytes. They stay excluded unless separately validated, even though
Microsoft drops them too (I2).

All other parts of this amendment still apply: the original ACE is kept in the lossless
representation, conversion alone creates no write intent, and InheritOnly is never cleared on
its own. Each allowed case still needs exact-precondition tests for access and inheritance
effects before implementation.

### D14. Absent/NULL DACL: follow verified per-operation behavior

Follow Microsoft's verified **per-operation** behavior, not a blanket "Everyone on any edit" rule.
The recordings show:
- `AddAccessRule` and the tested protection change materialize Everyone;
- removing Everyone instead produces an empty DACL, which is very different.

Add cases for owner/group/SACL-only changes, no-ops and failed calls before generalizing.
Preserve the original absent/null/empty distinction internally, and never turn getter
normalization into write intent. Compatibility stays the goal, without adopting an overly
broad rule.

Those cases were then recorded ([oracle B6](../research/acl-windows-oracle/README.md#per-operation-matrix-b6)).
They show materialization for every DACL-targeted call past argument validation, including
no-match removes, but not for owner/group/SACL-only changes, getters or failed calls.
Recording them does not by itself decide any further generalization.

## Still open (not decided)

These remain open. They are not decided by implication from the decisions above.

- SACL re-sorting on `AddAuditRule` (oracle I2 separate finding): not analyzed and has no
  allowlist status.
- Write-mask policy on commit: `Modified ∩ Retrieved` versus Microsoft's wire mask (O-4).
- Detached assignment to the same entry, and LDAP Add creation defaults.
- The protected `CommonSecurityDescriptor` facade surface (D5 asks for an explicit design; none
  has been chosen).
- The resolver's final helper and overload names, and its error categories.
- How the internal model represents a materialized Everyone ACE while preserving the original
  absent/NULL/empty state (D14 requires both). This is a representation question, not a new
  grant: a NULL DACL is already unrestricted.
