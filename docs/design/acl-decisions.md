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

## Still open (not decided)

These remain open. They are not decided by implication from the decisions above.

- Which observed Microsoft normalizations are accepted as harmless (D3 open item).
- Write-mask policy on commit: `Modified ∩ Retrieved` versus Microsoft's wire mask (O-4).
- Detached assignment to the same entry, and LDAP Add creation defaults.
- The protected `CommonSecurityDescriptor` facade surface (D5 asks for an explicit design; none
  has been chosen).
- The resolver's final helper and overload names, and its error categories.
- Whether the portable implementation follows Microsoft's absent/NULL-DACL materialization of an
  explicit Everyone full-control ACE (observed in the oracle), or refuses that transition. This is
  a representation question, not a new grant: a NULL DACL is already unrestricted.
