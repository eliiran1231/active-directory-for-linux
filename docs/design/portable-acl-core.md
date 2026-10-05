# Design: a portable ACL core for the ten Linux-blocked security classes

Status: **proposal for review** · Issue: #224 · Baseline: `dev` @ `e72a421a` · Related: #5, #90 (closed)

This document is design-only. It records the constraints, the alternatives, a recommended
direction and the decisions still open. It does not change production code, and it does not
propose a Windows access-check (effective-permissions) engine.

The ten classes in scope, all in `AdForLinux.DirectoryServices`
([ActiveDirectorySecurity.cs](../../src/AdForLinux.DirectoryServices/ActiveDirectorySecurity.cs)):

| # | Class | Base today | Visible ctors |
|---|---|---|---|
| 1 | `ActiveDirectorySecurity` | `DirectoryObjectSecurity` | 1 |
| 2 | `ActiveDirectoryAccessRule` | `ObjectAccessRule` | 6 |
| 3 | `ActiveDirectoryAuditRule` | `ObjectAuditRule` | 6 |
| 4 | `CreateChildAccessRule` | `ActiveDirectoryAccessRule` | 6 |
| 5 | `DeleteChildAccessRule` | `ActiveDirectoryAccessRule` | 6 |
| 6 | `DeleteTreeAccessRule` | `ActiveDirectoryAccessRule` | 3 |
| 7 | `ExtendedRightAccessRule` | `ActiveDirectoryAccessRule` | 6 |
| 8 | `ListChildrenAccessRule` | `ActiveDirectoryAccessRule` | 3 |
| 9 | `PropertyAccessRule` | `ActiveDirectoryAccessRule` | 6 |
| 10 | `PropertySetAccessRule` | `ActiveDirectoryAccessRule` | 3 |

---

## 1. Summary and recommendation

1. **Build a pure, managed security-descriptor core** (SID, ACE, ACL, self-relative
   descriptor, rule semantics). It has no `System.Security.AccessControl` or
   `System.Security.Principal` dependency, does no I/O and does no name lookup. It is
   lossless by default: bytes it was not asked to change come back unchanged.
2. **Route all `nTSecurityDescriptor` reads and writes in `DirectoryEntry` through one
   section-aware descriptor state** backed by the core, on both platforms. Writes cover only
   the sections that were both retrieved and modified.
3. **Keep the ten existing classes BCL-derived and unchanged in signature.** On Windows they
   stay the Microsoft-compatible surface, and the core is checked against them byte for
   byte. They **cannot** become executable on Linux without a breaking change (§3). This
   document does not claim otherwise.
4. **Add a parallel, portable public API** in a new namespace that mirrors the ten classes'
   operations one to one, using a portable SID type in place of `IdentityReference`. This is
   how Linux callers get ACL functionality.
5. **Defer the breaking option** (re-rooting the ten classes per target framework) to an
   explicit maintainer decision after phases 1–2 ship. It goes ahead only if user demand
   justifies a split public API.

Phases: **P1** core + transport + rewrite `ChangePasswordAcl` on the core (internal only) →
**P2** portable public API → **P3** decision on re-rooting. See §10.

---

## 2. Scope

In scope: the representation and binary codec, directory ACE semantics, mutation semantics,
the read/edit/write data flow through `DirectoryEntry`, the compatibility strategy, safety
rules and the test/oracle plan.

Out of scope: implementation, production changes, running workflows, real permission
changes on any directory, an access-check engine, SDDL alias resolution that needs a domain
(planned as a later component, §4.7), and schema/GUID name lookup (`schemaIDGUID`,
`rightsGuid`).

---

## 3. Evidence: platform constraints

These were checked against the official `Microsoft.NETCore.App.Runtime.linux-x64` 10.0.0
runtime pack by reading the IL of the Linux implementation assemblies. They were not assumed.

| Fact | Evidence | Consequence |
|---|---|---|
| Every constructor of `SecurityIdentifier`, `NTAccount`, `IdentityReference` throws `PlatformNotSupportedException` on Linux | IL for each ctor in `System.Security.Principal.Windows.dll` (linux-x64) is `newobj PlatformNotSupportedException; throw` | No `IdentityReference` value can exist on Linux, so no rule constructor can be called with a valid identity. |
| `IdentityReference`'s only constructor is `internal` | Ref pack 10.0.3 `System.Security.Principal.Windows.dll`, ctor access = `Assembly` | A third-party portable identity type **cannot** subclass `IdentityReference`. Every signature that takes or returns `IdentityReference` is Windows-only. |
| Every constructor of `ObjectSecurity`, `ObjectAccessRule`, `ObjectAuditRule`, `AccessRule`, `AuthorizationRule`, `CommonSecurityDescriptor`, `RawSecurityDescriptor`, `RawAcl`, `GenericAce`, `CommonAce`, `ObjectAce` throws PNSE on Linux | IL for each ctor in `System.Security.AccessControl.dll` (linux-x64); 249 of 374 method bodies are tiny `throw` stubs | Any subclass of these, including the ten classes, fails in its base constructor. Composition inside the subclass cannot help, because the base ctor runs first. |
| `DirectoryObjectSecurity` is defined in `System.IO.FileSystem.AccessControl.dll` (forwarded from `mscorlib`) and derives from `ObjectSecurity` | Ref pack type definitions | It inherits the same PNSE base. |

The current code already reflects this:
[`DirectoryEntry.EnsureAccessControlSupported`](../../src/AdForLinux.DirectoryServices/DirectoryEntry.cs)
throws PNSE for `ObjectSecurity` off Windows.

**Conclusion:** the ten classes cannot run on Linux while they keep their current base types
and `IdentityReference` parameters. Any Linux-executable form needs either new public types
(the parallel API) or different base types and signatures (a breaking change).

### 3.1 Assessment of existing assets

| Asset | What to reuse | Limitations to fix in the core |
|---|---|---|
| [`SidCodec`](../../src/AdForLinux.DirectoryServices.AccountManagement/SidCodec.cs) | Correct endianness (big-endian 48-bit authority, little-endian sub-authorities), the 15 sub-authority limit, strict numeric parsing (`SidCodecTests`) | It lives in **AccountManagement**, the wrong layer. DirectoryServices cannot see it, so it moves down. `Format` always prints the authority in decimal. Windows prints `0x…` hex for authorities ≥ 2³²; the oracle must confirm this, and the codec must match. `Format` ignores trailing bytes and reports no consumed length, which an ACE parser needs. It uses `byte[]` only and has no value type, equality or ordering. |
| [`ChangePasswordAcl`](../../src/AdForLinux.DirectoryServices.AccountManagement/ChangePasswordAcl.cs) | The **splice-and-relocate** technique: rewrite only the DACL, copy everything else verbatim, and shift only the owner/group/SACL offsets that follow the DACL. Bounds checks on ACL/ACE sizes. Explicit-ACE-only matching. Its tests are a ready golden corpus. | DACL only. Does not validate the descriptor revision, the `SE_SELF_RELATIVE` flag, ACL revision or SID bounds inside ACEs. `checked((int)offset)` throws `OverflowException`, which is not a domain exception. `IsTarget` slices from the SID offset to the end of the ACE, so trailing ACE padding defeats matching. Does not check whether components overlap. Its canonical insertion heuristic is specific to one right. |
| `DirectoryEntry` transport (`ReadSecurityDescriptorImmediate`, `ReplaceSecurityDescriptorImmediate`, `AddObjectSecurity`, `ReadObjectSecurity`) | Base-scope read with `SecurityDescriptorFlagControl`. Writes are scoped by `RetrievedMasks`, not by the current `Options.SecurityMasks`. Commit discards the cache and reloads. A failed commit keeps dirty state (`ObjectSecurityComparisonTests`). | Writes **every retrieved section** on any change, not just the modified ones. `new ActiveDirectorySecurity()` reports `RetrievedMasks = Owner\|Group\|Dacl\|Sacl`, so assigning a fresh descriptor sends an SD-flags control that includes SACL. That needs `SeSecurityPrivilege` and may replace the SACL. The Microsoft behavior is unverified (open question O-4). There is no concurrency protection. There is no request-capture seam for offline tests: every request goes straight to `SendRequestCompatible`. |

---

## 4. Representation and binary codec (core layer)

The core lives in the `AdForLinux.DirectoryServices` assembly under the internal namespace
`AdForLinux.DirectoryServices.Security.Core`. AccountManagement already sees it through the
existing `InternalsVisibleTo`. `SidCodec` moves here, and AccountManagement uses it through
the same IVT.

All core values are **immutable**. Edits produce new values. This is the basis for
"no partial mutation" (§7).

### 4.1 SID — `Sid`

- Fields: revision (must be 1), a 48-bit identifier authority and 0–15 sub-authorities (`uint`).
- Binary codec: `TryRead(ReadOnlySpan<byte>, out Sid, out int consumed)` and `WriteTo(Span<byte>)`.
  It never reads past `8 + 4·count`.
- String form: `S-1-<auth>-<sub>…`. Hex authority at or above 2³², and decimal below it
  (to be confirmed by the oracle). Parsing is strict, with no silent normalization (as in
  `SidCodecTests`).
- Equality and hashing are ordinal on the canonical bytes. There is no well-known-SID
  translation in the core, apart from a static table of constants (`Everyone`, `Self`, …)
  used by callers.

### 4.2 ACE — `Ace`

Every ACE keeps its **raw header**: `AceType` (byte), `AceFlags` (byte, all 8 bits preserved)
and `AceSize` (ushort). Parsed kinds:

| Kind | ACE types | Parsed fields |
|---|---|---|
| `AccessAce` | 0x00 allowed, 0x01 denied | mask, SID |
| `AuditAce` | 0x02 system-audit | mask, SID (success/failure come from the flags) |
| `ObjectAccessAce` | 0x05 allowed-object, 0x06 denied-object | mask, object flags (raw `uint`), optional `ObjectType`, optional `InheritedObjectType`, SID |
| `ObjectAuditAce` | 0x07 system-audit-object | as above |
| `OpaqueAce` | everything else (0x03 alarm, 0x04 compound, 0x08 alarm-object, 0x09–0x10 callback, 0x11 mandatory-label, 0x12 resource-attribute, 0x13 scoped-policy, 0x14 process-trust, unknown types) | raw bytes only |

Rules:

- **Trailing bytes**: if `AceSize` is larger than the parsed content, the extra bytes are kept
  as `Trailing` and written back. An ACE with trailing bytes is still matchable, but merging
  or splitting it keeps the trailing bytes on the surviving ACE (see O-6).
- **Object flags**: bits other than `ACE_OBJECT_TYPE_PRESENT` (0x1) and
  `ACE_INHERITED_OBJECT_TYPE_PRESENT` (0x2) make the ACE **opaque**, because the layout
  cannot be trusted.
- GUIDs use the Windows mixed-endian layout, which `new Guid(ReadOnlySpan<byte>)` produces.
- An ACE whose embedded SID fails to parse becomes opaque. It is never rejected outright,
  so unknown but well-framed data survives.

### 4.3 ACL — `Acl`

- Fields: `Revision` (raw byte; 2 = `ACL_REVISION`, 4 = `ACL_REVISION_DS`), `Sbz1` and `Sbz2`
  (raw, preserved), an ordered list of `Ace`, and `Trailing` (bytes inside `AclSize` after
  the last ACE).
- Original order is kept exactly. The parser never reorders.
- On write, the revision becomes 4 if any object ACE is present. Otherwise the original
  revision is kept (lossless) or 2 is used (new ACLs).

### 4.4 Security descriptor — `SecurityDescriptor`

- Header: `Revision` (must be 1), `Sbz1` (raw; the resource-manager control byte when
  `SE_RM_CONTROL_VALID`), and `Control` (raw `ushort`, **all bits kept**, including unknown ones).
- Owner and Group: `Sid?`.
- DACL and SACL are each an `AclSlot` with **five distinct states**:

| State | Binary meaning | Semantics |
|---|---|---|
| `NotRetrieved` | Not in the server response because the read's SD-flags mask excluded it | Unknown. **Must not be written.** Tracked from the read mask, because the bytes look the same as `Absent`. |
| `Absent` | `SE_*_PRESENT` clear | No ACL. For a DACL, the defaulting rules apply. |
| `Null` | `SE_*_PRESENT` set, offset 0 | **Null DACL = full access for everyone.** Never created implicitly. |
| `Empty` | Present, ACL with 0 ACEs | Empty DACL = no access (apart from implicit owner rights). |
| `Populated` | Present, ACL with ≥1 ACE | Normal. |

- **Section tracking**: `RetrievedSections` and `ModifiedSections` (flags: Owner, Group, Dacl,
  Sacl). Their values match `SecurityMasks`, so they convert with a cast.
- **Original layout**: the parsed descriptor keeps the original bytes and each component's
  `(offset, length)`.

### 4.5 Round-trip contract

| Mode | Guarantee |
|---|---|
| **Lossless** (default) | For every accepted input `b`: `Serialize(Parse(b)) == b`, byte for byte, including gaps, component order, unknown control bits, opaque ACEs, trailing bytes and non-canonical order. |
| **Splice** (after an edit) | Only modified components are re-encoded. Unmodified components and inter-component gaps are copied verbatim. Offsets after a resized component are shifted by its size delta (the `ChangePasswordAcl` technique, generalized to all four components). |
| **Normalized** (explicit call only) | `ToNormalizedBinary()` drops gaps and trailing bytes, uses a fixed component order and recomputes sizes and revisions. It never runs implicitly. Changing the stored bytes is an explicit caller decision. |

The component order for brand-new descriptors (and for normalized output) is taken from the
Windows oracle: whatever `CommonSecurityDescriptor.GetBinaryForm` produces. It is not
hard-coded from memory.

### 4.6 Directory semantics

The core models directory ACEs directly. Nothing here relies on an effective-permissions engine.

- **Rights mask**: stored as a raw `uint`. `ActiveDirectoryRights` is a typed view.
  `GENERIC_*` high bits (0x1000_0000–0x8000_0000) are kept as-is. There is no generic
  mapping (AD stores expanded masks, but the core doesn't rely on that).
- **ACE flags**: `OBJECT_INHERIT` 0x01, `CONTAINER_INHERIT` 0x02, `NO_PROPAGATE_INHERIT` 0x04,
  `INHERIT_ONLY` 0x08, `INHERITED` 0x10, `SUCCESSFUL_ACCESS` 0x40, `FAILED_ACCESS` 0x80.
  Bit 0x20 and anything unknown are kept as-is.
- **Explicit vs inherited**: `INHERITED` is set. Rule operations **never** change inherited
  ACEs (§5), with one exception: the `SetAccessRuleProtection(preserveInheritance: true)`
  conversion.
- **Inheritance mapping**: reuse the existing `ActiveDirectoryInheritance`
  (`None`/`All`/`Descendents`/`SelfAndChildren`/`Children` ↔ `ContainerInherit` plus
  propagation flags). On read, an ACE with `OBJECT_INHERIT` only, or with propagation bits
  that don't map, still parses. Its `InheritanceType` getter reproduces whatever Microsoft
  does for such ACEs (oracle; today's `FromFlags` throws `ArgumentException` for
  unmappable propagation).
- **Object-specific ACEs**: an object ACE type is used **if and only if** `ObjectType` or
  `InheritedObjectType` is non-empty, as `ObjectAccessRule` does. `Guid.Empty` means "absent"
  and sets the presence flag to 0.
- **Property / property-set / extended-right / child-class GUIDs**: all are `ObjectType`. Their
  meaning depends on the mask bits (`ReadProperty`/`WriteProperty` → attribute or property set;
  `ExtendedRight` → control access right; `CreateChild`/`DeleteChild` → class;
  `Self` → validated write). The core **does not** check that a GUID exists in the schema.
- **Audit**: `SUCCESSFUL_ACCESS`/`FAILED_ACCESS` ↔ `AuditFlags`. `AuditFlags.None` is
  rejected when the rule is created, with the same exception Microsoft throws.

**Mapping of the ten classes onto core ACE specs** (`spec` = identity SID, mask, kind,
object GUID, inherited-object GUID, inheritance/propagation flags, audit flags):

| Class | Mask | `ObjectType` meaning | ACE kind produced |
|---|---|---|---|
| `ActiveDirectoryAccessRule` | any `ActiveDirectoryRights` | caller-supplied | `AccessAce`, or `ObjectAccessAce` if either GUID is set |
| `ActiveDirectoryAuditRule` | any | caller-supplied | `AuditAce`, or `ObjectAuditAce` if either GUID is set |
| `ListChildrenAccessRule` | `ListChildren` | — (always empty) | Access, or object access only if an inherited-object GUID is set |
| `CreateChildAccessRule` | `CreateChild` | child class `schemaIDGUID` | Access / object access |
| `DeleteChildAccessRule` | `DeleteChild` | child class `schemaIDGUID` | Access / object access |
| `DeleteTreeAccessRule` | `DeleteTree` | — | Access, or object access only if an inherited-object GUID is set |
| `ExtendedRightAccessRule` | `ExtendedRight` | `rightsGuid` | Access / object access |
| `PropertyAccessRule` | `ReadProperty` or `WriteProperty` | attribute `schemaIDGUID` | Access / object access |
| `PropertySetAccessRule` | `ReadProperty` or `WriteProperty` | property-set `rightsGuid` (required) | Object access |

Reading returns `ActiveDirectoryAccessRule`/`ActiveDirectoryAuditRule`, never the specialized
subclasses. That matches `AccessRuleFactory`/`AuditRuleFactory` today. The subclasses are
construction conveniences only, and the portable API keeps that property (§6.2).

### 4.7 SDDL (later component)

`GetSecurityDescriptorSddlForm`/`SetSecurityDescriptorSddlForm` are inherited public members
and part of parity. SDDL is a **separate codec over the core**, with its own oracle
(`ConvertSecurityDescriptorToStringSecurityDescriptor` output through
`RawSecurityDescriptor.GetSddlForm`). Domain-relative aliases (`DA`, `EA`, …) need a domain SID
from the identity layer, so SDDL parsing with aliases lives above the core. It is P2 work.

---

## 5. Mutation semantics

**Principle: Microsoft's `CommonSecurityDescriptor` behavior is the oracle.** On Windows the
existing classes *are* that behavior, so the core is held to it by differential tests. The
core does not invent its own semantics. Where the oracle's behavior is not yet captured, this
section states the intended rule and marks it as an oracle item.

### 5.1 Operations (DACL; the SACL mirrors them with audit rules)

| Operation | Scope | Effect |
|---|---|---|
| `Add(rule)` | explicit ACEs | Merge into an existing **compatible** explicit ACE (§5.2) by OR-ing the mask. Otherwise insert at the canonical position. |
| `Set(rule)` | explicit ACEs for (SID, allow/deny) | Remove every explicit ACE for that SID with the same `AccessControlType`, then `Add`. Whether object GUIDs narrow the removal is an oracle item. |
| `Reset(rule)` | explicit ACEs for SID | Remove all explicit allow and deny ACEs for the SID, then `Add`. |
| `Remove(rule)` | explicit ACEs | Subtract the mask bits from compatible ACEs. This may **split** an ACE whose inheritance makes it apply to both the object and its children (§5.3). ACEs that end with a zero mask are dropped. Returns `bool`, as Microsoft does. |
| `RemoveSpecific(rule)` | explicit ACEs | Remove only ACEs that **exactly** match (mask, flags, GUIDs). No splitting. |
| `RemoveAccess(identity, type)` / `RemoveAudit(identity)` | explicit | Remove all explicit ACEs for SID (and type). |
| `Purge(identity)` | explicit | Remove all explicit ACEs for SID, of either type. |
| `ModifyAccessRule(modification, rule, out modified)` | as mapped | Dispatch to the operations above. |
| `SetAccessRuleProtection(isProtected, preserveInheritance)` | control + inherited | Set or clear `SE_DACL_PROTECTED`. When protecting: if `preserveInheritance`, convert inherited ACEs to explicit (clear `INHERITED`); otherwise remove them. |
| Owner / Group set | header | Replace the SID and mark the section modified. |

### 5.2 Matching and merging rules

Two ACEs are **compatible for merging** only if all of these hold:

- the same parsed kind and the same allow/deny/audit type;
- the same SID, byte for byte;
- the same inheritance and propagation flags;
- the same object-presence flags and the same GUIDs;
- for audit ACEs, the same success/failure flags;
- both are explicit;
- neither is opaque.

Merging **never** crosses allow/deny. It never merges an object-specific ACE into a
non-object ACE: that would widen a GUID-scoped right to all properties or rights. It never
merges ACEs with different inheritance scope.

Opaque ACEs are never matched, merged, split or removed by rule operations. That includes
callback ACEs whose SID could be parsed. `Purge` and `RemoveAccess` leave them untouched.

### 5.3 Splitting

`Remove` on an ACE that applies to both the object and its children
(`CONTAINER_INHERIT`, not `INHERIT_ONLY`), with a rule that has a different inheritance
scope, splits it into at most two ACEs (object-only and inherit-only) so each scope keeps
exactly its remaining bits. The exact split order and placement is an **oracle item**,
captured from `CommonAcl` with seeded scripts (§9.3).

### 5.4 Canonicalization policy

- **Parse never reorders.** A non-canonical ACL from the server stays exactly as it is.
- Canonical order (oracle-confirmed): explicit deny, then explicit allow, then inherited ACEs
  in their original relative order. Opaque ACEs keep their position relative to their
  neighbors.
- **Mutating a non-canonical DACL or SACL** follows Microsoft. `CommonAcl` reports
  `AreAccessRulesCanonical == false` and its modifying methods throw `InvalidOperationException`.
  The core does the same: it refuses, with no partial change.
- Reordering is allowed **only** through an explicit `Canonicalize()` call that marks the
  section modified. It is never a side effect of another operation.
- Unrelated ACEs keep their relative order across every operation. New ACEs are inserted at
  the canonical boundary; they are not appended.

### 5.5 Null and empty ACL transitions

- Operations never turn `Empty` into `Null`. Removing the last ACE gives `Empty` (deny all),
  not `Null` (allow all).
- Adding to a `Null` DACL: Microsoft is believed to materialize a single
  "Everyone: full control" ACE first, so the result *keeps* the original null-DACL breadth,
  and to write it back as null if it is unchanged. This is **oracle item O-3**, and the core
  will copy whatever is observed. Either way, the core never **creates** a null DACL from
  `Absent`, `Empty` or `Populated`.
- An `Absent` SACL becomes `Present` on the first `AddAuditRule`, and only if the SACL was
  retrieved.

### 5.6 Dirty tracking

- Each section has its own modified flag. Header control bits belong to their section
  (DACL protection/auto-inherit bits → Dacl; SACL ones → Sacl).
- An operation that leaves a section's bytes unchanged does **not** set modified in the core.
  The Windows adapter's `IsModified()` keeps Microsoft's own flag semantics, and the write
  path (§6.1) uses the core's byte comparison to decide what goes on the wire.

### 5.7 Validation failures

All of these are checked **before** any state changes, with the exception types the oracle
shows:

- a null rule or identity;
- an identity that cannot be expressed as a SID (Windows: translation failure; portable: an
  unresolved name);
- a zero mask;
- an invalid inheritance or `PropertyAccess` enum value (`InvalidEnumArgumentException` with the
  parameter name, as `SecurityRuleValidationComparisonTests` covers);
- `AuditFlags.None`;
- a section that was not retrieved (`InvalidOperationException`, as in `RequireDacl`/`RequireSacl`);
- a non-canonical target ACL;
- a resulting ACL larger than 65 535 bytes or holding more than 65 535 ACEs.

---

## 6. Boundaries and data flow

```
 ┌──────────────────────────── public surface ────────────────────────────┐
 │  Windows only (unchanged):                Portable (new, P2):          │
 │  ActiveDirectorySecurity + 9 rule classes  DirectorySecurityDescriptor │
 │  DirectoryEntry.ObjectSecurity             DirectoryAccessRule/Audit…  │
 │        │  (BCL-derived; binary adapter)    DirectoryEntry.Get/Set…     │
 └────────┼───────────────────────────────────────────┼───────────────────┘
          ▼                                           ▼
 ┌──────────────────── DirectoryEntry security slot (internal) ───────────┐
 │  SecurityDescriptorState: core descriptor + RetrievedSections +        │
 │  original bytes; one active view; commit/refresh/invalidate rules      │
 └────────┬─────────────────────────────────────────────┬─────────────────┘
          │ LDAP I/O (SD-flags control, Replace)        │ identity lookup
          ▼                                             ▼
 ┌──────── transport ────────┐            ┌──────── identity layer ────────┐
 │ Read/ReplaceSecurity-     │            │ ISidResolver: LDAP objectSid,  │
 │ DescriptorImmediate,      │            │ well-known table, FSPs.        │
 │ request-capture seam      │            │ Windows adapter: Translate()   │
 └───────────────────────────┘            └────────────────────────────────┘
          ▲                                             ▲
          └──────────── pure core (no I/O, no BCL ACL types) ──────────────┘
                 Sid · Ace · Acl · SecurityDescriptor · RuleSpec · ops
```

**Dependency rules:** the core references nothing above it. The transport and identity
layers reference the core. Public types reference the slot and identity layers. Only the
Windows adapter references `System.Security.AccessControl`/`Principal`, and it carries
`[SupportedOSPlatform("windows")]`.

### 6.1 Read → edit → write

1. **Read**: the `ObjectSecurity` getter (Windows) or `GetDirectorySecurity()` (portable)
   reads with the mask `EffectiveSecurityMasks()`, as today. The slot records
   `RetrievedSections = mask` and the original bytes, and parses them with the core.
   A parse failure surfaces at this point, before any edit.
2. **Edit**: the Windows view is a real `ActiveDirectorySecurity` built from the same bytes,
   as today. The portable view wraps the core descriptor. **Only one view may be dirty at a
   time.** Asking for the other view while one has pending edits throws
   `InvalidOperationException`, so two divergent edits never race to commit.
3. **Commit** (`CommitChanges`, or immediately when `UsePropertyCache == false`, as today):
   1. Get the edited bytes: Windows view → `GetSecurityDescriptorBinaryForm()`, then
      re-parse with the core. Portable view → the core descriptor.
   2. **Compute `WriteSections = Modified ∩ Retrieved`**, where Modified comes from a
      per-section byte comparison against the original. If it is empty, nothing is sent.
   3. **Splice** the modified sections into the *original* bytes (§4.5). Sections outside
      `WriteSections` keep their original bytes, even if a view rewrote them. Example: BCL
      re-serialization may reorder or normalize the owner; that change is not sent.
   4. Send `Replace nTSecurityDescriptor` with `SecurityDescriptorFlagControl(WriteSections)`
      in the same `ModifyRequest` as the pending property changes (or in the `AddRequest`
      for a new entry), as today.
   5. On success: discard the slot (Microsoft parity, already covered by tests). The next
      access reloads, so server-computed inherited ACEs and server reordering become visible.
   6. On failure: the slot, the view and the dirty flags stay **exactly** as they were
      before the commit. Serialization happens before the send, so a serialization error
      sends nothing.
4. `RefreshCache` (all properties, or a list containing `nTSecurityDescriptor`) and moves or
   renames discard the slot, as today.

**Deliberate change from today:** the write mask narrows from `RetrievedMasks` to
`Modified ∩ Retrieved`. This is safer (a DACL edit never touches owner, group or SACL). It
must still be checked against Microsoft's wire behavior (O-4) before it ships. If Microsoft
sends the full retrieved mask, the project must choose between safety and wire parity. The
difference only shows when the server would reject or alter an owner/group section the
caller did not change.

**Server behavior the core must not fight:** on a DACL/SACL write, AD recomputes inherited
ACEs from the parent and ignores inherited ACEs the client supplies. The core does not
propagate inheritance. The reload after commit is the only source of truth.

### 6.2 Portable public API sketch (P2)

Namespace `AdForLinux.DirectoryServices.AccessControl`. The names are deliberately distinct,
so importing both namespaces never makes a name ambiguous.

```csharp
public readonly struct DirectorySid : IEquatable<DirectorySid>     // S-1-…; binary/string codec
public sealed class DirectorySecurityDescriptor                     // mirrors ActiveDirectorySecurity ops
{
    public DirectorySecurityDescriptor();                           // new, empty, all sections "owned"
    public static DirectorySecurityDescriptor FromBinary(ReadOnlySpan<byte> sd, SecurityMasks retrieved);
    public DirectorySid? Owner { get; set; }  public DirectorySid? Group { get; set; }
    public void AddAccessRule(DirectoryAccessRule rule);  /* Set/Reset/Remove/RemoveSpecific/RemoveAccess/Purge */
    public void AddAuditRule(DirectoryAuditRule rule);    /* Set/Remove/RemoveSpecific/RemoveAudit/Purge */
    public IReadOnlyList<DirectoryAccessRule> GetAccessRules(bool includeExplicit, bool includeInherited);
    public IReadOnlyList<DirectoryAuditRule>  GetAuditRules(bool includeExplicit, bool includeInherited);
    public bool AreAccessRulesProtected { get; }  public bool AreAccessRulesCanonical { get; }
    public void SetAccessRuleProtection(bool isProtected, bool preserveInheritance);  // + audit
    public SecurityMasks RetrievedSections { get; }  public SecurityMasks ModifiedSections { get; }
    public byte[] GetBinaryForm();                                  // lossless/splice
    public byte[] GetNormalizedBinaryForm();                        // explicit normalization
}
public class DirectoryAccessRule  /* same 6 ctor shapes as ActiveDirectoryAccessRule, DirectorySid identity */
public class DirectoryAuditRule   /* same 6 ctor shapes as ActiveDirectoryAuditRule */
public static class DirectoryAccessRules                            // one factory group per specialized class
{   ListChildren(…) CreateChild(…) DeleteChild(…) DeleteTree(…) ExtendedRight(…) Property(…) PropertySet(…) }
// DirectoryEntry
public DirectorySecurityDescriptor GetDirectorySecurity();
public void SetDirectorySecurity(DirectorySecurityDescriptor descriptor);   // same cache/commit rules as ObjectSecurity
// Windows-only bridges
[SupportedOSPlatform("windows")] public static DirectorySid FromSecurityIdentifier(SecurityIdentifier sid);
[SupportedOSPlatform("windows")] public ActiveDirectorySecurity ToActiveDirectorySecurity();  // via bytes
```

Each factory overload matches one existing specialized constructor overload (same parameter
order, `DirectorySid` instead of `IdentityReference`), so migrating is mechanical. Name
resolution is a separate, explicit step:
`DirectoryEntry`-scoped `ResolveSid(string samOrUpn)` through the identity layer. It is never
implicit inside a rule constructor, because Linux has no LSA to fall back on.

---

## 7. Compatibility decision

| Option | Linux executes the ten classes? | Source compat | Binary compat | Reflection / public-surface parity | Packaging | Cost and risk |
|---|---|---|---|---|---|---|
| **A. Status quo + internal core only** | No | Unchanged | Unchanged | Unchanged | Unchanged | Low. Removes no blocker for callers, but fixes internal safety (`ChangePasswordAcl`, write masks). |
| **B. Portable core + Windows adapter + parallel portable API** (recommended, P1+P2) | **No** (the ten stay Windows-only); Linux uses the parallel API | Existing code unchanged; Linux code uses new types | Unchanged for existing types; additive | The ten classes keep exact parity (`LowLevelPublicSurfaceComparisonTests` stay green). New types are outside the Microsoft comparison set. | One assembly, one API across TFMs | Medium. Two public models to keep consistent, mitigated by both serializing through the same core and by cross-checking against the BCL on Windows. |
| **C. Breaking re-root, one API** (ten classes derive from clone bases; `IdentityReference` → clone identity type everywhere) | Yes | **Breaks** every caller that passes `SecurityIdentifier`/`NTAccount`, casts to `DirectoryObjectSecurity`/`ObjectSecurity`, or uses inherited BCL members polymorphically | Breaks | `BaseType` chain and inherited members diverge from Microsoft; parity tests must be rewritten as "documented deviation" | One API | High. Gives up the drop-in goal on Windows too, for no Windows benefit. |
| **D. Per-TFM split** (`net*-windows` keeps BCL bases; plain `net*` re-roots on clone bases with clone identity types) | Yes, in the Linux TFM | Source compatible only if callers avoid BCL identity types. Most real code uses `NTAccount`/`SecurityIdentifier`, so it needs `#if` | **Different public API per TFM**; a library built against one breaks at runtime against the other | Diverges in the portable TFM | Multi-TFM packaging, two reference surfaces, the `-windows` TFM required for parity | Very high. Composition alone still can't make the BCL hierarchy run. It only replaces it. |

**Recommendation: B**, with D as a later, explicit decision. Reasons:

- The verified constraints (§3) leave only two ways to make the ten classes run on Linux:
  replace their public bases and identity type (C/D), or provide equivalent new types (B).
- B keeps the project's existing guarantee: the ten classes match Microsoft exactly on
  Windows. It delivers Linux functionality without a split API.
- B is the necessary first step for C or D anyway. The core, transport, safety rules and
  oracle corpus are all reused unchanged. Choosing B now doesn't close off D later.
- The coverage report stays honest: the ten rows remain **not implemented on Linux**. The
  parallel API is recorded as the Linux path, not counted as promotion (see O-8).

Migration for consumers (B): Windows callers change nothing. Linux callers replace
`IdentityReference` with `DirectorySid` (after `ResolveSid` or a known SID string),
`ActiveDirectorySecurity` with `DirectorySecurityDescriptor`,
`entry.ObjectSecurity` with `entry.GetDirectorySecurity()`/`SetDirectorySecurity`, and
`new XxxAccessRule(...)` with `DirectoryAccessRules.Xxx(...)`.

---

## 8. Safety

### 8.1 Parser bounds (core)

All arithmetic is on `uint`/`long` with explicit range checks, never `checked((int)…)`. Every
failure throws **one** domain exception type (`ArgumentException` with `paramName`
`"binaryForm"`, the BCL convention for `RawSecurityDescriptor`; the oracle confirms the exact
type).

| Check | Rule |
|---|---|
| Header | `length ≥ 20`; `Revision == 1`; `SE_SELF_RELATIVE` set (absolute form rejected) |
| Offsets | each of the four offsets is `0` or `≥ 20`, and `offset + minimal component size ≤ length` |
| Present flags vs offsets | `SE_DACL_PRESENT` with offset 0 → `Null`; offset ≠ 0 without the present flag → preserved but treated as `Absent` (oracle-confirmed) |
| Overlap | components that overlap each other or the header are **rejected** (deterministic; deviations from the oracle are documented) |
| SID | sub-authority count ≤ 15; `8 + 4n ≤` remaining bytes of the component |
| ACL | `AclSize ≥ 8`; `offset + AclSize ≤ length`; **`AceCount × 4 ≤ AclSize − 8`, checked before allocating** (prevents allocation amplification) |
| ACE | `AceSize ≥ 4`; `cursor + AceSize ≤ ACL end`; parsed body ≤ `AceSize`; object-ACE GUID presence within bounds |
| Alignment | unaligned input is accepted on read (preserved); output is always DWORD-aligned (oracle item O-5 for the reject-vs-accept policy) |
| Size | no separate cap is needed: parsing is linear, and every count is bounded by the input length |

### 8.2 Deterministic failure without partial mutation

- Core values are immutable. An operation builds a new ACL, validates it completely, and only
  then replaces the reference in the descriptor.
- The DirectoryEntry slot only replaces its state after a successful parse or commit. Input
  arrays are never written in place (`ChangePasswordAclTests.Malformed_descriptors_fail_without_mutating_the_input`
  is the pattern).
- Only the declared exception types escape. Fuzz tests (§9.2) enforce this.

### 8.3 Safeguards

| Risk | Safeguard |
|---|---|
| Dropping unknown data | Opaque ACEs, unknown control/ACE/object flags, `Sbz` fields and trailing bytes are preserved. Test invariant: for every operation, *the opaque-ACE multiset and every unmodified section's bytes are unchanged*. |
| Replacing unread sections | A `NotRetrieved` slot cannot be edited (`InvalidOperationException`) and is never written: `WriteSections ⊆ Retrieved`. A brand-new descriptor (public ctor) owns all sections but only writes the ones it modified. This closes the `new ActiveDirectorySecurity()` → SACL-mask risk in §3.1, subject to O-4. |
| Broadening permissions | No implicit `Null` DACL. No allow/deny or object/non-object merge. Splitting keeps each inheritance scope's exact bits. No generic-bit expansion. `Remove` only clears the bits it was asked to. Protection changes only happen through `SetAccessRuleProtection`. |
| Silent reordering | Parse never reorders. Mutating non-canonical ACLs is refused. `Canonicalize()` is explicit. |
| Lost updates (concurrent edits) | **Default: section-scoped last writer wins** (today's and Microsoft's behavior, but limited to modified sections). **Opt-in (portable API):** `CommitOptions.DetectConcurrentChange`. Before writing, re-read `WriteSections` and compare to the original bytes; on mismatch, throw a conflict exception and send nothing. A small TOCTOU window remains; this is documented, not hidden. A true compare-and-swap through a value-matched delete+add in one `ModifyRequest` is a research item (O-7), because AD returns SD-flag-filtered bytes that likely don't match the stored value. |

---

## 9. Test and oracle plan

The tests build on the existing suites and keep them green. Linux offline, Windows oracle and
live-directory evidence are recorded separately, and **Samba evidence is never counted as AD
parity**.

### 9.1 Existing suites (unchanged, extended)

| Suite | Role going forward |
|---|---|
| `ObjectSecurityComparisonTests` (Windows, live AD) | Must stay green. Extend `Dacl_change_round_trips_without_replacing_unrequested_security_sections` to cover owner-only, SACL-retrieved-but-unmodified, and the portable view. Add a `new ActiveDirectorySecurity()` assignment case to capture O-4. |
| `SecurityRuleValidationComparisonTests` (Windows) | Extend to all 10 classes × every ctor overload: invalid enums, `AuditFlags.None`, `Guid.Empty` handling, exception type and parameter name. Run the same cases on the portable factories (Linux) against the recorded expected values. |
| `LowLevelPublicSurfaceComparisonTests` | Must stay green: the ten classes' signatures don't change. Add a separate snapshot (approval) test for the new portable namespace. It is not compared with Microsoft. |
| `SidCodecTests` | Move with the codec. Add hex authority ≥ 2³², consumed-length and trailing-bytes cases. |
| `ChangePasswordAclTests` | Becomes a **byte-exact golden regression** for `ChangePasswordAcl` rewritten on the core. Every existing expected output must be reproduced exactly. |

### 9.2 Linux offline (FunctionalTests, runs on Linux and Windows, no directory)

- **Fixture corpus** `tests/AdForLinux.FunctionalTests/Fixtures/SecurityDescriptors/`: `.bin`
  files plus a JSON manifest (source, expected sections, expected ACE summary). Sources:
  (a) captured from Windows AD at each SD-flags mask, with SIDs re-mapped to a fixed test
  domain; (b) generated on Windows through `CommonSecurityDescriptor`; (c) handcrafted edge
  cases (gaps, reversed component order, unknown control bits, opaque/callback/label ACEs,
  trailing ACE and ACL bytes, null vs empty vs absent DACL, ACL revision 2 with object ACEs).
- **Lossless round-trip**: `Serialize(Parse(b)) == b` for every accepted fixture.
- **Malformed inputs**: a table-driven defect list (each §8.1 check, plus truncation at every
  byte boundary of a valid fixture). Asserts the declared exception type, input unchanged and
  no partial state.
- **Fuzz/property**: seeded mutations of the corpus. Invariant: success with a lossless
  round-trip, or the declared exception. Bounded runtime. The seeds are stored so failures
  can be reproduced.
- **Mutation and inheritance**: replay recorded oracle scripts (§9.3) from JSON on Linux and
  compare output bytes. The 5 inheritance values × object/inherited GUID presence × 10
  classes × allow/deny/audit.
- **Partial-section safety (transport)**: add an internal request-capture seam to
  `DirectoryEntry` (an `ILdapRequestSink` wrapping `SendRequestCompatible`). Assert the
  SD-flags mask and the spliced bytes for each `WriteSections` case, the failed-commit state,
  and the one-dirty-view rule.

### 9.3 Windows oracle (DifferentialTests, `net8.0-windows` + `net10.0-windows`, Microsoft `System.DirectoryServices` 9.0.0)

- **Offline, no AD needed**: build Microsoft's `ActiveDirectorySecurity` from fixture bytes
  (`SetSecurityDescriptorBinaryForm`). Run seeded random operation scripts (add / set / reset /
  remove / remove-specific / purge / protect, across all 10 rule classes) on both Microsoft
  and the core, then compare `GetSecurityDescriptorBinaryForm()` bytes, rule enumerations
  and exceptions. Record each script and its Microsoft output as JSON. Those recordings are
  the Linux replay fixtures in §9.2.
- These scripts settle the oracle items in §5 (split order, `Set` scope, null-DACL behavior,
  canonical order, exception types). Results are committed as fixtures, not re-derived
  from memory.
- **Live AD (existing fixture)**: the wire-level SD-flags mask for each edit kind (O-4), and
  the server's reordering and inheritance recomputation after commit.

### 9.4 Later: Linux → real Windows AD (integration)

- The same scenario set as §9.3 live, run from Linux through the portable API against a real
  DC. Compare post-commit bytes with a Windows-side Microsoft run on the same object.
- Concurrency: two writers on different and on the same sections, with the opt-in
  conflict detection.
- **Samba**: a separate trait (`Category=Samba`), with results recorded in a separate
  section. Samba's SD defaults, storage order and inheritance handling differ, so a Samba
  pass never counts toward AD parity or coverage promotion.

---

## 10. Phased plan (follow-up issues)

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **P1a** | Core codec: `Sid` (move `SidCodec`), `Ace`, `Acl`, `SecurityDescriptor`, lossless/splice serialization | §9.2 corpus round-trip + malformed + fuzz green on Linux; `SidCodecTests` green |
| **P1b** | Windows oracle harness + recorded scripts; core mutation semantics | §9.3 offline differential green on net8/net10-windows; recordings replay on Linux |
| **P1c** | `DirectoryEntry` security slot, request-capture seam, `Modified ∩ Retrieved` writes (after O-4) | `ObjectSecurityComparisonTests` green; new transport tests green |
| **P1d** | `ChangePasswordAcl` rewritten on the core | `ChangePasswordAclTests` byte-identical |
| **P2** | Portable public API + identity layer (`ResolveSid`) + SDDL codec | Surface snapshot; §9.2/9.3 for portable paths; README "Linux ACL" section |
| **P3** | Decision on option D | Recorded maintainer decision based on user demand and P2 adoption |

---

## 11. Unresolved decisions and oracle items

| ID | Question | How it gets resolved |
|---|---|---|
| O-1 | Exact canonical order, including object vs non-object explicit ACEs | §9.3 recordings |
| O-2 | `SetAccessRule` scope: does it remove explicit ACEs with *different* object GUIDs for the same SID and type? | §9.3 recordings |
| O-3 | Null-DACL behavior on add (Everyone-full-control materialization, and write-back as null?) | §9.3 recordings |
| O-4 | Microsoft's wire SD-flags mask on commit: `Options.SecurityMasks`, retrieved, or modified? And for a freshly constructed `ActiveDirectorySecurity`? | Live §9.3; decides whether `Modified ∩ Retrieved` is parity or a documented safety deviation |
| O-5 | Parse policy for unaligned components or ACE sizes that aren't a multiple of 4 (accept-and-preserve vs reject) | `RawSecurityDescriptor` behavior on handcrafted fixtures |
| O-6 | Merging or splitting an ACE that has trailing bytes: keep them, drop them, or refuse? | Oracle + maintainer call (default: refuse, and treat as opaque for edits) |
| O-7 | Is a value-matched compare-and-swap on `nTSecurityDescriptor` viable against AD? | Research spike against live AD |
| O-8 | Coverage reporting: should the ten rows note "Linux path: portable API" while staying `not implemented`? | Maintainer decision when P2 lands |
| O-9 | Namespace and type names for the portable API (§6.2) | Review of this document |
| O-10 | `InheritanceType` getter on an ACE with unmappable flags (throw, as `FromFlags` does today, or a Microsoft-specific value) | §9.3 recordings |
