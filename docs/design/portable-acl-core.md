# Design: a portable ACL core for the ten Linux-blocked security classes

Status: **research/design; original BCL contract blocked; same-name portable dependencies under authorized investigation** · Issue: #224 · Baseline: `dev` @ `e72a421a` · Related: #5, #90 (closed)

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

The goal remains a portable **internal** ACL core supporting the ten **existing** public
classes and their callers. A parallel public API was rejected by the user. It is not the
recommendation, a prerequisite, or an approved fallback. The user has since authorized
investigation of keeping the ten names/method patterns with portable base and identity types.
[The concrete candidate and evidence](same-name-portable-acl-api.md) record that research;
no production implementation or final public-contract adoption is chosen.

**Original-contract blocker:** on stock Linux .NET 8 and 10, the actual BCL base constructors
and SID constructors throw before our implementation can run. `IdentityReference` cannot
be subclassed by this library. Preserving those actual type identities **and** making these
classes execute on those platforms cannot both be delivered by an internal core (§3, §7).
This is narrower than saying that managed ACL processing is impossible: the byte model and
algorithms can be portable; the public BCL boundary cannot currently be made portable.

Continue design of reusable internal foundations, raw preservation, section-aware transport,
and oracle fixtures alongside the authorized same-name candidate. Gate production integration
and rollout on explicit adoption of the reviewed compatibility changes. Do not mark the ten
Linux coverage rows fixed by core work alone.

This revision corrects three earlier contradictions: raw versus projected dirty tracking
(§6.1), LDAP Add versus Modify (§6.2), and lossless bytes versus normalization/merging (§4–5).
Executed evidence and reproduction instructions are in
[the contract probe](../research/acl-contract-probe/README.md). No live directory or workflow
was run. The proposal is reviewable, but not an approved implementation plan.

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

The [reproducible probe](../research/acl-contract-probe/README.md) builds against the actual
repository project, without changing production sources. It was executed on Linux x64 with
Microsoft.NETCore.App **8.0.0 and 10.0.0**, using SDK **10.0.100** for both target frameworks.
These pinned versions establish the mechanism; this is not a test of every servicing release.
The project's Microsoft DirectoryServices **9.0.0** comparison package is a separate oracle
version, not a .NET 9 runtime requirement or evidence of Windows behavior on this host.

| Resolved fact | Executed/source evidence | Consequence |
|---|---|---|
| `new ActiveDirectorySecurity()` fails on both runtimes | PNSE at `ObjectSecurity..ctor()` | Composition in its constructor cannot avoid the base call. Removing the `DirectoryEntry` guard cannot fix it. |
| Representative constructors from all nine existing rule classes fail | Null-identity probes reach PNSE at `AuthorizationRule..ctor(...)`; null is intentionally used to isolate the base failure | Not successful rule construction or validation parity; confirms a separate obstacle from SID creation. |
| BCL SID string/binary construction and `NTAccount` construction fail | PNSE at `IdentityReference..ctor()` | Caller-created BCL identities already fail before an ACL method is reached. SID parsing inside our core cannot repair that caller expression. |
| `IdentityReference` has an assembly-internal constructor; `SecurityIdentifier` is sealed | Reflection, negative compile probe (CS1729), official source | No ordinary third-party portable subclass/identity adapter can satisfy the same signature. |
| Non-Windows ACL and principal assemblies are deliberately unsupported | Official .NET 8/10 project files generate PNSE assemblies; probe records actual assembly-qualified identities and constructor IL | Windows implementation source containing managed algorithms does not prove Linux package support. Some generated constructors call a base stub before their own throw; not every IL body is just a two-instruction throw. |
| `DirectoryObjectSecurity` resolves to `System.IO.FileSystem.AccessControl`, with `ObjectSecurity` in `System.Security.AccessControl` | Actual reflected assembly-qualified names | Both assemblies participate in the constructor chain. |

The production file's comment that descriptors are in-memory and its CA1416 suppression do
not change runtime behavior. `DirectoryEntry.EnsureAccessControlSupported` is an additional
explicit guard, not the fundamental blocker.

Official source links, exact errors and test limits are recorded with the probe. No patched
system assemblies, uninitialized object allocation, private reflection invocation, custom
runtime or unsafe constructor bypass is proposed as a supported solution.

### 3.1 Assessment of existing assets

| Asset | What to reuse | Limitations to fix in the core |
|---|---|---|
| [`SidCodec`](../../src/AdForLinux.DirectoryServices.AccountManagement/SidCodec.cs) | Correct endianness (big-endian 48-bit authority, little-endian sub-authorities), the 15 sub-authority limit, strict numeric parsing (`SidCodecTests`) | It lives in **AccountManagement**, above the intended core. A future internal move down avoids a circular project dependency; no move is made in this design PR. `Format` prints the authority in decimal, consistent with the inspected managed .NET 8/9/10 SID source. The previous hex-output claim was incorrect; native SDDL and managed Value need separate oracle cases (see the same-name candidate). `Format` ignores trailing bytes and reports no consumed length, which an ACE parser needs. It uses `byte[]` only and has no value type, equality or ordering. |
| [`ChangePasswordAcl`](../../src/AdForLinux.DirectoryServices.AccountManagement/ChangePasswordAcl.cs) | The **splice-and-relocate** technique: rewrite only the DACL, copy everything else verbatim, and shift only the owner/group/SACL offsets that follow the DACL. Bounds checks on ACL/ACE sizes. Explicit-ACE-only matching. Its tests are a ready golden corpus. | DACL only. Does not validate the descriptor revision, the `SE_SELF_RELATIVE` flag, ACL revision or SID bounds inside ACEs. `checked((int)offset)` throws `OverflowException`, which is not a domain exception. `IsTarget` slices from the SID offset to the end of the ACE, so trailing ACE padding defeats matching. Does not check whether components overlap. Its canonical insertion heuristic is specific to one right. |
| `DirectoryEntry` transport (`ReadSecurityDescriptorImmediate`, `ReplaceSecurityDescriptorImmediate`, `AddObjectSecurity`, `ReadObjectSecurity`) | Base-scope read with `SecurityDescriptorFlagControl`. Writes are scoped by `RetrievedMasks`, not by the current `Options.SecurityMasks`. Commit discards the cache and reloads. A failed commit keeps dirty state (`ObjectSecurityComparisonTests`). | Writes **every retrieved section** on any change, not just the modified ones. `new ActiveDirectorySecurity()` reports `RetrievedMasks = Owner\|Group\|Dacl\|Sacl`, so assigning a fresh descriptor sends an SD-flags control that includes SACL. That can require SACL privileges and may replace the SACL on Modify; Add ignores the control (§6.2). The Microsoft behavior is unverified (open question O-4). There is no concurrency protection. There is no request-capture seam for offline tests: every request goes straight to `SendRequestCompatible`. |

---

## 4. Representation and binary codec (core layer)

The proposed core would live in the `AdForLinux.DirectoryServices` assembly under the internal namespace
`AdForLinux.DirectoryServices.Security.Core`. AccountManagement already sees it through the
existing `InternalsVisibleTo`. `SidCodec` would move here, and AccountManagement would use it through
the same IVT.

All core values are **immutable**. Edits produce new values. This is the basis for
the internal core's "no partial mutation" guarantee (§8.2).

### 4.1 SID — `Sid`

- Fields: revision (must be 1), a 48-bit identifier authority and 0–15 sub-authorities (`uint`).
- Binary codec: `TryRead(ReadOnlySpan<byte>, out Sid, out int consumed)` and `WriteTo(Span<byte>)`.
  It never reads past `8 + 4·count`.
- String form: `S-1-<auth>-<sub>…`, with unsigned decimal authority/subauthorities for
  managed SID Value. Numeric parsing accepts hex authority as SidCodec already does; full
  BCL alias/validation compatibility remains to be measured. The prior forced-hex formatting
  proposal is withdrawn; see the [source correction](same-name-portable-acl-api.md#4-portable-identity-and-sid-behavior).
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
  as `Trailing` and written back in raw mode. Such ACEs are opaque for semantic edits:
  never merge, split, match or silently discard them. If an operation needs to interpret,
  reorder or rewrite them, refuse atomically (§5.2).
- **Object flags**: bits other than `ACE_OBJECT_TYPE_PRESENT` (0x1) and
  `ACE_INHERITED_OBJECT_TYPE_PRESENT` (0x2) make the ACE **opaque**, because the layout
  cannot be trusted.
- GUIDs use the Windows mixed-endian layout, which `new Guid(ReadOnlySpan<byte>)` produces.
- An invalid embedded SID is retained only as opaque, read-only data when the complete ACE
  is safely framed. Out-of-bounds sizes/offsets are rejected; opacity is not a bounds bypass.

### 4.3 ACL — `Acl`

- Fields: `Revision` (raw byte; 2 = `ACL_REVISION`, 4 = `ACL_REVISION_DS`), `Sbz1` and `Sbz2`
  (raw, preserved), an ordered list of `Ace`, and `Trailing` (bytes inside `AclSize` after
  the last ACE).
- Original order is kept exactly. The parser never reorders.
- Raw serialization never changes revision, including revision 2 containing object ACEs.
  New directory ACLs and normalized Microsoft output use the oracle-required revision
  (normally DS revision 4). Editing an incompatible original revision/layout is refused
  unless an explicit, reviewed normalization policy applies; no hidden revision upgrade.

### 4.4 Security descriptor — `SecurityDescriptor`

- Header: `Revision` (must be 1), `Sbz1` (raw; the resource-manager control byte when
  `SE_RM_CONTROL_VALID`), and `Control` (raw `ushort`, **all bits kept**, including unknown ones).
- Owner and Group: `Sid?`.
- DACL and SACL are each an `AclSlot` with **five distinct states**:

| State | Binary meaning | Semantics |
|---|---|---|
| `NotRetrieved` | Not in the server response because the read's SD-flags mask excluded it | Unknown. **Must not be written.** Tracked from the read mask, because the bytes look the same as `Absent`. |
| `Absent` | `SE_*_PRESENT` clear | No ACL present. Do not interpret as an empty deny-all DACL; creation defaulting is a separate server operation (§6.2). |
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
| **Splice** (after an edit) | Only intentionally modified components are re-encoded; header offsets and section-owned control bits change as needed. Unmodified components and gaps remain byte-identical. Untouched ACEs, opaque payloads and trailing data **within the changed ACL** must also survive. Refuse if that cannot be proven. Plan all relocations before copying; alias/overlap is rejected. |
| **Microsoft projection / normalized output** | Separate internal projection follows the pinned Windows oracle, including canonicalization, merging, revision and alignment changes. It is not lossless and is not a commit payload by default. Never silently drop opaque/trailing data to make a projection writable. No new public normalization method is approved. |

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
  ACEs (§5), except explicit protection changes that convert or remove inherited entries.
- **Inheritance mapping**: reuse the existing `ActiveDirectoryInheritance`
  (`None`/`All`/`Descendents`/`SelfAndChildren`/`Children` ↔ `ContainerInherit` plus
  propagation flags). On read, an ACE with `OBJECT_INHERIT` only, or with propagation bits
  that don't map, still parses. Its `InheritanceType` getter reproduces whatever Microsoft
  does for such ACEs (oracle; today's `FromFlags` throws `ArgumentException` for
  unmappable propagation).
- **Object-specific ACEs**: for new public rules, GUID presence and rights/inheritance
  eligibility follow the Microsoft rule/factory pipeline (oracle required). Raw parsing
  preserves an object ACE and its presence bits even if a present GUID is all-zero. Do not
  infer on-wire absence from `Guid.Empty` or convert raw object ACEs into common ACEs.
- **Property / property-set / extended-right / child-class GUIDs**: all are `ObjectType`. Their
  meaning depends on the mask bits (`ReadProperty`/`WriteProperty` → attribute or property set;
  `ExtendedRight` → control access right; `CreateChild`/`DeleteChild` → class;
  `Self` → validated write). The core **does not** check that a GUID exists in the schema.
- **Audit**: `SUCCESSFUL_ACCESS`/`FAILED_ACCESS` ↔ `AuditFlags`. `AuditFlags.None` is
  rejected when the rule is created, with the same exception Microsoft throws.

**Proposed mapping of the ten classes onto core ACE specs** (`spec` = identity SID, mask, kind,
object GUID, inherited-object GUID, inheritance/propagation flags, audit flags). New-rule
GUID/mask eligibility needs oracle validation; this table does not rewrite parsed raw ACEs:

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
| `PropertySetAccessRule` | `ReadProperty` or `WriteProperty` | property-set `rightsGuid` parameter | Access / object access; include `Guid.Empty` in oracle cases |

Reading returns `ActiveDirectoryAccessRule`/`ActiveDirectoryAuditRule`, never the specialized
subclasses. That matches `AccessRuleFactory`/`AuditRuleFactory` today. The subclasses are
construction conveniences only. The core uses internal rule specs, not replacement public classes.

### 4.7 SDDL (later component)

`GetSecurityDescriptorSddlForm`/`SetSecurityDescriptorSddlForm` are inherited public members
and part of parity. SDDL is a **separate codec over the core**, with its own oracle
(`ConvertSecurityDescriptorToStringSecurityDescriptor` output through
`RawSecurityDescriptor.GetSddlForm`). Domain-relative aliases (`DA`, `EA`, …) need a domain SID
from an explicit identity context. Full inherited SDDL surface coverage is an integration gate,
not a reason to claim the ten classes work once their declared methods are modeled.

---

## 5. Mutation semantics

Two contracts must remain distinct. The raw core preserves accepted bytes. The compatibility
projection targets Microsoft behavior, measured with System.DirectoryServices 9.0.0 on each
Windows runtime separately. Existing BCL mutation paths can normalize on import or access.
Safety policies that refuse operations Microsoft permits are **explicit deviations**, pending
approval for public integration; they must not be labeled exact behavioral compatibility.
The table below describes operation families, not a complete oracle-verified algorithm.

### 5.1 Operations (DACL; the SACL mirrors them with audit rules)

| Operation | Scope | Effect |
|---|---|---|
| `Add(rule)` | explicit ACEs | Merge compatible explicit ACEs using mask/audit/scope cases (§5.2); otherwise insert according to the canonical algorithm. |
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

Do not equate Microsoft's merge predicate with equality of inheritance/audit flags.
Official [CommonAcl source (v9.0.0)](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs)
contains `MergeAces`, `MergeInheritanceBits`, `AccessMasksAreMergeable` and
`AceFlagsAreMergeable`. It can combine masks, audit flags, or differing inheritance scopes
under distinct conditions. Object GUIDs qualify rights and inheritance separately. This is
source evidence for the previous design's error, not a Windows runtime oracle recording.

The compatible projection must reproduce those cases using Windows net8/net10 recordings,
including same SID with differing GUID presence, same mask with complementary scopes, and
success/failure audit combinations. Never merge allow with deny. Do not substitute a blanket
"never merge different inheritance scopes" policy and claim Microsoft parity.

Raw edit safety: unsupported/callback ACEs, unknown semantic flags and supported-layout ACEs
with unexplained trailing data are opaque for edits. Preserve their exact bytes and relative
position. Unrelated targeted changes are permitted only if the edit planner proves that no
opaque entry needs interpretation, movement or reconstruction. Otherwise refuse the entire
operation before mutation. Purge/protection over a section with opaque entries must refuse
when it cannot establish the complete target set; silently leaving possibly matching entries
is not a successful purge. This conservative policy may diverge from Microsoft and requires
explicit approval at the public boundary.

### 5.3 Splitting

`Remove` may split mask, audit and inheritance scope. Do not cap the result at two ACEs:
combined audit and propagation differences require the complete Microsoft algorithm.
Record returned boolean, output ACE order and bytes, and exceptions for each script. A
semantic truth table over self/child/descendant scope is useful supporting evidence but does
not replace exact output comparison or establish effective-access equivalence for all ACEs.

### 5.4 Canonicalization policy

Raw parse/serialize never reorder. Normalized projection may sort and compact as Microsoft
does. Explicit deny/allow/inherited ordering alone is insufficient to describe all object-ACE
and inherited ordering rules. Mutations on noncanonical ACLs and the constructor's handling
of initially noncanonical data require separate oracle cases. Raw edits preserve untouched
order or fail; normalized results are not automatically suitable for splicing back. An
internal normalization operation is explicit and carries a proposed section mutation intent;
no new public `Canonicalize()` method is part of this design.

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

Track raw origin, clean projection, and explicit per-section mutation intent separately.
BCL flags are operation evidence, not proof that a serialized section still preserves all raw
information. A byte difference caused solely by clean import/serialization is never an edit.
Conversely, an explicit binary setter may intentionally replace bytes even when a normalized
projection looks equal. The operation and affected sections must be recorded (§6.1).

### 5.7 Validation failures

For internal core operations, these checks precede publication of any changed core state,
with exception types guided by the oracle. This is not a rollback guarantee for an inherited
BCL setter that has already run (§8.2):

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

```text
Existing ten public classes + DirectoryEntry.ObjectSecurity
    |  Windows BCL adapter; unchanged-contract Linux adapter BLOCKED
    v
Internal descriptor state: raw origin + clean projection + section intents
    |                         |
    v                         v
Pure managed core         identity resolution (outside core)
Sid / ACE / ACL / SD       BCL translation on Windows; Linux boundary unresolved
    |
    v
LDAP transport: Search / Modify section patch / separate Add creation policy
```

The pure core performs no LDAP, name lookup, BCL ACL calls or effective-access checks.
It can use private SID values while retaining existing public declarations on Windows;
that does not make a private SID assignable to BCL `IdentityReference` on Linux.

### 6.1 Existing-object read → edit → Modify

This adapter discussion describes the **current BCL-derived boundary**. The authorized
[same-name candidate](same-name-portable-acl-api.md#7-core-and-ldap-integration-under-this-candidate)
would own the portable base implementations and their intent capture on both platforms. Raw,
projection, section-intent and commit-safety distinctions below still apply; the BCL
interception obstacle need not apply to newly owned portable methods.

1. **Read:** retain immutable original response bytes `R`, requested/retrieved mask `Q`,
   parsed section spans, and unknown data. A missing response/attribute is an error, not an
   empty descriptor. `NotRetrieved` comes from the request, not inference from zero offsets.
2. **Project:** create the BCL view on Windows. Immediately capture its clean serialization
   and per-section projection baseline `P0` through the same path used at commit. Retain `R`
   separately. If further getters lazily normalize, stabilize the clean projection first and
   test read-only access. Never compare a BCL projection directly with raw `R` to infer edits.
3. **Record intent `I`:** which operation deliberately targeted Owner, Group, DACL or SACL,
   including section-owned protection flags and full/partial binary or SDDL setters. Enumerate
   inherited nonvirtual entry points (`SetOwner`, `SetGroup`, protection methods and binary/SDDL
   setters) separately from virtual mutation entry points (`ModifyAccessRule`, `ModifyAuditRule`,
   `PurgeAccessRules`, `PurgeAuditRules`), which the existing class overrides. Calls through
   an `ObjectSecurity` reference must be covered in both cases. Official [ObjectSecurity source](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ObjectSecurity.cs)
   confirms protected section flags capture setter intent but not the original payload or an
   operation log; import through binary/SDDL setters can also set flags; the adapter needs a verified clean checkpoint. Method
   hiding cannot intercept a nonvirtual base call. Exact intent capture is a remaining adapter
   feasibility gate; if attribution is ambiguous, fail before sending rather than infer it
   from `P1 != R` or silently omit a genuine edit.
4. **Plan:** compare edited projection `P1` against `P0` by section, never by whole-buffer
   offset changes. For semantic operations suppress proven no-ops; explicit raw replacement
   retains its intent. Reject requested edits to unread sections rather than silently mask
   them away. For existing read-derived descriptors, `WriteSections ⊆ I ∩ Q`. No intent means
   no security write, even if BCL serialization normalized every section.
5. **Preserve inside each changed section:** reconstruct targeted operations over raw `R`,
   carrying untouched ACEs, unknown flags and tails. A whole normalized DACL is not safe just
   because only DACL is dirty. If correspondence is ambiguous, or the BCL discarded opaque
   data needed to reconstruct the requested operation, refuse publication of the core patch
   and send no commit request. This does not undo a setter already executed on the BCL view
   (§8.2). Refusing a commit Microsoft accepts is a proposed safety deviation, not established
   parity.
6. **Send:** splice the approved section patches; validate all lengths/offsets/control bits;
   send `Replace nTSecurityDescriptor` with nonzero `SecurityDescriptorFlagControl(WriteSections)`
   in the existing object's `ModifyRequest`. No dirty section means omit this modification
   and its control; unrelated property updates can still commit. Do not send zero as a
   shorthand for "nothing". Failed validation or send retains the raw baseline and the pending
   local state as it stood at commit entry, including any BCL-view edits already made.
   Successful commit invalidates the cache; reload server-produced bytes.
7. **Assignment is separate:** assigning a fresh or detached `ActiveDirectorySecurity` to an
   existing entry has no read-derived raw baseline. Do not call all sections "retrieved" or
   assume defaults were intended. Capture the Microsoft behavior for assignment and agree
   its explicit replacement intent, unread-section policy and SACL privilege requirements
   before integrating. The no-incidental-write promise cannot be inferred from ctor defaults.

**Required regression:** raw ACL has noncanonical/redundant or opaque data; clean BCL import
changes it; read-only access sends no SD. Owner-only edit sends Owner and preserves raw DACL.
DACL edit preserves every untouched ACE/tail inside DACL or is refused before I/O. Exercise
base-typed mutation, no-op mutation, reverted edits, binary setters and failed commit retry.

Narrowing today's retrieved-mask writes to intent-based section writes may differ from
Microsoft's wire behavior (O-4). Obtain that oracle evidence and a decision before rollout.
No production behavior is changed here. Refresh/move/rename invalidation must retain current
caller-visible semantics; concurrency across threads/views is not solved by immutability.

### 6.2 Creation / LDAP Add is a different contract

[MS-ADTS §6.1.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
specifies that SD-flags scope Search/Modify but are ignored on Add. Therefore a
`SecurityDescriptorFlagControl(Dacl)` on an `AddRequest` cannot protect other sections.

Create has no retrieved baseline. Track explicitly supplied sections separately from server
defaults. No explicit descriptor means omit `nTSecurityDescriptor` and allow server creation
rules. An explicit descriptor is a **creation input**, not a partial-section patch: owner,
group, DACL/SACL defaulting, class defaults, parent inheritance and caller privileges must
be modeled independently and checked against Microsoft + real AD later. Missing, null and
empty ACLs cannot be interchanged. Do not manufacture a null DACL or empty SACL from omitted
fields. Until those defaults and caller intent are established, do not claim arbitrary
partial creation descriptors safe. Failed Add retains pending creation state; successful Add
reloads the resulting descriptor. No Add experiment is authorized or executed in this PR.

### 6.3 Identity and inherited surface inventory

Inventory every public signature, not just 46 constructor shapes. Include base assignability,
`IdentityReference` parameters/results, `GetOwner`/`GetGroup(Type)`, rule factories,
`AuthorizationRuleCollection`, `GetAccessRules`/`GetAuditRules`, binary/SDDL methods, protection,
canonicality properties, virtual dispatch and consumer subclassing. Identity lookup belongs
outside the core; SID-only operations should never require a directory lookup. Account names,
well-known identities, translation errors and LDAP lookup semantics need their own contract.
An optional resolver cannot change what an already compiled BCL-typed method accepts.

---

## 7. Compatibility decision — investigation approved, adoption pending

| Compatibility dimension | Required distinction |
|---|---|
| Source after namespace substitution | The project already substitutes `AdForLinux.DirectoryServices` for Microsoft DirectoryServices. That earlier substitution alone did not authorize changing `System.Security.Principal` or AccessControl types; the new investigation explicitly evaluates that additional change. Same method spelling with clone parameter types is a further source migration. |
| Binary/type identity | The two DirectoryServices libraries are not binary interchangeable merely because signatures normalize in tests. Within this library's existing contract, callers' BCL identities, base casts and compiled member references remain real BCL types. Equal names in another assembly do not satisfy that identity. |
| Behavior | Byte output, exceptions, no-op/dirty flags, merging, enumeration and server writes must be compared separately. Similar rule semantics do not establish exact compatibility. |
| Platform support | Successful compile/reflection does not imply construction/execution. Linux PNSE remains even for in-memory methods with analyzers suppressed. |

| Candidate | Existing contract on stock Linux | Status / decision needed |
|---|---|---|
| Internal managed core behind current BCL-derived classes | Blocked at BCL construction and identity creation | Continue foundation design, report coverage honestly; this alone does not meet the end goal. |
| Parallel portable public API (prior option B) | Does not execute the ten existing types | **Rejected by user.** Removed from recommendation and delivery plan. |
| Re-root existing names on replacement public bases and replace public identity types | Can make algorithms portable but breaks base assignability, BCL signatures, binary clients and some source callers | Material public-contract change; **investigation authorized, adoption pending**. The [same-name candidate](same-name-portable-acl-api.md) supplies dependency ownership, caller examples and remaining decisions. |
| Per-target framework split | Same breaks on the portable target, plus two reference surfaces | Not selected; a `net*-windows` TFM or runtime identifier cannot make stock Linux BCL constructors portable. |
| Supported upstream .NET change providing these actual BCL implementations on Linux | Could remove the platform premise if upstream provides it | External dependency, no commitment or evidence that it exists; cannot be promised by this library. |

A public class cannot derive from a less-accessible base class. A replacement base hierarchy
would therefore be a public dependency and a type-identity change, not a private implementation
detail hidden behind the existing ten names. The user approved evaluating this alternative,
not adopting its complete public surface or implementing it.

**Current decision state:** the user authorized investigation of a same-name, single-surface
API with portable dependencies. This relaxes the research constraint; it does not make the
original BCL identities portable or approve every proposed omission. Final adoption needs the
[specific compatibility review](same-name-portable-acl-api.md#9-prioritized-decisions-and-bounded-next-evidence).
The parallel API remains rejected. Continuing core research does not approve a breaking release.
An internal facade, aliases, implicit conversions, type forwarding, or hiding base methods cannot solve both demonstrated
constructor barriers. Shipping patched framework assemblies or unsafe runtime bypasses is
outside the approved solution space.

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
| Present flags vs offsets | `SE_DACL_PRESENT` with offset 0 → `Null`; contradictory nonzero offset without present bit: preserve only if safely bounded, read-only pending oracle; never drop referenced bytes |
| Overlap | components that overlap each other or the header are **rejected** (deterministic; deviations from the oracle are documented) |
| SID | sub-authority count ≤ 15; `8 + 4n ≤` remaining bytes of the component |
| ACL | `AclSize ≥ 8`; `offset + AclSize ≤ length`; **`AceCount × 4 ≤ AclSize − 8`, checked before allocating** (prevents allocation amplification) |
| ACE | `AceSize ≥ 4`; `cursor + AceSize ≤ ACL end`; parsed body ≤ `AceSize`; object-ACE GUID presence within bounds |
| Alignment | accepted unaligned input must serialize byte-exactly in raw mode; normalized/new output follows oracle alignment. Refuse edits when safe relocation cannot be proven; final acceptance parity remains O-5 |
| Size | bound all allocations by validated input and checked output lengths; define an internal resource budget for untrusted descriptors, with deterministic failure and documented limits |

### 8.2 Internal-core atomicity and commit-I/O refusal

Atomic refusal applies to publishing an internal core edit and to validation before commit
I/O. It does **not** promise rollback of an inherited nonvirtual BCL setter that already
changed the public object. Such a setter may run before the adapter can validate its effect;
interception, recovery and caller-visible state require the adapter feasibility work in §6.1.
No broader public-object atomicity guarantee is made until that work is proven.

- Core values are immutable. An operation builds a new ACL, validates it completely, and only
  then replaces the reference in the descriptor.
- The DirectoryEntry slot publishes a new raw baseline only after a successful parse and
  invalidates it after a successful commit. Failed pre-send validation sends nothing and
  retains the pending local state at commit entry. This is not a rollback to before the edit.
  Input arrays are never written in place (`ChangePasswordAclTests.Malformed_descriptors_fail_without_mutating_the_input`
  is the pattern).
- Only the declared core exception types escape core operations. Fuzz tests (§9.2) enforce
  this; inherited BCL setters retain their own behavior until adapter parity is established.

### 8.3 Safeguards

| Risk | Safeguard |
|---|---|
| Dropping unknown data | Opaque ACEs, unknown control/ACE/object flags, `Sbz` fields and trailing bytes are preserved. Test invariant: for every operation, *the opaque-ACE multiset and every unmodified section's bytes are unchanged*. |
| Replacing unread sections | A `NotRetrieved` slot cannot be edited (`InvalidOperationException`) and is never written: `WriteSections ⊆ Retrieved`. Fresh/detached assignment and creation have separate unresolved contracts (§6.1–6.2); ctor defaults are not proof of intent. |
| Broadening permissions | No implicit `Null` DACL. No allow/deny merge; GUID/scope merges require the full oracle predicate. Splitting keeps each inheritance scope's exact bits. No generic-bit expansion. `Remove` only clears the bits it was asked to. Protection changes only happen through `SetAccessRuleProtection`. |
| Silent reordering | Raw parse never reorders. Preserve raw unrelated order or refuse; Microsoft projection normalization is a separate contract (§5.4). |
| Lost updates (concurrent edits) | Section-scoped writes still overwrite concurrent changes within a written section. No atomic concurrency guarantee is claimed. A re-read/compare can detect some conflicts but leaves TOCTOU; no new public `CommitOptions` is approved. AD assertion-control/version support and SD value-match behavior are future research, not a tested CAS solution. |

---

## 9. Test and oracle plan

The tests build on the existing suites and keep them green. Linux offline, Windows oracle and
live-directory evidence are recorded separately, and **Samba evidence is never counted as AD
parity**.

### 9.1 Existing suites (unchanged, extended)

| Suite | Role going forward |
|---|---|
| `ObjectSecurityComparisonTests` (Windows, live AD) | Must stay green. Extend `Dacl_change_round_trips_without_replacing_unrequested_security_sections` to cover owner-only, SACL-retrieved-but-unmodified, and clean-projection normalization. Add a `new ActiveDirectorySecurity()` assignment case to capture O-4. |
| `SecurityRuleValidationComparisonTests` (Windows) | Extend to all 10 classes × every ctor overload: invalid enums, `AuditFlags.None`, `Guid.Empty` handling, exception type and parameter name. Run the same cases on the internal rule specs (Linux), against recorded expected values; public integration awaits the boundary decision. |
| `LowLevelPublicSurfaceComparisonTests` | Must stay green: the ten classes' signatures don't change. Add assembly-qualified BCL parameter/base checks and compiled consumer cases: the existing name-normalizing test alone does not establish binary identity or Linux execution. |
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
  raw-versus-projection intent, same-section opaque preservation, and separate Add capture.

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

- The same scenario set as §9.3 live, run from Linux through the existing surface **only after the
  compatibility gate is resolved**, against a real DC. Compare post-commit bytes with a Windows-side Microsoft run on the same object.
- Concurrency: two writers on different and on the same sections; document lost-update
  behavior and any later approved detection mechanism.
- **Samba**: a separate trait (`Category=Samba`), with results recorded in a separate
  section. Samba's SD defaults, storage order and inheritance handling differ, so a Samba
  pass never counts toward AD parity or coverage promotion.

---

## 10. Bounded next steps (design gates, no implementation authorized here)

| Gate | Work | Exit evidence |
|---|---|---|
| G0: public boundary | Investigate the authorized same-name portable-dependency candidate; review final contract | Direction approved, adoption pending; scaffold construction alone does not promote the ten rows |
| G1: common foundations | Specify internal SID/ACE/ACL/SD codec, raw/splice/projection modes and immutable edit planner; assess internal SidCodec extraction | Offline fixture design covers unknown bytes within changed sections, overlap, alignment and revision; no new public types |
| G2: Microsoft semantics | Extend offline Windows oracle scripts and inventory inherited entry points | Microsoft DirectoryServices 9.0.0 on net8/net10 separately; capture loaded dependency versions, bytes, flags and exceptions |
| G3: state/transport | Prove clean projection and mutation-intent capture including nonvirtual base methods; design request-capture seam | Read-only normalization never writes, owner-only and DACL edits preserve unrelated raw data, ambiguous mapping publishes no core patch and sends no commit request; BCL-view rollback remains unproven |
| G4: creation and deviations | Resolve Add defaults and fresh assignment; decide refusal, write-mask and malformed-input deviations | Reviewable behavior matrix and later authorized real AD evidence; Samba kept separate |
| G5: implementation proposal | Only after relevant gates, scope internal core/reuse and public integration work | Separate approval/scope for production changes; passing codec tests alone does not promote the ten classes |

`ChangePasswordAcl` rewrite is a potential later internal consumer, not an automatic rollout.
Its golden outputs, error behavior and unknown-data limitations need preservation or explicit
review. SDDL and identity resolution remain required surface coverage, not optional omissions
from a claim of general-purpose library compatibility.

## 11. Resolved facts, remaining decisions and risks

| ID | Item | State / next evidence |
|---|---|---|
| B-1 | Stock Linux existing BCL contract | **Blocked**, executed on 8.0.0/10.0.0. Portable-dependency investigation now authorized; final adoption pending (§7). |
| O-1 | Canonical order/merging/splitting | Prior blanket same-inheritance-only rule disproved by official source; exact net8/net10 Windows recordings pending |
| O-2 | Set/Reset/Purge scope across GUIDs, opaque ACEs and inherited entries | Windows scripts plus explicit safety-deviation review |
| O-3 | Null/absent/empty ACL mutations and materialization | Offline Windows oracle; never infer equality of these states |
| O-4 | Modify masks, fresh assignment and dirty/intent semantics | Windows request capture and inherited-entry-point audit; narrowed mask not yet approved as behavioral parity |
| O-5 | Unaligned/contradictory/revision-mismatched input | Raw accepted bytes remain exact; final reject-vs-accept parity requires Windows cases |
| O-6 | Opaque/trailing ACE edit policy | Proposed preserve-or-refuse rule resolved in this design (§5.2); public behavioral deviation still needs approval |
| O-7 | Concurrent edits / atomic conflict detection | No CAS guarantee; protocol research and separately authorized AD validation remain |
| O-8 | Coverage | No promotion from internal-core or compilation evidence alone |
| O-9 | Public compatibility decision | Same-name investigation authorized; candidate namespace, dependency surface, omissions and semantic choices require final review |
| O-10 | InheritanceType on unmappable flags | Capture getter behavior separately from raw retention |
| O-11 | LDAP Add | SD-flags ignored: **resolved protocol fact**. Creation defaults, inheritance and privilege behavior remain to be measured |
| O-12 | Incidental normalization | Raw R / clean P0 / edited P1 / section intent design is resolved; complete BCL adapter attribution is not yet proven |

No Windows oracle or live AD/Samba test was executed in this research environment. See the
[probe report](../research/acl-contract-probe/README.md) for the narrower executed evidence.
