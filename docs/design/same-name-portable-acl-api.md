# Research candidate: one ACL API with the existing ten class names

Status: **authorized for investigation; not adopted or implemented**. PR #225 / issue #224.
The user approved investigating replacement base and identity types while keeping the ten
class names and familiar methods. This is a deliberate relaxation of the original BCL-type
contract, not a finding that the original contract was portable. A parallel ACL API remains
rejected. The user subsequently confirmed the library is unreleased and approved the supporting
`AdForLinux.Security.*` namespace/assembly ownership below. **Update 2026-10-06:** the user
decided that the same portable types are used on Windows and Linux, with explicit snapshot
bridges to Microsoft objects. Protected hooks, including all `Persist` overloads, are preserved.
`Principal.Sid` moves to the portable type in the same pre-release design. See
[decisions](acl-decisions.md). The final member-by-member surface is still under review.
No production source, packaging, directory permission or workflow changes occur here.

**Useful result:** an isolated prototype links the actual ten-class wrapper source and rebinds
its dependencies to portable scaffolding. All **46 public constructor shapes** execute on
Linux .NET 8.0.0 and 10.0.0. Factory dispatch and using the real BCL enums work. Unmigrated
BCL SID arguments, base assignments and generic rule collections fail compilation, as expected.
Descriptor mutation deliberately throws: this establishes construction/type feasibility,
**not** working ACL semantics, LDAP integration or ten completed Linux implementations.
See [reproduction and outputs](../research/same-name-acl-probe/README.md).

The [core design](portable-acl-core.md) remains the representation, safety and transport
foundation. This candidate changes who owns the public implementation boundary; it does not
relax raw-preservation, explicit section intent, Add/Modify separation or unknown-data rules.

## 1. Concrete ownership and dependency graph

Evaluate one reference surface for **both net8.0 and net10.0, on Windows and Linux**:

```text
AdForLinux.DirectoryServices.dll (candidate future breaking version)
  AdForLinux.DirectoryServices                    [the same ten public class names]
    ActiveDirectorySecurity
      : AdForLinux.Security.AccessControl.DirectoryObjectSecurity
        : AdForLinux.Security.AccessControl.ObjectSecurity
    ActiveDirectoryAccessRule
      : AdForLinux.Security.AccessControl.ObjectAccessRule
        : AdForLinux.Security.AccessControl.AccessRule
          : AdForLinux.Security.AccessControl.AuthorizationRule
    ActiveDirectoryAuditRule
      : AdForLinux.Security.AccessControl.ObjectAuditRule
        : AdForLinux.Security.AccessControl.AuditRule
          : AdForLinux.Security.AccessControl.AuthorizationRule
    CreateChild / DeleteChild / DeleteTree / ExtendedRight /
    ListChildren / Property / PropertySet AccessRule
      : AdForLinux.DirectoryServices.ActiveDirectoryAccessRule
  AdForLinux.Security.AccessControl
    AuthorizationRuleCollection : System.Collections.ReadOnlyCollectionBase
  AdForLinux.Security.Principal
    IdentityReference (abstract; assembly-internal constructor)
      SecurityIdentifier (sealed; immutable SID value)
      NTAccount (sealed; unresolved account-name value)
  AdForLinux.DirectoryServices.Security.Core        [internal, immutable bytes/algorithms]
    Sid / Ace / Acl / SecurityDescriptor / RuleSpec / MutationIntent
  DirectoryEntry.ObjectSecurity                     [same property name/type spelling]
    -> portable ActiveDirectorySecurity -> shared state -> LDAP transport
```

These replacement bases are **public**, as required for public derived classes. They are not
private implementation details, BCL type forwards, or aliases at runtime. New supporting
namespaces are dependencies of the single existing-name API, not another family of ACL entry
points. Do not define types under `System.Security.*` or ship replacement system assemblies.

Approved supporting-type ownership is the existing low-level DirectoryServices assembly: it avoids a new
package/version edge and keeps AccountManagement's dependency direction intact. Internal SID
bytes/codec move down only in a later implementation, preserving `InternalsVisibleTo` access.
A separate portable primitives assembly could be considered if other libraries need it, but
would add another public assembly identity and release dependency; it is not needed to test
this candidate. Keep this approved ownership stable through public preview; moving public types later would
create another migration even when type forwarding is possible.

Windows would also use the portable bases/core. Keeping BCL bases only on Windows would mean
platform/TFM-dependent casts, overload binding, generic types and reflection surfaces. That
split is not the proposed candidate. Windows BCL objects can be explicitly converted through
SID/descriptor bytes at an integration boundary; they are not the live backing public objects.
Windows execution and byte/exception parity still require the Microsoft oracle.

## 2. Which types stay, which change

| Type family | Candidate binding | Reason / limitation |
|---|---|---|
| Ten directory classes, `ActiveDirectoryRights`, `ActiveDirectorySecurityInheritance`, `PropertyAccess`, `SecurityMasks` | Existing `AdForLinux.DirectoryServices` names/assembly | Class names and directory enum identities remain; the classes' bases and identity-bearing signatures change |
| `AccessControlType`, `AuditFlags`, `InheritanceFlags`, `PropagationFlags`, `AccessControlModification`, `ObjectAceFlags`, `AccessControlSections` | Keep real `System.Security.AccessControl` enums | Value-only metadata works on Linux in the probe; replacing it would cause unnecessary enum conversions. This is not use of BCL descriptor implementations |
| `WellKnownSidType` | Candidate retains real `System.Security.Principal.WellKnownSidType` enum if that constructor/helper surface is approved | Enum presence is not implementation of every well-known SID algorithm |
| Identity, SID/account, base rules/security and rule collections | New `AdForLinux.Security.*` types | Runtime and generic type identities change on **both** operating systems |
| `Guid`, `byte[]`, `string`, `bool`, `int`, `Type` and standard collection interfaces | Existing framework types | `Type` arguments now identify portable SID/account types, not BCL types |
| Raw/Common ACL, ACE and security descriptor classes | Internal core, not cloned public BCL universe | Protected-subclass compatibility consequences below must be explicitly accepted |

**Do not cast section flags:** `SecurityMasks` uses Owner=1, Group=2, Dacl=4, Sacl=8;
`AccessControlSections` uses Audit=1, Access=2, Owner=4, Group=8. Retaining BCL enums requires
an explicit checked mapping at binary/SDDL setters and transport. The prototype verifies the
Dacl/Access mismatch. Passing one integer mask as the other could target the wrong section.

## 3. Proposed member contract to review

Use `P` for `AdForLinux.Security.Principal`, `A` for
`AdForLinux.Security.AccessControl`, and `E` for `System.Security.AccessControl` below.
These are a design specification, not implemented classes. The
[reflected net8](../research/same-name-acl-probe/results/bcl-surface-net8.txt) and
[net10](../research/same-name-acl-probe/results/bcl-surface-net10.txt) inventories record
public/protected BCL declarations, exact member-access categories, static/abstract/virtual/final
flags and abstract/sealed type status; ordinary `System.Object` inherited
members are not repeated. The inventory is not a claim that all listed dependencies should
be replicated.

### Existing ten classes

Preserve accessibility, sealed status, parameter order/names, overload count, virtual/final
factory behavior and member spelling where possible. Substitute **only** the proposed
identity/base/collection types in relevant signatures; there are no implicit BCL conversions.

- `ActiveDirectorySecurity()` remains the sole public constructor. `DirectoryEntry.ObjectSecurity`
  still gets/sets `ActiveDirectorySecurity`; its private loading path binds to core state.
- Access and audit rules retain six constructor shapes each: `(identity, rights, kind)`, plus
  `objectType`, `inheritanceType`, both, `inheritanceType + inheritedObjectType`, or all three.
  `identity` becomes `P.IdentityReference`; `kind` remains `E.AccessControlType` or `E.AuditFlags`.
- CreateChild, DeleteChild, ExtendedRight and PropertyAccess retain six shapes each;
  DeleteTree, ListChildren and PropertySet retain three each. All identity parameters change
  to `P.IdentityReference`; directory rights/property enums and GUID parameters stay.
- `ActiveDirectoryRights` and `InheritanceType` getters remain on ordinary access/audit rules;
  specialized rules remain construction conveniences, not enumeration result types.
- Existing typed `Add/Set/Reset/Remove/RemoveSpecific` access methods and corresponding audit
  methods retain their names and `void`/`bool` results. `RemoveAccess(P.IdentityReference, E.AccessControlType)`
  and `RemoveAudit(P.IdentityReference)` change identity type.
- `ModifyAccessRule(E.AccessControlModification, A.AccessRule, out bool)` and audit counterpart
  remain virtual overrides; purge methods take `P.IdentityReference`. Factories still return
  `A.AccessRule`/`A.AuditRule`, with both ordinary and object-GUID overloads, and remain sealed
  overrides where the existing class is sealed-overriding them.

All 46 constructors are bound and invoked by the prototype, but only one valid argument set
per shape is used. It does not validate every enum, mask, inheritance/GUID combination or
exception ordering.

### Inherited public surface to preserve by shape

| Owner | Required candidate members / types |
|---|---|
| `A.AuthorizationRule` | `P.IdentityReference IdentityReference`, `bool IsInherited`, `E.InheritanceFlags InheritanceFlags`, `E.PropagationFlags PropagationFlags`; protected-internal `int AccessMask` and corresponding protected-internal constructor |
| `A.AccessRule` / `A.AuditRule` | `E.AccessControlType AccessControlType` / `E.AuditFlags AuditFlags`; protected constructor accepting portable identity and unchanged scalar/enum parameters |
| `A.ObjectAccessRule` / `A.ObjectAuditRule` | `Guid ObjectType`, `Guid InheritedObjectType`, `E.ObjectAceFlags ObjectFlags`; protected object-GUID constructor |
| `A.ObjectSecurity` identity | `P.IdentityReference? GetOwner(Type)`, `GetGroup(Type)`; `void SetOwner(P.IdentityReference)`, `SetGroup(P.IdentityReference)` |
| `A.ObjectSecurity` binary | `byte[] GetSecurityDescriptorBinaryForm()`; `void SetSecurityDescriptorBinaryForm(byte[])` and `(byte[], E.AccessControlSections)` |
| `A.ObjectSecurity` SDDL | `string GetSecurityDescriptorSddlForm(E.AccessControlSections)`; `void SetSecurityDescriptorSddlForm(string)` and `(string, E.AccessControlSections)`; static `bool IsSddlConversionSupported()` |
| `A.ObjectSecurity` flags | `bool AreAccessRulesCanonical`, `AreAuditRulesCanonical`, `AreAccessRulesProtected`, `AreAuditRulesProtected`; `SetAccessRuleProtection(bool,bool)` / audit counterpart |
| `A.ObjectSecurity` dispatch | Abstract `Type AccessRightType/AccessRuleType/AuditRuleType`; ordinary factories; virtual modify and purge methods with portable rule/identity types |
| `A.DirectoryObjectSecurity` | Object-GUID factories; `A.AuthorizationRuleCollection GetAccessRules(bool includeExplicit, bool includeInherited, Type targetType)` and audit counterpart |
| `A.AuthorizationRuleCollection` | Public constructor, `AddRule(A.AuthorizationRule?)`, typed indexer, `CopyTo(A.AuthorizationRule[], int)`, plus inherited `Count`, `ICollection`, enumeration and synchronization members from `ReadOnlyCollectionBase` |

Collection results should be detached snapshots: modifying the result collection must not
mutate the descriptor. Null/index/copy behavior and ordering require oracle tests. A
`List<A.AccessRule>` is not a `List<System.Security.AccessControl.AccessRule>`; ordinary
covariance rules do not bridge unrelated class identities. Collection names alone are not
compatibility.

### Protected surface: explicit preserve/deferred manifest

**Status labels are proposals, not approval.** Preserve means retain the familiar shape with
only the reviewed portable type substitutions; behavior still requires implementation/oracle
coverage. Omit-proposed identifies a possible additional source break that cannot be adopted
without approval. Deferred means evaluate preservation alternatives before selecting omission.
The original scaffold is only a constructor/dispatch subset, not this inherited contract.
The [interop/override follow-up](acl-microsoft-interop-and-overrides.md#5-protected-hooks-preserve-extension-points-separate-native-defaults)
adds executable subclass evidence and recommends preserving ordinary hooks, including Persist.

| Owner and member | Candidate disposition | Required detail / scaffold limitation |
|---|---|---|
| `AuthorizationRule(P.IdentityReference, int, bool, E.InheritanceFlags, E.PropagationFlags)` and `int AccessMask { get; }` | **Preserve**, protected-internal | Retain `FamilyOrAssembly` accessibility, not merely protected. The scaffold currently has narrower protected declarations |
| `AccessRule` / `AuditRule` protected constructors | **Preserve** | Same identity/mask/inherited/inheritance/propagation parameters plus access-control/audit enum; identity type substituted |
| `ObjectAccessRule` / `ObjectAuditRule` protected constructors | **Preserve** | Preserve GUID arguments and scalar/enum shape with portable identity; scaffold covers construction but not full validation |
| `ObjectSecurity()` | **Preserve**, protected | Explicitly specify clean initial state and no write intent; scaffold only has an implicit parameterless base constructor |
| `ObjectSecurity(bool isContainer, bool isDS)` | **Preserve**, protected | Keep both flags and validate/default descriptor semantics against oracle; absent from scaffold |
| `DirectoryObjectSecurity()` | **Preserve**, protected | Directory/container state initialization needs oracle; scaffold constructor is empty |
| `ObjectSecurity(CommonSecurityDescriptor)` and `DirectoryObjectSecurity(CommonSecurityDescriptor)` | **Preserve direction; dependency contract deferred** | Investigate a public portable descriptor facade. Its usable ACL/ACE surface and sharing/tracking behavior need specification; no omission is approved |
| `CommonSecurityDescriptor SecurityDescriptor { get; }` | **Preserve direction; dependency contract deferred** | A bounded public descriptor facade may serve subclasses; an internal core type cannot be exposed through this protected member. Preserve usable behavior, not just the name |
| `ReadLock()`, `ReadUnlock()`, `WriteLock()`, `WriteUnlock()` | **Preserve**, protected | Retain locking semantics and protected access requirements; scaffold has only throwing read-lock hooks |
| `bool OwnerModified`, `GroupModified`, `AccessRulesModified`, `AuditRulesModified` (`get; set;`) | **Preserve**, protected | Do not use subclass-writable flags as the sole mutation-intent record. Scaffold has placeholder getters and no setters |
| `bool IsContainer { get; }`, `bool IsDS { get; }` | **Preserve**, protected | Consistent with constructor state; absent from scaffold |
| `ObjectSecurity.ModifyAccess(E.AccessControlModification, A.AccessRule, out bool)` and audit counterpart | **Preserve**, protected abstract | Keep override signatures after portable rule substitution; absent from scaffold |
| `DirectoryObjectSecurity.ModifyAccess(...)` / `ModifyAudit(...)` overrides | **Preserve**, protected override | Route through the internal transaction planner; absent from scaffold |
| `DirectoryObjectSecurity.AddAccessRule(A.ObjectAccessRule)`, `SetAccessRule(...)`, `ResetAccessRule(...)` | **Preserve**, protected nonvirtual, `void` | Familiar helper shapes; scaffold throws rather than modifying descriptors |
| `RemoveAccessRule(A.ObjectAccessRule)`; `RemoveAccessRuleAll(...)`, `RemoveAccessRuleSpecific(...)` | **Preserve**, protected nonvirtual | First returns `bool`; remaining helpers return `void`. Scaffold throws |
| `AddAuditRule(A.ObjectAuditRule)`, `SetAuditRule(...)`; `RemoveAuditRule(...)`, `RemoveAuditRuleAll(...)`, `RemoveAuditRuleSpecific(...)` | **Preserve**, protected nonvirtual | Remove returns `bool`, others `void`; there is no corresponding BCL ResetAuditRule helper to invent. Scaffold throws |
| `Persist(string, E.AccessControlSections)`, `Persist(bool, string, E.AccessControlSections)`, `Persist(SafeHandle, E.AccessControlSections)` | **Preserve virtual hook shapes; native default policy deferred** | New subclass probes exercise all three overloads without I/O. False-ownership forwarding can be managed; true-ownership base behavior may need Windows privileges. Do not omit hooks because defaults concern native resources; never reinterpret them as LDAP |

Factories and virtual public modify/purge methods retain the shapes in the public manifest,
including existing sealed overrides. New portable base implementations can record intent
through their own nonvirtual setters; there is no BCL constructor or implementation to
intercept. Derived consumer code still needs the portable base/identity type substitutions.

The public descriptor dependency is the main scope risk: replicating
`CommonSecurityDescriptor` pulls in further ACL/SID classes. The bounded investigation uses
an internal descriptor-state loading path as an option, **not an approved removal of subclass
members**. Its throwing public `CommonSecurityDescriptor` scaffold only binds the current
internal loading constructor and is not a shipping design. Preserve familiar hooks where
practical; if complete protected descriptor fidelity is required, explicitly expand the scope
rather than claiming a small replacement already covers it. `DirectoryEntry.CommitChanges`
remains the proposed LDAP persistence path. Public SDDL, identity, collection and descriptor
members likewise need real semantics before claiming the familiar surface works.

## 4. Portable identity and SID behavior

Candidate `P.IdentityReference` is abstract with an internal constructor, `Value`,
`ToString/Equals/GetHashCode`, equality operators, `IsValidTargetType(Type)` and `Translate(Type)`.
Keeping its constructor internal matches the current non-extensible identity model. Candidate
`P.SecurityIdentifier` is sealed and immutable; equality and hashing must agree for the same
SID regardless of string spelling or originating byte array. Do not promise stable serialized
hash codes. Mutable buffers are copied, with strict offset/length checks on every operation.

| Surface | Candidate contract / evidence limit |
|---|---|
| `SecurityIdentifier(string)` | Numeric `S-1-authority-sub...` parsing backed by internal codec; decimal and `0x` authority, authority ≤ 48 bits, revision 1, ≤15 uint subauthorities. Alias/whitespace/sign/leading-zero acceptance must be specified against the BCL string oracle; current SidCodec is not the complete BCL parser |
| `SecurityIdentifier(byte[], int)` | Read exactly `8 + 4*count` bytes at offset; allow a following buffer payload without including it in the SID; reject truncated/invalid input; copy bytes |
| `BinaryLength`, `GetBinaryForm(byte[], int)`, `Value`, `ToString()` | 8–68 byte SID representation; authority big-endian, subauthorities little-endian; text emits unsigned decimal fields. Offset/copy/simple SID cases executed, not complete exception parity |
| `MinBinaryLength`, `MaxBinaryLength`, typed/object equality, equality operators, `IComparable<P.SecurityIdentifier>` | Preserve recognizable surface; require null, differing counts and high-bit subauthority comparison cases. Do not assume lexicographic byte ordering equals BCL comparison |
| `AccountDomainSid`, `IsAccountSid`, `IsEqualDomainSid` | Required if claiming a general SID replacement; numeric domain-shape interpretation must be separately specified/oracled. SidCodec's GetRid/ReplaceRid alone do not establish account-domain validity |
| `(WellKnownSidType, P.SecurityIdentifier? domainSid)`, `IsWellKnown` | Candidate retains enum identity but needs tested constant/domain-relative tables and invalid/domain-required cases; unsupported values fail explicitly, never synthesize an approximate SID |
| `SecurityIdentifier(IntPtr)` | Proposed omission from this bounded safe-managed surface; explicit source break for native-pointer callers. They must copy a validated bounded native SID into bytes at their own interop boundary. Approval remains open |
| `P.NTAccount(string)` / `(string domain, string account)` | Unresolved name value, not a SID or proof of existence. Value/equality/case/length/format validation need oracle coverage; no DNS/domain inference or network I/O during construction |

**Correction to the previous design:** official managed `SecurityIdentifier.ToString` source
in [v8](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/SID.cs),
[v9](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/SID.cs)
and [v10](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/SID.cs)
formats the authority as a decimal unsigned number. The old claim that this property must
switch to hex above 2³² was incorrect. Distinguish managed SID `Value` from native SDDL
conversion rules. Windows string/alias parsing and native-derived account/well-known behavior
still require runtime oracle cases; reading source is not executing that oracle.

### Explicit translation boundary

A SID-only rule needs no network or local account lookup. **Proposed intrinsic contract,
not yet adopted:** standalone `P.IdentityReference.Translate(Type)` handles only same-kind
translation (returning the identity), rejects unsupported target types, and refuses cross-kind
SID/account translation. Cross-kind work uses an explicit resolver call below. This changes
BCL name-translation behavior even though the method shape remains familiar; the precise
exception contract is still a decision. No global/ambient resolver or Windows LSA fallback
is introduced.

The [built-in context resolver follow-up](context-bound-identity-resolution.md) now recommends
a library-supplied AD implementation, automatically available to entry-derived descriptors
and explicitly supplied for standalone identities. Callers need not implement LDAP lookup.
This supporting extension seam remains illustrative (not another ACL API):

```csharp
// Candidate helper contract, not implemented in this PR.
public interface IIdentityResolver
{
    P.SecurityIdentifier ResolveSid(P.NTAccount account);
    P.NTAccount ResolveAccount(P.SecurityIdentifier sid);
}
// Consumer resolves once, then uses the same existing-name rule constructor.
var sid = resolver.ResolveSid(new P.NTAccount("EXAMPLE", "alice"));
var rule = new ActiveDirectoryAccessRule(sid, ActiveDirectoryRights.ReadProperty,
                                       E.AccessControlType.Allow);
```

The resolver is explicitly associated with the caller's directory endpoint, credentials,
search scope and domain context. Ambiguous/missing results fail without mutations; no global
cache of credentials or guessed cross-domain search. LDAP escaping, foreign security
principals, trusts and name ambiguity need dedicated tests. A Windows resolver can be an
opt-in integration implementation, not hidden behavior of portable constructors.

**Current research direction:** automatically propagate the actual DirectoryEntry binding to
its descriptor, so `GetOwner/GetAccessRules(targetType)` and name-bearing edits use the
library's built-in resolver. Standalone identities still have no descriptor context and must
not acquire ambient resolver state when used in a rule. The follow-up specifies a borrowed,
revocable capability, lookup timing, domain scope and failure-before-mutation; final lifecycle
and exception contracts remain unapproved except the bounded cross-entry assignment decision:
an independent descriptor-data snapshot is approved, with no source resolver/credential/lease
transfer. This intentionally breaks current shared-reference aliasing; the destination must
establish its own valid authority. Intent/provenance validation details remain open. An options epoch also cannot pin ambient/default
authentication; automatic lookup requires a proven identity-pinned lease or explicit refusal
until a fresh context establishes explicit authority. Specify missing-context versus identity-not-mapped
exception types and payloads before publishing. Cloning BCL
`IdentityNotMappedException.UnmappedIdentities` also pulls in `IdentityReferenceCollection`;
that support family is not justified solely by spelling parity.
The prototype implements no translation, NTAccount or exception-family replacement.

## 5. Exact caller migration examples

Explicit `ToMicrosoftObject()`-style bridges are now under investigation in the
[conversion follow-up](acl-microsoft-interop-and-overrides.md). They support Windows snapshot
interoperability, not old BCL casts or binary identity. The examples below remain relevant.


Before (the existing library's BCL boundary):

```csharp
using AdForLinux.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

var sid = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
ObjectSecurity security = entry.ObjectSecurity;
AccessRule rule = new ActiveDirectoryAccessRule(sid,
    ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
security.ModifyAccessRule(AccessControlModification.Add, rule, out var changed);
entry.CommitChanges();
```

After (candidate, same entry/property/class/method pattern, new dependency bindings):

```csharp
using AdForLinux.DirectoryServices;
using System.Security.AccessControl; // keep BCL enums
using SecurityIdentifier = AdForLinux.Security.Principal.SecurityIdentifier;
using ObjectSecurity = AdForLinux.Security.AccessControl.ObjectSecurity;
using AccessRule = AdForLinux.Security.AccessControl.AccessRule;

var sid = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
ObjectSecurity security = entry.ObjectSecurity;
AccessRule rule = new ActiveDirectoryAccessRule(sid,
    ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
security.ModifyAccessRule(AccessControlModification.Add, rule, out var changed);
entry.CommitChanges();
```

These snippets specify intended integration, not executed LDAP. Aliases show the exact source
migration; they do not preserve compiled identities. Importing both entire AccessControl
namespaces makes simple base-type names ambiguous. Fully qualified old SID types, declared
method parameters/results, generic arguments and `typeof` expressions need deliberate changes:

```csharp
// Before:
List<System.Security.AccessControl.AccessRule> rules;
var owner = security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
// After:
List<AdForLinux.Security.AccessControl.AccessRule> rules;
var owner = security.GetOwner(typeof(AdForLinux.Security.Principal.SecurityIdentifier));
```

**Adjacent blocker, without widening this PR's scope:**
[`Principal.Sid`](../../src/AdForLinux.DirectoryServices.AccountManagement/Principal.cs)
returns BCL `SecurityIdentifier` and throws on Linux. It does not automatically become portable
when these ten types change. `Principal.SidValue` already provides a portable string:

```csharp
// Before: new ActiveDirectoryAccessRule(principal.Sid, rights, type)
// Candidate migrated caller, if the principal actually has a SID:
var value = principal.SidValue ?? throw new InvalidOperationException("Principal has no SID.");
var rule = new ActiveDirectoryAccessRule(
    new AdForLinux.Security.Principal.SecurityIdentifier(value), rights, type);
```

**Decided ([D9](acl-decisions.md#d9-principalsid)):** `Principal.Sid`'s return type becomes the
portable `AdForLinux.Security.Principal.SecurityIdentifier` in the coordinated pre-release design,
on both platforms. `SidValue` stays. Migration and interoperability must be documented,
including the Windows bridge below. This is a design decision, not implementation in this PR.
It is currently the only other BCL identity use in the source tree
([Principal.cs](../../src/AdForLinux.DirectoryServices.AccountManagement/Principal.cs)).

Windows BCL SID interoperability can use explicit copying without adding ambiguous constructor
overloads accepting both BCL and portable identities:

```csharp
// Windows-only caller boundary; bclSid is System.Security.Principal.SecurityIdentifier.
var bytes = new byte[bclSid.BinaryLength];
bclSid.GetBinaryForm(bytes, 0);
var portableSid = new AdForLinux.Security.Principal.SecurityIdentifier(bytes, 0);
// Reverse copy to a BCL SID is also Windows-only:
var buffer = new byte[portableSid.BinaryLength];
portableSid.GetBinaryForm(buffer, 0);
var windowsSid = new System.Security.Principal.SecurityIdentifier(buffer, 0);
```

No implicit reference conversion, shared mutability, or ability to pass a portable rule to
BCL `ObjectSecurity` follows from this. Descriptor byte import/export is likewise an explicit
copy; a BCL consumer can normalize or reject opaque data. Do not claim its re-export preserves
the raw server representation.

## 6. Compatibility matrix

| Dimension | Can remain | What changes / evidence required |
|---|---|---|
| Simple source | Ten class names, directory namespaces, method patterns, scalar arguments and retained enums | Portable identity/base imports required; fully qualified BCL types, `typeof` and subclass dependencies need edits |
| Binary clients | Unrelated APIs may retain signatures | ACL constructors/member signatures, base classes and factory returns change. Rebuild dependent libraries; same namespace/assembly version cannot repair old metadata references |
| Casts / reflection | Portable casts within the analogous hierarchy | Old BCL base casts fail; `BaseType`, assembly-qualified identity and inherited member declarations differ |
| Generic/array collections | Standard collection mechanisms | `List<BclRule>`, arrays, `IComparable<BclSid>` and callback signatures are not portable equivalents; rebuild and update generic arguments |
| Windows interoperability | SID and accepted SD wire bytes | Explicit copying only; no BCL assignment, Windows ACL extension-method applicability or automatic BCL-name lookup |
| Serialization | SID/SD binary formats and supported SDDL semantics are compatibility targets | CLR type-name JSON/custom serializers change. No binary object-serialization guarantee. Public normalized SD bytes and internal lossless bytes are different contracts |
| Linux behavior | Constructor/type feasibility established | Full mutation, SDDL, identity, exceptions and LDAP behavior unimplemented; no coverage promotion |
| Windows behavior | Target same member operations and Microsoft outputs for supported inputs | Same portable implementation as Linux; replacement of formerly working BCL behavior needs regression coverage and explicit deviations |
| Subclassing | Selected portable constructor/factory/locking hooks | Persist hook shapes should be preserved; descriptor-facade semantics remain deferred. Any approved omissions, including the proposed native SID pointer omission, would add source breaks |
| Security / operational behavior | Raw-preservation and section-intent safeguards | Name resolution, unknown-data refusal, normalized output and server defaults require explicit contract; similar names cannot establish parity |

## 7. Core and LDAP integration under this candidate

The portable `ObjectSecurity` owns the internal state and **all** inherited public setter
implementations. It can route ordinary and base-typed calls through one transaction planner:
validate -> resolve required identities before mutation -> compute immutable result -> record
section intent -> publish. Retain operation evidence independently of mutable "modified"
flags that a consumer subclass might set. Constructors/getters must not create write intent.
This removes the old BCL interception obstacle for a fully portable implementation; it is a
design opportunity, not evidence the scaffold implements atomicity.

Keep raw origin `R`, retrieval mask, explicit per-section intent, and a clean normalized
projection baseline distinct as in [§6.1](portable-acl-core.md#61-existing-object-read--edit--modify).
The public `GetSecurityDescriptorBinaryForm` target is the Microsoft-style normalized view
for supported inputs. The internal raw serializer remains lossless, and commit uses raw
patches with proven intent. Neither a public getter nor a Windows interop re-export causes an
incidental write. Unknown/trailing bytes inside a changed section must survive if untouched;
if a requested semantic operation cannot preserve them safely, refuse before publishing or
sending. Explicit binary replacement intent must be distinguished from incidental projection
loss; decide what deliberately replacing opaque data means before implementation.

`DirectoryEntry.ObjectSecurity` attaches/detaches this same-name wrapper to the shared cache.
A detached `new ActiveDirectorySecurity()` still needs a reviewed assignment contract; ctor
defaults are not retrieval or mutation intent. Successful commits invalidate/reload; pre-send
failure leaves pending state and sends nothing. This is internal transaction/I/O atomicity,
not permission to promise rollback for an already-executed legacy BCL setter or an atomic
compare-and-swap against concurrent AD writers.

Modify patches only approved sections with an explicitly mapped nonzero SD-flags mask. LDAP
Add ignores that control: creation must track explicitly provided values versus server class
defaults, parent inheritance, ownership and privileges separately. Existing
[Add/Modify safeguards](portable-acl-core.md#62-creation--ldap-add-is-a-different-contract)
and real-AD evidence gates remain. No live test is part of this research.

## 8. Reuse, release and maintenance boundaries

`SidCodec` is useful internal binary/numeric machinery: endian handling, counts, strict
numeric parsing and its existing tests. The prototype source-links it for SID construction.
Its permissive trailing-buffer formatting and no consumed-length result require a bounded
reader; its null/exception/alias grammar and account-RID helpers need additional validation
before they become a public SID contract. Do not change decimal formatting based on the old
hex assumption. The public value object must define copy/equality/ordering independently.

`ChangePasswordAcl` demonstrates splicing and offset relocation and supplies a golden test
corpus. It is not a general ACL engine: exact flag/SID matching, trailing data, object flags,
revision/control/overlap checks, narrow rights replacement and exception behavior need review.
Reusing its technique does not authorize reuse of its entire edit policy for arbitrary ACEs.
A future rewrite must preserve its current outputs or declare intentional changes; the helper
and existing consumers remain untouched in this PR.

The user confirmed the library is **unreleased**: settle the contract before first stable
publication rather than assume a mandatory major-version bump from a released API. Existing
source users and compiled artifacts still need explicit migration. Coordinate DirectoryServices
and dependent AccountManagement packages; do not invent a release number or publish during
research. Keep one portable reference surface across net8/net10. A new package ID alone does
not solve assembly/type collisions in one load context. Optional Microsoft interoperability
packaging is evaluated in the [follow-up](acl-microsoft-interop-and-overrides.md#4-platform-annotations-ownership-and-references).

Replace blanket BCL public-surface equality tests with **explicitly reviewed** expected type
substitutions and a checked list of omissions; preserve every other comparison. Add assembly-
qualified type checks and compile consumer fixtures so normalized type names cannot hide
breaks. Preserve both the old-contract failure probes and this candidate's construction
probes, clearly labeled. The latter's success must not become a "ten classes implemented"
coverage claim.

Scope is a directory security model with necessary supporting values/bases/collections, not
Windows token APIs, local file/registry ACLs, native handles, privilege manipulation, an access
check engine, or a public clone of every Raw/Common ACE/ACL class. Any expansion across those
boundaries needs an explicit reason and decision.

## 9. Prioritized decisions and bounded next evidence

| Priority | Decision / test | Why it matters |
|---|---|---|
| 1 | Approve exact public dependency/omission list after this investigation | Public bases and identity types change compatibility; review deferred protected preservation and any proposed pointer/member omissions explicitly before adoption |
| 1 | Built-in entry-context resolver lifetime, assignment semantics and precise failure contract | Hidden name translation changes network activity, credentials, ambiguity and security semantics |
| 1 | Public normalized output versus raw preservation; explicit binary replacement of opaque data | Affects whether callers can unknowingly lose ACE data or trigger permission changes |
| 1 | Detached assignment and LDAP Add creation defaults | Section-scoped Modify cannot make creation safe; requires later authorized real AD comparisons |
| 2 | Windows oracle matrix for all 46 overloads, inherited/protected methods, merging and SDDL | Microsoft DirectoryServices 9.0.0 on net8/net10 Windows; record loaded ACL/identity assembly versions, scripts and exceptions separately |
| 2 | SID aliases, high-bit comparison, well-known/domain helpers and unmapped identity behavior | Value construction alone is not a general-purpose identity replacement |
| 2 | Compile migrated and unmigrated consumers, subclass fixtures and serializer round-trips | Quantify actual migration and avoid hiding omissions behind name-normalizing reflection tests |
| 3 | Offline raw parser/edit fuzz, state transitions, request capture and concurrency policy | Validate no incidental writes, preserve-or-refuse and failed-commit state without directory operations |
| 3 | Release/package migration and documentation | No platform split or accidental in-place binary break disguised as a patch |

No decision above is silently resolved by the scaffold. The construction barrier is removed
under substituted dependencies in an isolated executable; the full candidate remains
research. The next implementation proposal should be bounded by these decisions and the
Windows oracle rather than starting with a broad System.Security clone.
