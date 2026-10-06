# Research: explicit Microsoft objects and portable protected hooks

Status: **investigation authorized, names and final API policy not adopted**. PR #225.
This extends the [same-name candidate](same-name-portable-acl-api.md), rather than proposing
another portable ACL API. The user confirmed the library is unreleased and approved
`AdForLinux.Security.*` in `AdForLinux.DirectoryServices.dll`. Windows behavior changes,
resolver policy, `Principal.Sid` changes and final conversion policy remain unapproved.

**Conclusion:** a `ToMicrosoftObject()`-style explicit bridge is a useful solution for passing
portable values to existing **Windows** libraries. It should be investigated as a detached
snapshot conversion, paired with an explicit import. It does not make BCL ACL objects execute
on Linux, preserve old casts/binaries, or carry a subclass's virtual behavior across the
boundary. Ordinary protected hooks can be retained: native default behavior and managed
extension points are separate questions. The earlier suggestion to omit `Persist` merely
because it concerns local resources was too broad.

[Executable evidence](../research/acl-interop-probe/README.md): both net8/net10 builds pass;
portable subclass dispatch, lock/flag access and all three Persist overrides execute on Linux.
Actual Microsoft exports throw PNSE there. A real Microsoft consumer subclass and conversion
pairs compile against System.DirectoryServices 9.0.0, but their Windows execution is **pending**.
No production implementation, live directory, token/privilege change or workflow was run.

## 1. What explicit conversion would solve

Illustrative extension/static helper names below are not a final naming decision:

```csharp
// Windows caller; existing entry/property/class patterns remain the portable API.
var portable = entry.ObjectSecurity;
System.DirectoryServices.ActiveDirectorySecurity microsoft = portable.ToMicrosoftObject();
WindowsLibrary.Inspect(microsoft); // Existing parameter type now receives a real Microsoft object.
```

A Windows library that edits the argument edits **only the exported object**:

```csharp
// Separate illustrative edit workflow: obtain object and provenance together.
var export = portable.ExportMicrosoftSnapshot();
WindowsLibrary.Edit(export.Object);
// Never guess provenance from zero offsets or Microsoft serializing all four sections.
var imported = MicrosoftInterop.FromMicrosoftObject(export.Object, export.Context);
// Review/reconcile permitted edits with original raw bytes and section intent before assignment.
entry.ObjectSecurity = imported;
entry.CommitChanges();
```

These illustrate intended caller integration, not a working LDAP implementation. A plain
`ToMicrosoftObject()` returning only an object cannot by itself supply `exportContext` for
safe round-trip editing. A production bridge needs either a separately retained export session
(e.g. `ExportMicrosoftSnapshot()` returning object + provenance), or a deliberately restricted
simple overload for complete, representable, detached values. Do not silently infer an export
session from object identity or use a process-global side table.

| Caller situation | Bridge result / limit |
|---|---|
| Windows method accepts BCL SID, AD rule, descriptor or collection | Explicit conversion supplies the expected runtime type; reverse conversion can import supported values |
| Existing code casts portable object to `System.Security.AccessControl.ObjectSecurity` | Still fails. Use the converted Microsoft object, not a cast of the portable object |
| Old compiled constructor/signature references | Still need rebuilding/migration; conversion methods cannot rewrite metadata references |
| `List<BclRule>` / BCL arrays | Convert elements into a new collection of the expected type; unrelated generic arguments are not interchangeable |
| Windows library retains/mutates the exported object | No live synchronization. Caller must control its lifetime and explicitly import changes later |
| Custom subclass with overrides/state | Data conversion does not clone subclass type, delegates or virtual dispatch behavior |
| Linux caller wants the same Microsoft object | Actual BCL target construction is unsupported on the tested runtimes; bridge cannot repair it |
| In-memory conversion to/from account names | Copy the name, do not silently translate or query a directory. Later recipient operations may translate it |

A live proxy is a different, much larger design. A Windows BCL-derived facade would still
have its own BCL state and nonvirtual mutation paths; forwarding a few virtual methods does
not establish shared state or identity. It is not the proposed default conversion model.

## 2. Conversion contracts by type

Use `P` for portable `AdForLinux.Security.Principal`, `A` for portable AccessControl and `M`
for Microsoft DirectoryServices. Retain the same scalar/enum bindings as the candidate.

| Portable ↔ Microsoft | Proposed copy route | Conditions and unresolved details |
|---|---|---|
| `P.SecurityIdentifier` ↔ BCL `SecurityIdentifier` | `BinaryLength` + `GetBinaryForm` + byte constructor | Copy exact SID bytes; no translation, privilege check or lookup. Validate bounds and revision before export; target constructors are Windows-only |
| `P.NTAccount` ↔ BCL `NTAccount` | Copy `Value` into name constructor | No SID resolution. Preserve qualified/unqualified spelling; constructor validation/case behavior needs Windows tests. Resolved meaning is not established by copying a name |
| `ActiveDirectoryAccessRule` ↔ `M.ActiveDirectoryAccessRule` | Identity copy, raw rights bits, type, inherited flag, inheritance/propagation flags, both GUIDs via factories | Public convenience constructors cannot restore `IsInherited`; factories can. Verify GUID presence and all flags after conversion, not just nonempty GUID values |
| `ActiveDirectoryAuditRule` ↔ Microsoft audit rule | Same, including success/failure bits | Invalid/unknown bits, zero masks and exception order require oracle coverage; never drop audit flags silently |
| Seven specialized access-rule classes | Convert to semantic ordinary AD access rule, or exact recognized specialized constructor where representable | Recommended simple return is Microsoft ordinary access rule. It preserves intended rule fields, **not** concrete subtype; final policy must be explicit. Unknown consumer subclasses need rejection or explicit field-only opt-in |
| `ActiveDirectorySecurity` ↔ `M.ActiveDirectorySecurity` | Guarded descriptor snapshot through binary form | BCL import/export may normalize, merge, drop unsupported data or materialize ACL states; requires the descriptor protocol below. Never call a byte constructor and claim general losslessness |
| `A.AuthorizationRuleCollection` / sequences ↔ BCL collection/list/array | Allocate new collection, convert each supported element, preserve order and multiplicity | No descriptor backing connection or shared rule identities. Fail the whole conversion on an unsupported element; no returned partial result |

Individual rule objects cannot express arbitrary raw ACE payloads, callback conditions,
unknown bits or all on-wire GUID-presence distinctions. Conversion through a rule list is
therefore **not** a descriptor export strategy: it can lose ACL revision/order, control flags,
opaque ACEs, null/absent state and owner/group. Supported rule conversion is narrower than
raw ACE conversion. Foreign `AccessRule` types (file/registry/custom) require explicit mapping;
do not assume all rights masks have directory semantics.

The research converter uses factories for both directions and checks export object-GUID
presence. Its supported tests use ordinary access/audit rules, one SID/account name, and one
empty-DACL descriptor fixture. It is not a fail-closed production converter for arbitrary
subclasses, unknown flags or byte streams, nor a complete specialized-subtype preservation test.

## 3. Descriptor snapshots, raw data and edit-back protocol

A safe bridge must distinguish **wire bytes**, **projected Microsoft state**, and **intent**:

1. Capture a consistent portable snapshot under its read discipline: original raw bytes,
   known/retrieved sections, absent/null/empty distinctions, relevant control bits, dirty/intent
   metadata and a generation identifier. Release the lock before any external library call.
   A descriptor that was partially retrieved does not become complete because a serializer
   supplies default fields.
2. Validate representability **before** publishing a converted object. Opaque ACEs, unknown
   control/object/ACE flags, trailing data, revision/alignment anomalies and unmappable rule
   flags need explicit tests. A strict bridge should reject cases it cannot preserve/prove;
   any deliberately lossy projection needs an explicit policy and diagnostics, not a fallback.
   Whether strictness means byte equality or an approved equivalence class remains a decision.
3. Construct Microsoft state and retain its clean post-import baseline `M0`. If comparison
   already shows unsafe loss, reject. Preserve original `R` separately; equality to `M0` is
   not evidence that `R` was preserved. Do not copy portable modified flags into Microsoft
   state or let constructor/setter flags become permission-write intent.
4. The Windows caller operates on its detached copy. A copied `NTAccount` may cause the
   recipient library to perform name translation later; our conversion does not grant that
   library credentials, validate permissions, or promise its operations are side-effect-free.
5. Import `M1` only through an explicit edit-back/replacement policy. `M1 == M0` means no
   inferred edit, even when `M0 != R`. For differences, establish intended sections and
   preserve untouched opaque bytes **within** changed ACLs or refuse. Diffing two whole
   normalized buffers does not reconstruct every intended operation or identify a no-op
   explicit replacement. A simple object-only import can create a detached value, but cannot
   infer original retrieval provenance, server baseline or operation history.
6. Reject stale generation/unknown provenance for a merge workflow; do not overwrite newer
   portable edits. Do not overwrite raw data after a failed conversion, import or validation.
   A complete explicit replacement is a separate, still-unresolved policy, not permission to
   discard opaque data under the semantic-edit invariant.
7. LDAP commit still follows the [core design](portable-acl-core.md): section-aware Modify,
   failed-commit retention and reload after success. LDAP Add ignores SD-flags and needs its
   own creation/default-inheritance contract. Exporting a Microsoft object does not authorize
   broader sections, bypass SACL privileges or make concurrent directory edits atomic.

**Null/absent/unread are not interchangeable.** An absent DACL, present-null DACL and empty
DACL have materially different representation and security implications. Microsoft model
normalization must be measured for each. A projection must never convert `NotRetrieved`
into a value that an import silently writes, or an empty DACL into a null/full-access DACL.
Control bits must be attributed to their owner/group/DACL/SACL sections; map BCL
`AccessControlSections` to LDAP `SecurityMasks` explicitly because their bit values differ.

The scaffold intentionally accepts only a complete 28-byte empty-DACL fixture (ACL revision
2 or 4) and explicit complete-section provenance on import. It does **not** implement this
protocol. Its binary setter is a fixture carrier, not evidence of general mutation-intent,
normalization, permission-equivalence or edit-back safety.

## 4. Platform annotations, ownership and references

The portable public types stay in the approved `AdForLinux.Security.*` namespaces inside
`AdForLinux.DirectoryServices.dll`. Keep the same portable surface across net8/net10 and
Windows/Linux; a Microsoft converter is not a reason to reinstate different public bases per
platform. That remains a proposed Windows migration, not a final adoption decision.

A concrete packaging option to evaluate is an **optional companion**
`AdForLinux.DirectoryServices.MicrosoftInterop` assembly/package referencing the portable
assembly plus Microsoft `System.DirectoryServices` (9.0.0 in research). Extension methods
supply `portable.ToMicrosoftObject()` syntax without forcing every portable consumer to take
the Microsoft dependency. Reverse helpers are static or extensions over explicit Microsoft
types. This does not move the approved portable types or introduce another portable ACL API.
Final assembly/package/helper names are still illustrative.

The companion needs a narrowly specified internal snapshot interface (possibly controlled
friend access) for raw bytes, provenance and intent; public normalized binary methods alone
cannot reveal that state. Defining converters inside the existing assembly instead is simpler
for access but adds its Microsoft dependency to all users. Record this packaging tradeoff
before adopting a public bridge. Do not introduce circular assembly references.

Annotate both directions with `[SupportedOSPlatform("windows")]` where they construct or
inspect Microsoft objects. An annotation documents/analyzes platform requirements; it is not
a runtime guard. Production methods should fail clearly on unsupported platforms rather than
rely on an incidental downstream stub. A Windows-only TFM for the companion is an option,
not a way to execute it on Linux. Cross-compilation alone is not Windows runtime validation.
No replacement framework assemblies, unsafe allocation or runtime patching is involved.

All names should be fully qualified or aliased where both libraries are referenced. Return
actual Microsoft types from the bridge; never return a portable object typed as `object` and
call that compatibility. No implicit conversion operators are proposed: they could hide
platform transitions, snapshot costs, lookup assumptions and normalization loss.

The library is **unreleased**. Settle these contracts before a first stable release; a mandatory
major-version bump from an already released API is not an established requirement. Existing
source users, tests and compiled artifacts still need explicit migration. Future breaking
changes need normal release policy, but no package release is authorized by this research.

## 5. Protected hooks: preserve extension points, separate native defaults

The actual public/protected inventories and official implementation support retaining the
hooks. Relevant evidence:

- [ObjectSecurity, .NET 10](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ObjectSecurity.cs):
  constructor overloads, recursive lock helpers, lock-guarded writable flags, public modify
  dispatch and three virtual Persist overloads. The bool overload's ownership-enabled path
  invokes native privilege support; its false path delegates to the name overload.
- [DirectoryObjectSecurity, .NET 10](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.IO.FileSystem.AccessControl/src/System/Security/AccessControl/DirectoryObjectSecurity.cs):
  default constructor calls the container/directory base constructor. Protected modify
  overrides and typed nonvirtual helpers select different overload paths. Object-GUID
  factories are virtual with unsupported defaults, not abstract requirements.
- [Microsoft ActiveDirectorySecurity, 9.0.0](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectorySecurity.cs):
  the concrete AD class seals factory overrides. A subclass cannot override them merely
  because factories are extensible on the base hierarchy.

| Extension point | Research recommendation / exact limitation |
|---|---|
| Protected constructors `ObjectSecurity()`, `(bool,bool)`, `(CommonSecurityDescriptor)` and both DirectoryObjectSecurity constructors | Preserve shapes with portable types. The empty ObjectSecurity constructor and bool constructor have different initialization behavior; do not invent identical defaults. Limited constructor fixtures compile/run in the probe |
| `ModifyAccess/ModifyAudit` protected overrides | Preserve. Public `ModifyAccessRule/ModifyAuditRule` dispatch to them with type/lock handling. Subclass overrides execute portably in the probe; Microsoft counterpart compiles, Windows run pending |
| Typed Add/Set/Reset/Remove helper families | Preserve shapes and source-confirmed dispatch. Their private implementation path must not be silently changed to call every protected override; routing internals through a common planner is possible without changing that dispatch contract |
| Factory hooks | Retain ordinary abstract factories and object-GUID virtual factories at the appropriate base level; preserve final overrides in ActiveDirectorySecurity. Probe custom base subclass succeeds; overriding the concrete sealed factory yields CS0239 |
| Read/write locks and writable modified flags | Implement managed lock discipline and preserve accessors, including protected-internal members where applicable. Test recursion, exception cleanup and flag reads/writes under correct locks. Modified flags are not an operation journal or sufficient raw-preservation evidence |
| `Persist(string, sections)` and `Persist(SafeHandle, sections)` | Keep virtual signatures with explicit default unsupported behavior matching the chosen oracle. A consumer override can be entirely managed. SafeHandle as a parameter does not force native I/O or make the handle LDAP-related |
| `Persist(bool enableOwnershipPrivilege, string, sections)` | Keep virtual signature. An override can supply portable behavior. A false-valued base call can forward to the name override without enabling privileges; true-valued **base** behavior needs a deliberate Windows-native/unsupported-platform policy. The probe refuses that native path and never enables privileges |
| Protected `SecurityDescriptor` plus descriptor-taking constructors | Prefer preserving through a public portable descriptor facade if scope permits; the actual dependency is public/protected. The unresolved issue is the usable descriptor/ACL member closure and tracking/aliasing semantics, not impossibility of a protected method |

Do not omit hooks merely because the library itself does not call them. Conversely, keeping
a signature with a throwing research body is not implementing the contract. No `Persist`
overload automatically maps to LDAP, and conversion does not carry overrides into the exported
Microsoft instance. Default exception types/order, native behavior and all extension-point
interactions require Windows oracle validation before release.

A protected descriptor facade deserves a bounded follow-up inventory of the Common descriptor,
ACL and ACE members actually exposed to subclasses. It may route mutations through the same
internal core, preserving familiar subclass syntax without exposing internal core types.
Constructor sharing versus copying of a supplied descriptor, two wrappers sharing a facade,
lock ownership and notification of direct facade edits need explicit tests. A constructor
signature plus a byte-only placeholder does not settle this. Consumer-writable dirty flags
must remain available, while any independent mutation-intent ledger and the effect of resetting
flags must be specified against expected commit behavior; no silent safety/parity tradeoff.

These are reasons to design and test the extension surface, not evidence that it must be
removed. The existing preserve/deferred manifest is refined accordingly; no omission is
approved by this research.

## 6. Executed evidence and exact next matrix

The [new probe](../research/acl-interop-probe/README.md) compiles real wrapper source against
experimental portable bases, plus a consumer subclass against Microsoft's actual package.

| Case | Linux net8.0 / 8.0.0 and net10.0 / 10.0.0 | Windows net8/net10 with Microsoft 9.0.0 |
|---|---|---|
| Portable base-typed access/audit dispatch, recursive locks, writable flag guards, exception cleanup | Executed, pass | Same probe runnable; not executed here |
| Portable constructors, custom base factory, three Persist overrides, false forwarding | Executed, pass; no I/O | Same probe runnable; not executed here |
| Sealed concrete AD factory override | Expected CS0239 on both compilations | Compiler restriction, not platform-dependent |
| Actual Microsoft SID/name/access/audit/descriptor/collection export | Six expected PNSE results per runtime | Representative conversions compiled; run pending |
| Import back from actual Microsoft values | Cannot arrange usable source objects on Linux | Offline branch supplied for SID/name/rule fields, inherited GUID rules, collection and empty-DACL snapshot; run pending |
| Real Microsoft consumer protected hooks / helper bypass / Persist overrides | Consumer compiles, cannot construct here | Offline branch supplied; no base true-ownership/native privilege call; run pending |
| Mixed/unknown rule subtypes, all seven specialized subtypes, unknown flags, all constructor validation | Not validated by this probe | Add explicit conversion policy/field round-trip/exception tests |
| Null/absent/empty/populated and unread sections; owner/group/SACL; object GUID present-but-zero; callbacks/opaque/trailing data; revisions/alignment | Not covered beyond fixed empty-DACL fixture | Build fixture grid, compare raw R vs clean M0 vs edited M1; unsafe cases must reject under strict policy |
| Read-only conversion, edit/revert/no-op, stale export session, same-section unknown data, deliberate replacement | No transport implementation | Offline state/request-capture tests before any live integration |
| Actual permission changes / server defaults / concurrent writers | Not authorized or executed | Later separately authorized real AD tests; Samba evidence separate |

No live AD operation is needed to settle most bridge and subclass questions. Prioritize the
Windows offline field/descriptor/hook matrix, then provenance and intent reconciliation, then
any required server evidence. Two remaining design decisions materially affect callers:
strict descriptor conversion/export-session shape, and default native ownership behavior in
base Persist. Neither should block preserving the ordinary portable hooks or researching
value-copy interop. Final API names/adoption remain for review.
