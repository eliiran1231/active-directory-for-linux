# Approved Microsoft companion public contract

The user approved this exact optional contract and the recommended MicrosoftInterop name
on 2026-10-09. The wrappers are now implemented in source; no NuGet release is published.
`ToMicrosoftObject` remains the simple independent-copy path. Checked edit-back is optional,
and persistence remains an explicit separate caller operation. This approval does not
authorize live AD, authentication/security changes or an effective-access evaluator.

## Package and dependency arrangement

**Approved naming: `AdForLinux.DirectoryServices.MicrosoftInterop`.** This continues the
MicrosoftInterop wording in D8. The earlier `.Microsoft` alternative was not selected.

| Item | Approved contract |
| --- | --- |
| NuGet package ID | `AdForLinux.DirectoryServices.MicrosoftInterop` |
| Assembly / file | `AdForLinux.DirectoryServices.MicrosoftInterop` / `AdForLinux.DirectoryServices.MicrosoftInterop.dll` |
| Public namespace | `AdForLinux.DirectoryServices.MicrosoftInterop` |
| Extension class | `MicrosoftConversions` |
| Target frameworks | `net8.0-windows;net10.0-windows` |
| Main dependency | `AdForLinux.DirectoryServices`, exact matching package version |
| Microsoft dependency | `System.DirectoryServices`, initially pinned to `9.0.0` to match the existing detached oracle |

The main and AccountManagement DLL names, namespaces and dependencies do not change. The
companion is optional and Windows-only, with `[SupportedOSPlatform("windows")]` on its public
surface and runtime checks at Microsoft-object construction/conversion boundaries. It does
not offer Linux stubs or cause the main library to load Microsoft DirectoryServices on Linux.
No new ACL/rule hierarchy, parallel AD API, credential provider or transport is introduced.

The main project now contains this friend declaration to the main project:

```xml
<InternalsVisibleTo Include="AdForLinux.DirectoryServices.MicrosoftInterop" />
```

The companion calls the existing internal snapshot, strict conversion and reconciliation
boundary. Internal snapshots remain internal; only the wrappers below become public. Existing
friend declarations remain unchanged. No reflection into Microsoft private members or new
public raw/provenance setters are needed. The main project is currently unsigned; the companion's named
friend relationship follows that existing build arrangement. It is not an authorization or
security boundary. If signing is introduced in a separate change, the exact companion public
key must be specified in the friend declaration; this proposal does not change signing or
security settings. Companion/core versions move together because the internal ABI is not a
cross-version public contract.

## Conversion signatures

Aliases in these declarations are ordinary C# aliases, not new public types:

```csharp
using D = AdForLinux.DirectoryServices;
using P = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;
using MP = System.Security.Principal;
using MA = System.Security.AccessControl;

namespace AdForLinux.DirectoryServices.MicrosoftInterop;

public static class MicrosoftConversions
{
    public static MP.SecurityIdentifier ToMicrosoftObject(this P.SecurityIdentifier source);
    public static P.SecurityIdentifier ToPortableObject(this MP.SecurityIdentifier source);
    public static MP.NTAccount ToMicrosoftObject(this P.NTAccount source);
    public static P.NTAccount ToPortableObject(this MP.NTAccount source);
    public static MP.IdentityReference ToMicrosoftObject(this P.IdentityReference source);
    public static P.IdentityReference ToPortableObject(this MP.IdentityReference source);

    public static M.ActiveDirectoryAccessRule ToMicrosoftObject(this D.ActiveDirectoryAccessRule source);
    public static D.ActiveDirectoryAccessRule ToPortableObject(this M.ActiveDirectoryAccessRule source);
    public static M.ActiveDirectoryAuditRule ToMicrosoftObject(this D.ActiveDirectoryAuditRule source);
    public static D.ActiveDirectoryAuditRule ToPortableObject(this M.ActiveDirectoryAuditRule source);

    public static IReadOnlyList<MP.IdentityReference> ToMicrosoftObjects(this P.IdentityReferenceCollection source);
    public static IReadOnlyList<P.IdentityReference> ToPortableObjects(this MP.IdentityReferenceCollection source);
    public static IReadOnlyList<MA.AuthorizationRule> ToMicrosoftObjects(this A.AuthorizationRuleCollection source);
    public static IReadOnlyList<A.AuthorizationRule> ToPortableObjects(this MA.AuthorizationRuleCollection source);

    public static M.ActiveDirectorySecurity ToMicrosoftObject(this D.ActiveDirectorySecurity source);
    public static D.ActiveDirectorySecurity ToPortableObject(this M.ActiveDirectorySecurity source, D.SecurityMasks retrievedSections);
    public static SecurityDescriptorSnapshot CaptureSnapshot(this D.ActiveDirectorySecurity source);
    public static MicrosoftSecurityEdit ExportForEdit(this D.ActiveDirectorySecurity source);
}
```

The access-rule overload covers the base AD access rule and the seven known specialized
subtypes: ListChildren, CreateChild, DeleteChild, Property, PropertySet, ExtendedRight and
DeleteTree. Runtime subtype and all recorded fields must survive both directions. The static
return type is the familiar AD access-rule base; callers needing a specialized static type
can cast after conversion. Audit has its own familiar base return type. No seven additional
extension-name families or public field-only rule classes are proposed.

Rule collections use the same known AD-family allowlist and preserve order and multiplicity.
A conversion stages every element and returns a read-only list only after all elements pass.
Using `IReadOnlyList` makes the result a frozen independent list. Microsoft's collection has
a public AddRule method; this helper does not return a mutable or linked native collection.
Unsupported custom subclasses and non-AD rule families refuse;
this initial public surface does not silently flatten their behavior/state. A future explicit
caller-factory bridge for arbitrary ObjectSecurity subclasses is separate from this smallest
AD companion surface. Internal field-only converters are not an implicit public fallback.

Identity conversion copies numeric SID bytes or account spelling; it never calls Translate
or resolves an account. Names remain names. Unknown identity subclasses refuse. Every
conversion validates the actual target fields/serialization and returns an independent object.
Neither direction invents original raw information that a Microsoft object has already lost.

## Read-only snapshot versus editable export

```csharp
public sealed class SecurityDescriptorSnapshot
{
    // No public constructor or setters. All byte-array results are defensive copies.
    public D.SecurityMasks RetrievedSections { get; }
    public D.SecurityMasks PendingWriteSections { get; }
    public byte[] GetRawBinaryForm();
    public byte[] GetOriginalBinaryForm();
    public byte[] GetObservableBinaryForm();
    public M.ActiveDirectorySecurity ToMicrosoftObject();
}

public sealed class MicrosoftSecurityEdit : IDisposable
{
    // No public constructor. Object is mutable; Snapshot is immutable original data.
    public M.ActiveDirectorySecurity Object { get; }
    public SecurityDescriptorSnapshot Snapshot { get; }
    public D.SecurityMasks ApplyTo(D.ActiveDirectorySecurity source);
    public void Dispose();
}
```

`CaptureSnapshot` freezes raw/original/observable bytes, coverage and pending intent. It
contains no source reference, resolver, identity attachment authority, credentials, connection,
callback or write capability. Capturing a partial read is allowed and records that coverage;
converting it to a complete Microsoft security object still refuses. Snapshot conversion
creates a fresh independent Microsoft object each time and grants no edit-back capability.
The immutable snapshot owns only managed data and is not IDisposable.

`ToMicrosoftObject(source)` is the convenient detached conversion, equivalent to capturing a
snapshot and converting it. Editing the returned object cannot change the source. Import via
`ToPortableObject` requires explicit caller-supplied retrieved-section knowledge (no default
All), and produces a new detached portable object with no inherited pending intent, resolver
or entry binding. The caller must supply the actual read coverage or explicitly known
in-memory construction coverage; serializer defaults are not evidence of loaded sections. It does not treat conversion as permission to assign or persist
all sections; existing explicit section-intent and destination-baseline rules still apply.

`ExportForEdit` separately captures the source wrapper token, descriptor generation and
identity-attachment version, plus its verified post-import Microsoft baseline. The edit
session holds those opaque data tokens, copied bytes and its Microsoft object; **it holds no
source wrapper reference or resolver/connection/credential capability**. `ApplyTo` requires
the caller to supply the originating portable wrapper explicitly. It checks source identity,
generation and attachment even for a no-op. An unrelated wrapper, shared-descriptor peer,
rebind, refresh or stale generation refuses. Caller edits occur on the real Microsoft object;
no companion Add/Remove/Set ACL methods are introduced.

Apply is atomic in the portable state and returns the existing `D.SecurityMasks` value for
changed sections; it never calls CommitChanges or sends LDAP. Current unambiguous owner/group,
unique mask/deletion and non-merging insertion proofs apply. Unsupported or lossy edits throw
NotSupportedException with the source unchanged. Concurrent/stale/unrelated state throws
InvalidOperationException. Ordinary argument errors retain normal ArgumentException behavior.
Strict detached export uses the same preservation allowlist and refuses unsupported data;
there is no `allowLossy` flag or fallback replacement.

A successful ApplyTo consumes the session, including a no-op; another ApplyTo throws
InvalidOperationException. Failed application does not consume it, so a candidate may be
corrected and retried only while source provenance remains valid. Object/Snapshot remain
readable after successful application until disposal. This one-success lifetime is a companion
wrapper rule, not a claim about the current internal baseline API.

Dispose is idempotent, discards managed references and makes Object/Snapshot/ApplyTo throw
ObjectDisposedException. It never applies edits, disposes the source, closes a directory
connection or revokes credentials. Previously obtained snapshots and Microsoft objects remain
independent usable data. No memory-zeroing guarantee is made. The mutable edit session is not
thread-safe; callers synchronize editing/application/disposal. Source freshness/atomicity
checks still protect publication against concurrent portable edits.

## User-visible contract example

```csharp
using AdForLinux.DirectoryServices.MicrosoftInterop;
using D = AdForLinux.DirectoryServices;
using M = System.DirectoryServices;
using MP = System.Security.Principal;
using System.Security.AccessControl;

D.ActiveDirectorySecurity portable = entry.ObjectSecurity;
M.ActiveDirectorySecurity detached = portable.ToMicrosoftObject();
// Editing detached never changes portable; it carries no edit-back provenance.

using (MicrosoftSecurityEdit edit = portable.ExportForEdit())
{
    edit.Object.AddAccessRule(new M.ActiveDirectoryAccessRule(
        new MP.SecurityIdentifier("S-1-5-21-1-2-3-2000"),
        M.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
    D.SecurityMasks changed = edit.ApplyTo(portable); // Local, atomic, may refuse ambiguity.
}
entry.CommitChanges(); // Explicit caller action; existing raw section planner is used.
```

The example requires a complete exportable descriptor and an unambiguous non-merging new
rule; it is not a guarantee that every Microsoft AddAccessRule result can be reconciled.
The [compiled example](../examples/MicrosoftInteropUsage.cs) is included in companion tests;
its EditAndSave method is compiled but never executed by offline tests. It is not live AD evidence.
For inspection/copying only, use `CaptureSnapshot` or `ToMicrosoftObject`, not ExportForEdit.

## Migration and release gates

- The existing coordinated portable hierarchy already requires rebuilding callers: supporting
  identity/access-control types use AdForLinux namespaces and Principal.Sid is portable. The
  companion does not undo that substitution or add implicit casts. Windows consumers add one
  optional package and explicit conversion calls at Microsoft API boundaries.
- Existing AD class/rule names stay unchanged. Known specialized rules retain their runtime
  subtype, though the compact extension surface returns the AD access-rule base statically.
- Collections convert to read-only lists, not live linked views or writable native collections.
  Unknown/custom subtypes refuse instead of losing extra state. Scalar conversion does no lookup.
- Previously detached ToMicrosoftObject callers keep detached semantics. Editable export is a
  separate opt-in; ApplyTo is local and explicit; CommitChanges remains a separate caller action.
- Copying a native object back does not recover raw bytes already lost before this boundary,
  preserve another object's pending intent, or transfer credentials/authority. Lossy native
  normalization can therefore cause explicit refusal where Microsoft alone would accept it.
- No public contextual identity resolver or host-relative alias helper is added by this proposal.
  Their authority contract remains separate; name-based edits still require the current verified
  context. No effective-access evaluator or live server defaults are implied.

The optional project, exact friend entry and wrappers are implemented. The solution compiles
the usage example and the public companion tests exercise actual Microsoft objects on Windows.
Linux runs the portable coverage/guard tests, builds both Windows-targeted companion TFMs and
validates local package contents and dependency isolation; Windows-only tests are explicitly
skipped there. Exact core/native NuGet dependencies are checked from generated nuspecs.
Packaging for offline verification is not release publication. No signing change is introduced.
