# AdForLinux.DirectoryServices.MicrosoftInterop

Optional Windows-only conversions for .NET 8 and .NET 10. The core and AccountManagement
packages remain independent of this package. Use the exact matching core package version.

```csharp
using AdForLinux.DirectoryServices.MicrosoftInterop;

// portable is an AdForLinux.DirectoryServices.ActiveDirectorySecurity.
System.DirectoryServices.ActiveDirectorySecurity copy = portable.ToMicrosoftObject();
// Changes to copy do not change portable or save anything.
```

`CaptureSnapshot()` retains defensive copies of raw, original and observable bytes, plus
retrieved coverage and pending intent. `ToPortableObject(retrievedSections)` imports a
Microsoft descriptor as detached data; callers must supply actual known coverage explicitly.
Copies never transfer credentials, connections, resolvers or entry authority.

`ExportForEdit()` is optional. Edit its real Microsoft `Object`, then call
`ApplyTo(originalPortable)` to reconcile locally and atomically. A success (including no-op)
consumes the session; failure can be corrected and retried only while provenance remains
valid. Dispose releases managed references and never saves or closes a connection.
Call `DirectoryEntry.CommitChanges()` separately when persistence is intended.

Conversions and edit-back can refuse unsupported/lossy data, ambiguous ACL edits or stale
sources. There is no lossy fallback. Names stay names; conversion performs no lookup.
Identity and known AD-rule conversions preserve fields and runtime rule subtype; collections
return independent read-only lists. Custom/unknown rule subclasses are unsupported.

This source package has not been released by the implementation task. Offline tests do not
establish live AD creation defaults, inheritance, privileges or server readback parity.
