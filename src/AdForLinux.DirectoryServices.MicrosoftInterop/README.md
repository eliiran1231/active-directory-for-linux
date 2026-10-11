# AdForLinux.DirectoryServices.MicrosoftInterop

Optional Windows-only, **export-only** conversions for .NET 8 and .NET 10. The core and
AccountManagement packages remain independent of this package. Use the exact matching
core package version.

```csharp
using AdForLinux.DirectoryServices.MicrosoftInterop;

// portable is an AdForLinux.DirectoryServices.ActiveDirectorySecurity.
System.DirectoryServices.ActiveDirectorySecurity copy = portable.ToMicrosoftObject();
// Changes to copy do not change portable or save anything.
```

`ToMicrosoftObject()` exports identities, known AD rules and complete verified descriptors.
`ToMicrosoftObjects()` exports identity/rule collections as independent read-only lists,
preserving order and duplicates. Names stay names; conversion performs no identity lookup.
Unknown/custom rule subclasses and conversions that change fields are rejected.

`CaptureSnapshot()` retains defensive copies of raw, original and observable bytes, plus
retrieved coverage and pending intent. Its `ToMicrosoftObject()` creates a fresh independent
Microsoft descriptor. Incomplete coverage, unexplained storage and unverified or lossy
projection refuse; there is no lossy fallback. Raw/write state remains separate from the
observable export. Copies and snapshots never retain credentials, connections, resolvers,
an owning entry or authority to publish edits.

There are no Microsoft-to-portable import APIs, edit sessions or apply-back operations.
Edit portable objects through their portable APIs. Exported Microsoft objects can be changed
independently, but those changes never flow back into portable state or directory writes.

This source package has not been released by the implementation task. Offline tests do not
establish live AD creation defaults, inheritance, privileges or server readback parity.
