# Optional Microsoft object exports

For Windows consumers on .NET 8/10 that still require Microsoft security objects.
Use the same version of this companion and the core library. Linux applications
do not need it.

```csharp
using AdForLinux.DirectoryServices.MicrosoftInterop;

// portable is an AdForLinux.DirectoryServices.ActiveDirectorySecurity.
System.DirectoryServices.ActiveDirectorySecurity copy = portable.ToMicrosoftObject();
```

`ToMicrosoftObject()` exports supported identities, AD rules and complete verified
descriptors. `ToMicrosoftObjects()` exports collections as independent read-only
lists. Conversion does not look up account names, connect to AD, or save changes.

These are independent copies. There is no Microsoft-to-portable import or apply-back
API. Edit the portable object to make portable directory changes; changing the
exported object will not update it. Incomplete or potentially lossy exports refuse.
`CaptureSnapshot()` provides defensive descriptor data and can export a fresh copy.

See [portable identities and permissions](../../docs/identity-resolution.md) and
[limitations](../../docs/limitations.md).
