# 3. Use portable identities and permissions

[Connect](getting-started.md) → [Migrate](migration.md) → Identities and permissions

## Use portable types end to end

`Principal.Sid` returns `AdForLinux.Security.Principal.SecurityIdentifier` and
works on Linux. `SidValue` is a string convenience. `DirectoryEntry.ObjectSecurity`
returns a portable `ActiveDirectorySecurity`; use portable rules and identity
types when reading or changing its permissions.

Microsoft security objects are not interchangeable with these types. Shared
framework enums such as `AccessControlType` remain in `System.Security.AccessControl`.

## Translate account names with an explicit owner

```csharp
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;

// entry is an existing caller-owned, authenticated DirectoryEntry.
var resolver = DirectoryIdentityResolver.ForEntry(entry);
var sid = (SecurityIdentifier)resolver.Translate(
    new NTAccount("EXAMPLE", "alice"), typeof(SecurityIdentifier));

// Or use an existing PrincipalContext:
var contextResolver = context.CreateIdentityResolver();
var name = (NTAccount)contextResolver.Translate(sid, typeof(NTAccount));
```

Creating a resolver performs no lookup. Keep its entry/context alive. Reacquire
it after closing or rebinding the owner, refreshing the entry's descriptor, or
otherwise invalidating its binding. Returned identities are data: they do not
carry credentials or inherit that resolver through their own `Translate` method.

A single missing identity throws `IdentityNotMappedException`. For collections,
`resolver.Translate(identities, targetType)` leaves unmapped values in place;
use `forceSuccess: true` if every identity must resolve. Connection, timeout and
lifetime failures still throw, so they cannot be mistaken for a missing account.

Lookup is scoped to the owner's verified domain. Name-to-SID lookup requires
explicit authenticated credentials. Global Catalog and cross-forest/trust routing
are not supported by this helper.

## Change permissions without discarding unrelated data

Read `entry.ObjectSecurity`, edit it using the portable rule APIs, then use
`entry.CommitChanges()` to persist cached changes. Request the security sections
you need through `entry.Options.SecurityMasks`; reading or writing the SACL may
require additional directory privileges.

The library preserves unrelated descriptor data. An edit or export can be refused
when it cannot safely preserve an unusual descriptor. Do not work around such a
refusal by replacing the entire ACL with an empty or newly constructed descriptor:
that can change permissions unrelated to your intended edit.

Validate permission changes on a disposable object and read them back before
rolling them out. Offline compatibility tests do not establish your server's
inheritance behavior, privileges, or creation defaults.

## If a Windows consumer still needs Microsoft objects

The optional Windows-only [MicrosoftInterop companion](../src/AdForLinux.DirectoryServices.MicrosoftInterop/README.md)
exports independent copies. It cannot import Microsoft edits or apply them back.
Keep directory edits on the portable side and export only at that integration boundary.

[Compiled identity example](examples/IdentityResolverUsage.cs) · [Limitations](limitations.md)
