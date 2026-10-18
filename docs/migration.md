# 2. Move to the portable APIs

[Connect](getting-started.md) → Migrate → [Identities and permissions](identity-resolution.md)

## Replace imports, then recompile

| Microsoft import | Portable import |
| --- | --- |
| `System.DirectoryServices` | `AdForLinux.DirectoryServices` |
| `System.DirectoryServices.AccountManagement` | `AdForLinux.DirectoryServices.AccountManagement` |
| Windows SID and account-name types in `System.Security.Principal` | `AdForLinux.Security.Principal` |
| Windows ACL/descriptor classes in `System.Security.AccessControl` | `AdForLinux.Security.AccessControl` |

Update explicit type declarations, aliases, and custom base classes too. Portable
objects are distinct CLR types: you cannot cast them to Microsoft's objects.
Keep shared framework enums such as `AccessControlType` and `AccessControlSections`
in `System.Security.AccessControl`; do not globally replace every `System.Security` import.

## Make connection choices explicit

- Supply a domain controller and container instead of relying on Windows domain
  discovery or `UserPrincipal.Current`.
- For explicit credentials on Linux, choose `SimpleBind | SecureSocketLayer` as
  shown in [getting started](getting-started.md). The default context requests
  Negotiate; it is not an automatic portable username/password login.
- Use `LDAP://dc.example.com/DN` for `DirectoryEntry`, with
  `AuthenticationTypes.SecureSocketsLayer` for LDAPS. `LDAPS://` is not a supported
  provider prefix.
- Replace ADSI `Invoke` calls with supported typed methods, such as
  `UserPrincipal.SetPassword`. Native COM objects and handles have no portable equivalent.

## Start with typed reads and bounded searches

Prefer `FindByIdentity` for exact account lookup and `PrincipalSearcher` for
query-by-example. Query-by-example string fields can interpret wildcards; they
are not a substitute for exact identity lookup.

Use `DirectorySearcher` when you need specific LDAP attributes or filters.
Request only needed attributes, choose an appropriate base/scope, and set paging
and time/size limits explicitly. Never interpolate untrusted values directly into
LDAP filter or distinguished-name syntax: filter escaping and RDN escaping are
different operations.

Dispose contexts, principals, entries, searchers, and result collections with
`using`. Keep their owners alive while consuming results. With `CacheResults=false`,
direct result enumeration is forward-only; `Count` and indexing materialize the
remaining results. After a search error, start a new search rather than treating
previously returned rows as a complete answer.

## Introduce writes on disposable test objects

After validating reads, try one supported change with an account authorized for
that change. For an existing `UserPrincipal` named `user`:

```csharp
user.Description = "Managed by the directory application";
user.Save();
```

With `DirectoryEntry`, attribute edits normally remain cached until
`CommitChanges()`. Setting `UsePropertyCache=false` can send writes immediately.
Password operations on existing accounts take effect immediately and require
protected transport. `SetPassword` on a new, unsaved principal is deferred until
creation; do not treat all password operations as ordinary cached attribute edits.

A sequence of changes is not a directory transaction. A timeout can mean the
server applied a write but its response was lost. Re-read and reconcile the
object before retrying; do not blindly repeat a move, create, or password change.
The library may reject further commits until uncertain state is reconciled.

For permissions, continue with [portable identities and permissions](identity-resolution.md).
Check [limitations](limitations.md) for moves, copies, large searches, and authentication.
