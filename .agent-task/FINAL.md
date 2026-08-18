# Issue 41 final

## Implementation

- Added a central Protocols-to-DirectoryServices translator for bind, search, create, update, delete, rename, ranged reads, schema reads, and asynchronous searches.
- Preserved Microsoft distinctions between plain `COMException` connection failures, `DirectoryServicesCOMException` operation responses, and `ArgumentException` malformed filters.
- Added AccountManagement translation to `PrincipalServerDownException`, `PrincipalOperationException`, `PrincipalExistsException`, `PasswordException`, `AuthenticationException`, `UnauthorizedAccessException`, and Microsoft-compatible framework exceptions.
- Applied translation at principal search, identity lookup, property access, save, delete, group lookup/membership, password, default naming-context discovery, and credential-validation boundaries.

## Verification

- Real AD isolated base: `OU=Issue41,OU=AoTesting,DC=adlab,DC=local`.
- Focused functional tests passed on .NET 8 and .NET 10 (16 each).
- Focused Microsoft differential tests passed on .NET 8 and .NET 10 (4 each), covering missing objects, duplicate creates, malformed filters, and unavailable servers.
- Focused Samba tests passed on .NET 8 and .NET 10 (27 each), including write/delete and attribute-scope paths.
- `dotnet build AdForLinux.sln --no-restore` and `git diff --check` passed.

## Known unrelated validation issue

A full Samba run reached an existing `UserPrincipalWriteTests.Delete_removes_the_user` assertion that reads `DistinguishedName` after deletion; current `main` now throws for deleted-principal property access. Focused issue-41 suites passed.