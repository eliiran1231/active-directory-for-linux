# AdForLinux

Active Directory access for .NET on Linux, with familiar `DirectoryEntry`,
`DirectorySearcher`, and principal APIs. Targets **.NET 8 and .NET 10**.

Use it to read and update directory objects, manage users and groups, and work
with portable SIDs and access rules. It uses LDAP rather than Windows ADSI.
Existing Microsoft code needs namespace and security-type changes, then recompilation.

## Start here

1. **[Connect and read a user](docs/getting-started.md)** — build from source,
   configure LDAPS, and make your first read-only query.
2. **[Move your application to the portable APIs](docs/migration.md)** — replace
   Windows assumptions, choose the right API, and introduce writes deliberately.
3. **[Use portable identities and permissions](docs/identity-resolution.md)** —
   translate names explicitly and handle directory security without Windows types.

Read the **[practical limitations](docs/limitations.md)** before adopting it.
Domain-controller discovery, ADSI/COM integration, and cross-controller moves
are not provided. An API having a familiar name does not guarantee every
Microsoft scenario is supported.

## Choose an API

| Task | Namespace |
| --- | --- |
| Users, groups, computers and membership | `AdForLinux.DirectoryServices.AccountManagement` |
| LDAP searches, attributes and directory entries | `AdForLinux.DirectoryServices` |
| Portable SIDs and account names | `AdForLinux.Security.Principal` |
| Portable permission rules and descriptors | `AdForLinux.Security.AccessControl` |

For explicit credentials on Linux, start with **simple bind over LDAPS and a
trusted server certificate**. Keep credentials outside source code.

Contributing? See [build and test guidance](CONTRIBUTING.md).
