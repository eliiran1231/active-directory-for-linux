# Differential tests (run these on Windows)

These tests compare **the real Microsoft library** with **our Linux clone**.

They cannot run on Linux, because `System.DirectoryServices` and
`System.DirectoryServices.AccountManagement` only work on Windows. So this
project is **not** part of the Linux/Docker test run. You run it yourself on a
Windows machine.

> The project *compiles* on Linux (that is checked in CI-style by building it),
> but every Microsoft call throws `PlatformNotSupportedException` at runtime
> there. Windows is required to actually run it.

## What they do

Each test runs the *same* operation twice:

1. with Microsoft's library (aliased as `Ms` in the code)
2. with our library (aliased as `Ours`)

then compares the answers. Because the two libraries use different namespaces,
both can be referenced at the same time with no clash.

Differences are collected and reported together, so one failure shows you every
property that disagreed, not just the first.

### What is covered

| File | Compares |
| --- | --- |
| `UserPrincipalComparisonTests` | user properties, account state (dates, flags, lockout), `FindByIdentity`, date-based finders, `ValidateCredentials` |
| `GroupPrincipalComparisonTests` | group properties, `Members`, `GetMembers`, `GetGroups`, `GetAuthorizationGroups` |
| `DirectoryEntryComparisonTests` | `DirectoryEntry` properties, `DirectorySearcher` `FindOne`/`FindAll` |
| `DirectoryEntryCopyComparisonTests` | real-AD `CopyTo` matrix for user, group, computer, and OU objects, both overloads, identity/security/source state, and failure results |
| `ObjectSecurityComparisonTests` | live DACL round trips, partial `SecurityMasks`, and cached versus immediate `ObjectSecurity` writes |
| `PrincipalSearcherComparisonTests` | query-by-example search, including wildcards |
| `PublicApiSurfaceComparisonTests` | every exported type in the two claimed namespaces, including declared members, modifiers, accessors, contract attributes, generic constraints, and usable nullable metadata |

### Reflection-oracle scope and allowlist

`PublicApiSurfaceComparisonTests` compares every exported type whose namespace is
exactly one of the following pairs:

- `System.DirectoryServices` and `AdForLinux.DirectoryServices`
- `System.DirectoryServices.AccountManagement` and
  `AdForLinux.DirectoryServices.AccountManagement`

The exact-namespace check deliberately excludes
`System.DirectoryServices.ActiveDirectory`; AdForLinux does not currently claim
that API. It also excludes the implementation-only `AdForLinux.DirectoryServices.Ldap`
namespace.

For each claimed type, the oracle compares type kind, visibility, base type,
interfaces, abstract/sealed modifiers, generic constraints, and every declared
externally visible constructor, method, property, event, and field. Property and
event accessors are inspected with non-public reflection so a private or protected
accessor change is visible. Contract custom attributes and DirectoryServices
nullable metadata are included. The Microsoft AccountManagement reference
assembly reports all nullable states as `Unknown`, so nullable comparison for
that namespace is intentionally disabled until the reference provides usable
metadata.

Intentional differences live in the `IntentionalDifferences` set in the test.
Entries are exact descriptors rather than member-name wildcards, and stale
entries fail the test. The current groups are:

- Linux/LDAP conveniences: `DirectoryEntry.DistinguishedName`, portable SID and
  connection properties, and `PrincipalSearcher.GetLdapFilter`.
- generic enumeration/readonly-list conveniences used by Linux and LINQ callers.
- three documented metadata-only differences: the Windows designer converter,
  `DirectoryEntry.Options` nullability, and normalized `DirectorySearcher.Filter`
  getter nullability.

Any new extension, including a future LINQ API, therefore requires an explicit,
reviewable allowlist entry; unrelated public-surface drift fails with side-by-side
Microsoft/AdForLinux descriptors.

## How to run

1. Use a Windows machine that can reach a domain controller.
2. Set these environment variables (PowerShell):

   ```powershell
   $env:AD_HOST    = "your-dc.example.com"
   $env:AD_PORT    = "636"
   $env:AD_USE_TLS = "true"
   $env:AD_BIND_DN = "administrator@example.com"
   $env:AD_BIND_PW = "yourPassword"
   $env:AD_BASE_DN = "DC=example,DC=com"
   ```

   Set `AD_USE_TLS=false` with port 389 for a disposable test DC that permits
   simple LDAP binds. The ObjectSecurity fixture does not set a password, so it
   can exercise Microsoft and AdForLinux behavior without requiring LDAPS.

3. Run:

   ```powershell
   dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows
   dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows
   ```

The tests create their own temporary user and two groups under `CN=Users`, and
delete them at the end.

## `DirectoryEntry.CopyTo` protocol limitation

The real-AD matrix found that Microsoft's Windows LDAP ADSI provider returns
`E_NOTIMPL` (`NotImplementedException`, HRESULT `0x80004001`) for both
`CopyTo(parent)` and `CopyTo(parent, newName)`. This was observed for valid user,
group, computer, and organizational-unit sources and valid destination
containers. No destination object is created, and the source DN, object class,
attributes, identity fields, account state, and security descriptor remain
unchanged. Consequently, copied/defaulted attributes, a resulting name/DN, and
copied security are not applicable; there is no Microsoft LDAP copy result to
reproduce.

`System.DirectoryServices.DirectoryEntry.CopyTo` delegates to ADSI
`IADsContainer.CopyHere`. LDAP itself defines no server-side copy operation. A
portable read-plus-Add emulation cannot reproduce server decisions for schema
defaults, object identity and uniqueness, SPN/DNS fields, account state,
security descriptor inheritance, or transactional/subtree behavior. The
library therefore matches the observed LDAP provider by throwing
`NotImplementedException` instead of creating a materially different object.

## Things to know before you read a failure

- **The account running the tests needs rights** to create and delete objects in
  `CN=Users`, to set a password, and to read the SACL for the disposable ACL
  test object. The SACL read is required to prove that a DACL-only update does not
  replace security-descriptor sections that were not requested.
- **`GetAuthorizationGroups` has two independent checks.** The differential
  comparison verifies that every directory-backed group we return also appears
  in Microsoft's answer. The Linux functional suite separately compares the
  result exactly with every `tokenGroups` SID that resolves to a group object;
  well-known SIDs without directory objects are intentionally outside that LDAP
  result.
- **Times.** We return `DateTime` values in UTC (`Kind = Utc`), which is what
  `DateTime.FromFileTimeUtc` gives, matching Microsoft's own conversion. The
  comparison compares the instant rather than the `Kind`, so a difference here
  means a real difference in the moment, not just the kind.
- **Self-signed certificates.** Against a test server with a self-signed
  certificate, Windows may refuse the TLS connection for *both* libraries. Use a
  DC with a trusted certificate, or install the test CA on the Windows machine.
