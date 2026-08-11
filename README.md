# AdForLinux — Active Directory for Linux

A Linux copy of Microsoft's directory APIs, built on the cross-platform
`System.DirectoryServices.Protocols`. It lets .NET code that used
`System.DirectoryServices` and `System.DirectoryServices.AccountManagement`
run on Linux against Active Directory.

Same shape as Microsoft, new name (so it does not clash with the real DLL on
Windows).

## Layers

| Our namespace | Copies |
| --- | --- |
| `AdForLinux.DirectoryServices` | `System.DirectoryServices` (`DirectoryEntry`, `DirectorySearcher`) |
| `AdForLinux.DirectoryServices.AccountManagement` | `System.DirectoryServices.AccountManagement` (`PrincipalContext`, `UserPrincipal`, `GroupPrincipal`, `PrincipalSearcher`) |

## Targets

`net8.0` and `net10.0`.

## What is implemented

**Low layer** — `DirectoryEntry` (read properties, write, `CommitChanges`,
`Children.Add`, `DeleteTree`, `Name`, `SchemaClassName`, `Guid`),
`DirectorySearcher` (`Filter`, `SearchScope`, `PropertiesToLoad`, `FindOne`,
`FindAll` with paging, and DN-valued `AttributeScopeQuery` emulation),
`SearchResult`, and the property collections.

`AttributeScopeQuery` uses the server's native ASQ control when available,
preserving server-side filtering and cross-DSA result semantics without one
request per referenced DN. On LDAP servers that do not support that control,
the library validates the attribute's AD schema syntax and falls back to
individual base searches. That fallback is O(number of references) LDAP
requests and referral chasing can differ from native AD ASQ behavior.

The broader `DirectorySearcher` constructor and option surface maps timeouts,
alias/referral behavior, sorting, DirSync, virtual-list-view, tombstone,
extended-DN, property-names-only, and security-mask requests to LDAP protocol
settings and controls. ADSI's `Asynchronous` and `CacheResults` flags are kept
for source compatibility, but searches complete synchronously and results are
materialized before they are returned.

The remaining modern `System.DirectoryServices` low-level public surface is
also present: schema-name collections, `DirectoryEntryConfiguration`, the
Active Directory access-rule/security-descriptor family, and
`DirectoryServicesCOMException`. Security-descriptor reads and writes use the
LDAP security-descriptor control on Windows. The access-rule family derives
from `System.Security.AccessControl`. On current .NET 8 and .NET 10 Linux
runtimes, even binary `SecurityIdentifier` construction and an empty
`DirectoryObjectSecurity` descriptor throw `PlatformNotSupportedException`.
Consequently `DirectoryEntry.ObjectSecurity` keeps an explicit Linux guard;
transporting the LDAP bytes is portable, but constructing the API's required
SID/ACL object model is not.

**High layer** — `PrincipalContext` (server, container, credentials,
`ValidateCredentials`), `UserPrincipal` and `GroupPrincipal`
(`FindByIdentity`, typed extension lookup, `Save`, context-aware save/move,
`Delete`, `Sid` (`SidValue` on Linux), extension attributes, identity equality,
properties), `SetPassword`,
`UnlockAccount`, `ExpirePasswordNow`, `Enabled`, account dates and flags,
`GroupPrincipal.Members` (`Add`/`Remove`/`Contains`), `GetMembers` (direct and
recursive), `GetGroups`, `IsMemberOf`, `GetAuthorizationGroups` (recursive, via
`LDAP_MATCHING_RULE_IN_CHAIN`), `ComputerPrincipal` with mutable service
principal names, and `PrincipalSearcher` query-by-example with wildcards and
advanced date/count comparisons.

### Not supported

- **Serverless binding.** Always pass the domain controller name; there is no
  domain auto-discovery on Linux.
- **Kerberos / Negotiate.** Simple bind over TLS only.
- **`ContextType.Machine` and `ApplicationDirectory`.** Domain only.
- **Cross-domain `Principal.Save(PrincipalContext)` moves.** LDAP supports moves
  within one AD naming context, including when the source and destination
  contexts name different domain controllers for that domain. Moving an
  existing object between AD domains requires ADSI cross-store behavior and
  currently throws `PlatformNotSupportedException` in this Linux port.
- Certificate members and the COM/event surface.
- **Active Directory ACL manipulation on Linux.** The public rule types are
  available for source compatibility, but their required
  `System.Security.AccessControl` base classes are Windows-only in modern .NET.
- **Legacy `DirectoryServicesPermission*` types.** These belonged to .NET
  Framework Code Access Security. They are absent from the modern
  `System.DirectoryServices` reference assembly and CAS is not supported by
  .NET 8/10, so this library does not recreate them.

## Auth

Simple bind (username + password) over LDAPS. A self-signed certificate can be
trusted for tests. No Kerberos yet.

### Skipping a self-signed certificate on Linux

On Linux the LDAP client is native OpenLDAP. To trust a self-signed
certificate, launch the process with:

```
LDAPTLS_REQCERT=never
```

The managed "verify certificate" callback that works on Windows actually breaks
the TLS handshake on Linux. `SkipCertificateCheck` therefore requires
`LDAPTLS_REQCERT=never` to already be set when the process starts; the library
never changes it at runtime because that would weaken certificate verification
for every OpenLDAP connection in the process. `docker-compose.yml` already sets
it for the tests.

## Testing

Two test projects:

- **`tests/AdForLinux.FunctionalTests`** — runs on Linux in Docker against the
  `smblds` Samba AD DC. Checks our clone works.
- **`tests/AdForLinux.DifferentialTests`** — runs on **Windows**. Compares the
  real Microsoft library with our clone, side by side. See its README.

### Run the Linux tests

The `smblds` container must be running (LDAPS on host port 636):

```bash
docker run -d --name smblds -p 389:389 -p 636:636 smblds/smblds:latest
```

Then:

```bash
docker compose up --build --abort-on-container-exit
```

This builds an image with both .NET 8 and .NET 10 and runs the functional
tests on each. 109 tests run on each target, including live coverage against a
real Samba AD domain controller.

The tests create and delete their own objects under `CN=Users`.
