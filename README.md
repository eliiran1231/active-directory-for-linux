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
as observable execution options: ordinary asynchronous `FindAll` searches use
Protocols partial results so enumeration can expose entries while the server is
still searching, and `CacheResults=false` makes direct enumeration forward-only.
Indexing, `Count`, `Contains`, and copy operations explicitly materialize the
remaining results, matching the shape of Microsoft's collection operations.
`FindOne` remains synchronous, and attribute-scoped queries are materialized
because their portable fallback can require multiple dependent LDAP requests.

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
properties), `SetPassword`, `ChangePassword`, `UnlockAccount`,
`ExpirePasswordNow`, `RefreshExpiredPassword`, `Enabled`, account dates and
flags, permitted logon times/workstations, X.509 account certificates, and the
portable `UserCannotChangePassword` change-password DACL mapping,
`GroupPrincipal.Members` (`Add`/`Remove`/`Contains`), `GetMembers` (direct and
recursive), `GetGroups`, `IsMemberOf`, `GetAuthorizationGroups` (directory-backed
authorization groups via `tokenGroups`, with a matching-rule fallback), `ComputerPrincipal` with mutable service
principal names, and `PrincipalSearcher` query-by-example with wildcards and
advanced date/count comparisons.

### Not supported

- **Non-LDAP ADSI providers and `System.DirectoryServices.ActiveDirectory`.**
  This project implements the LDAP-backed `System.DirectoryServices` and
  `AccountManagement` APIs; it does not implement the `WinNT://` or `IIS://`
  providers, or the separate `System.DirectoryServices.ActiveDirectory`
  namespace. Unsupported provider prefixes throw `PlatformNotSupportedException`
  instead of being treated as LDAP server names. `LDAPS://` is not an ADSI
  provider path: use `LDAP://` with `AuthenticationTypes.SecureSocketsLayer`,
  or an explicit LDAP port `636`.
- **The `GC://` ADSI provider prefix.** Global Catalog queries can use AD's LDAP
  Global Catalog endpoints explicitly as `LDAP://server:3268/...`, or port
  `3269` together with `AuthenticationTypes.SecureSocketsLayer`. The library
  does not map `GC://` implicitly because that ADSI provider also supplies
  provider-specific discovery and default-root behavior that a path rewrite
  cannot preserve. `GC://` therefore throws `PlatformNotSupportedException`.
- **Serverless binding.** Always pass the domain controller name; there is no
  domain auto-discovery on Linux. For the same reason, `UserPrincipal.Current`
  is present for source compatibility but throws `InvalidOperationException`;
  use an explicit `PrincipalContext` and `FindByIdentity` instead.
- **Portable explicit-credential Negotiate on Linux.** The library maps
  `AuthenticationTypes.Secure` to the runtime's Negotiate implementation and
  never falls back to Basic. Current .NET 8/10 Linux
  `System.DirectoryServices.Protocols` rejects an explicit credential at bind
  time even with `gss-ntlmssp` installed; default-credential GSSAPI behavior is
  runtime and machine configuration dependent.
- **`DirectoryEntry` authentication flags.** Supported `AuthenticationTypes`
  values are `None`, `Secure`, `Encryption`/`SecureSocketsLayer`, `Anonymous`,
  `ServerBind`, `Signing`, and `Sealing`. `Signing` and `Sealing` require
  `Secure`, while `Anonymous` cannot be combined with `Secure`. `FastBind`,
  `ReadonlyServer`, `Delegation`, and unknown flag values have no faithful
  `System.DirectoryServices.Protocols` equivalent and throw
  `PlatformNotSupportedException` when the entry attempts to bind.
- **Invalid `AuthenticationTypes` combinations.** `Anonymous` cannot be
  combined with `Secure`, and `Signing` or `Sealing` requires `Secure`. On
  Linux, `DirectoryEntry` rejects these combinations with
  `PlatformNotSupportedException` before sending an LDAP request. A Windows
  real-AD comparison confirmed that the LDAP ADSI provider enforces the same
  validity rules, although it reports native COM/directory-service errors
  instead of `PlatformNotSupportedException`.
- **`ContextType.Machine` and `ApplicationDirectory`.** Domain only.
- **Cross-domain `Principal.Save(PrincipalContext)` moves.** LDAP supports moves
  within one AD naming context, including when the source and destination
  contexts name different domain controllers for that domain. Moving an
  existing object between AD domains requires ADSI cross-store behavior and
  currently throws `PlatformNotSupportedException` in this Linux port.
- **Cross-connection `DirectoryEntry.MoveTo` moves.** LDAP `ModifyDN` is sent on
  the source connection and cannot honor a destination entry that uses another
  server, port, TLS mode, authentication type, credential, or connection
  security option. Such moves throw `PlatformNotSupportedException` before an
  LDAP request is sent; same-connection moves and renames remain supported.
- **Password transport options.** `DirectoryEntryConfiguration.PasswordPort`
  stores nondefault values, and `PasswordEncoding` accepts both defined enum
  values, matching Microsoft's setter/getter behavior. Portable password
  operations use the entry's existing connection; separate password connections
  and clear-text encoding are unsupported. Requesting a port other than `636`
  or `PasswordEncodingClear` causes password reset/change operations to throw
  `PlatformNotSupportedException` before binding or sending the password request.
  Setting these options does not enable ADSI password calls through `Invoke`.
- **`DirectoryEntry(object)` and `DirectoryEntry.NativeObject`.** Microsoft's
  constructor and property accept or expose an underlying ADSI/COM object,
  which has no Linux equivalent. The APIs are retained for source compatibility,
  but the constructor cannot wrap an ADSI object and throws
  `PlatformNotSupportedException` for a valid ADSI object; null and non-IADs inputs
  throw `ArgumentException` without a parameter name. Accessing `NativeObject`
  throws `PlatformNotSupportedException`. Create
  entries from an `LDAP://host/DN` path instead.
- **`SearchResultCollection.Handle`.** Microsoft exposes the native ADSI
  `IDirectorySearch::ExecuteSearch` handle. Protocol-based LDAP searches have no
  equivalent stable native handle, so accessing this property throws
  `PlatformNotSupportedException` rather than returning a fabricated zero value.
- **ADSI provider invocation through `DirectoryEntry.Invoke`, `InvokeGet`, and
  `InvokeSet`.** These methods require an underlying ADSI/COM provider object,
  which protocol-based LDAP does not expose. All three methods therefore throw
  `PlatformNotSupportedException` on Linux.
- `DirectoryEntry` certificate members and the remaining COM/event surface.
- **Active Directory ACL manipulation on Linux.** The public rule types are
  available for source compatibility, but their required
  `System.Security.AccessControl` base classes are Windows-only in modern .NET.
- **`DirectoryEntryConfiguration.SetUserNameQueryQuota`.** This is an ADSI
  provider option for returning quota information for a named security
  principal. LDAP has no equivalent interoperable option or control, so there
  is no portable fallback; this method throws `PlatformNotSupportedException`.
- **`DirectoryEntryConfiguration.IsMutuallyAuthenticated`.** The LDAP bind is
  performed before this member returns, but `System.DirectoryServices.Protocols`
  exposes neither the negotiated SSPI/GSSAPI mutual-authentication flag nor an
  equivalent portable status. The method therefore throws
  `PlatformNotSupportedException` instead of fabricating `false`. This applies
  to both default-credential Negotiate and explicit-credential binds.
- **Legacy `DirectoryServicesPermission*` types.** These belonged to .NET
  Framework Code Access Security. They are absent from the modern
  `System.DirectoryServices` reference assembly and CAS is not supported by
  .NET 8/10, so this library does not recreate them.

## Auth

Simple bind (username + password) over LDAPS is the portable explicit-credential
path. Negotiate requests are passed through to `System.DirectoryServices.Protocols`
without a Basic fallback; support depends on the platform runtime and GSSAPI
configuration. A self-signed certificate can be trusted for tests.

Password operations require an SSL-protected LDAP connection. Setting
`DirectoryEntryConfiguration.PasswordEncoding` to `PasswordEncodingClear`
stores the preference but does not enable clear-text password operations;
password reset/change operations throw `PlatformNotSupportedException` when
invoked with that preference.

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

### Validated principal collection compatibility

[Real-AD workflow 36900315548](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36900315548)
validated the [#185](https://github.com/eliiran1231/active-directory-for-linux/issues/185)
fix on October 1, 2026: **585/585 differential cases passed on each of
`net8.0-windows` and `net10.0-windows`**, with no failures or skipped cases.
This includes all 18 traversal/copy regressions and all 567 other comparisons.
Artifact upload and test-OU cleanup also succeeded.

`PrincipalValueCollection<T>` enumerators preserve their cached `Current` value
after the collection shrinks and reject `Current` after exhaustion, even if
values are appended. Both `CopyTo` APIs reject insufficient destination space with an
`ArgumentException` without a parameter name, matching Microsoft. The existing
Microsoft-oracle assertions were retained unchanged. Local checks also passed
all 63 offline principal-collection comparisons and all 12 functional
principal-collection tests on each of .NET 8 and .NET 10.

### Validated CopyTo and mutable logon-hours findings

[Real-AD workflow 36903609971](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36903609971)
validated the [#187](https://github.com/eliiran1231/active-directory-for-linux/issues/187)
fix on October 1, 2026: **597/597 differential cases passed on each of
`net8.0-windows` and `net10.0-windows`**, with no failures or skipped cases.
All 12 focused cases and the 585 other comparisons passed; artifact upload
and test-OU cleanup succeeded. The existing Microsoft-oracle tests are unchanged.

Non-generic `CopyTo` checks element compatibility while copying, so an empty
collection accepts an incompatible destination element type and a nonempty
collection throws the same exception as Microsoft, preserving partial writes.
In-place `PermittedLogonTimes` edits now persist through successive saves on
both newly saved and reloaded principals. Tracking belongs to the principal;
low-level `DirectoryEntry` cache invalidation is unchanged.

The earlier .NET 10 SourceLink allocation failure did not recur in this run:
build and full test execution succeeded without build configuration changes.
Its underlying cause remains unconfirmed. Local validation also passed 96
offline collection comparisons and 49 relevant functional checks on each of
.NET 8 and .NET 10.

### Validated group constructor and member enumerator findings

[Real-AD workflow 36907164882](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36907164882)
validated the [#189](https://github.com/eliiran1231/active-directory-for-linux/issues/189)
fix on October 1, 2026: **614/614 differential cases passed on each of
`net8.0-windows` and `net10.0-windows`**, with no failures or skipped cases.
All 17 focused cases and the 597 other comparisons passed; artifact upload
and test-OU cleanup succeeded. The existing Microsoft-oracle tests are unchanged.

Both public `GroupPrincipal` constructors reject a null context with an
`ArgumentException` without a parameter name, before assigning the group name.
Member enumerators reject `Current` before traversal and after exhaustion,
support `Reset`, and detect collection changes on `MoveNext` and `Reset`,
including clearing an empty collection after exhaustion. Enumerator and group
disposal checks remain intact. Local validation also passed all four offline
constructor comparisons and 27 functional compatibility/disposal checks on
each of .NET 8 and .NET 10.

### Run the Linux tests

The `smblds` container must be running (LDAPS on host port 636):

```bash
docker run -d --name smblds -p 389:389 -p 636:636 smblds/smblds:latest
```

Then:

```bash
docker compose up --build --abort-on-container-exit
```

This builds an image with both .NET 8 and .NET 10 and runs the full functional
suite on each target, including live coverage against a real Samba AD domain
controller.

The tests create and delete their own objects under `CN=Users`.
