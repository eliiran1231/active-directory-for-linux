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

**High layer** — `PrincipalContext` (server, container, credentials,
`ValidateCredentials`), `UserPrincipal` and `GroupPrincipal`
(`FindByIdentity`, `Save`, `Delete`, properties), `SetPassword`,
`UnlockAccount`, `ExpirePasswordNow`, `Enabled`, account dates and flags,
`GroupPrincipal.Members` (`Add`/`Remove`/`Contains`), `GetMembers` (direct and
recursive), `GetGroups`, `GetAuthorizationGroups` (recursive, via
`LDAP_MATCHING_RULE_IN_CHAIN`), and `PrincipalSearcher` query-by-example with
wildcards.

### Not supported

- **Serverless binding.** Always pass the domain controller name; there is no
  domain auto-discovery on Linux.
- **Kerberos / Negotiate.** Simple bind over TLS only.
- **`ContextType.Machine` and `ApplicationDirectory`.** Domain only.
- `ComputerPrincipal`, certificate members, and the COM/event surface.

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
tests on each. 87 tests, all against a real Samba AD domain controller.

The tests create and delete their own objects under `CN=Users`.
