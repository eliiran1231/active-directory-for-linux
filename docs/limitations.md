# Practical limitations

[README](../README.md) · [Connection guide](getting-started.md) · [Migration guide](migration.md)

## Connection and authentication

- **Active Directory domains only.** No local-machine accounts, AD LDS
  (`ApplicationDirectory`), or `System.DirectoryServices.ActiveDirectory` APIs.
- **Explicit server required.** There is no domain-controller discovery or
  portable `UserPrincipal.Current`.
- **Linux username/password connections should use LDAPS simple bind.** Negotiate
  delegates to the runtime and GSSAPI configuration; explicit-credential Negotiate
  is not a supported portable Linux path. It never silently falls back to Basic.
- **Certificate trust is your deployment's responsibility.** Use a trusted CA and
  matching server name. `LDAPTLS_REQCERT=never` disables verification process-wide
  for OpenLDAP; it does not establish trust and belongs only in isolated test setups.
- **Password changes need protected transport.** Clear-text password encoding and
  separate password connections/ports are unsupported.

## Windows features that do not carry over

Use `LDAP://` paths. `WinNT://`, `IIS://`, `GC://`, and `LDAPS://` provider prefixes
are unsupported. For ordinary Global Catalog searches, use explicit LDAP port
3268, or 3269 with SSL; this does not enable GC identity translation.

ADSI/COM objects, native search handles, provider `Invoke` calls, query-quota
configuration, and reported mutual-authentication status are unavailable.
`FastBind`, `ReadonlyServer`, and `Delegation` authentication flags are unsupported;
`Signing` and `Sealing` require `Secure`, and `Anonymous` cannot combine with it.
Use supported typed APIs rather than relying on provider-specific behavior.

## Writes and moves

- `DirectoryEntry.CopyTo` is not implemented.
- Moving an existing principal across domains or domain controllers is unsupported,
  including controllers in the same domain. [Two-controller work is deferred](https://github.com/eliiran1231/active-directory-for-linux/issues/230).
- Same-connection moves/renames are supported. A destination using a different
  endpoint, credential, or connection security configuration is not interchangeable
  with the source, even when both can see the object.
- A multi-step `Save` is not a transaction. On uncertain outcomes, verify server
  state before retrying. Renaming an existing object should use the explicit
  `DirectoryEntry.Rename` operation; do not assume assigning `Principal.Name`
  performs a rename.
- Replacing one multi-valued attribute value with an already-present value can be
  rejected by LDAP even when ADSI would accept it. Handle the failure rather than
  assuming duplicate values are ignored.
- Permission edits or Microsoft exports may refuse unusual descriptors to preserve
  unrelated data. Test your permission workflows against your actual directory.

## Search and lifetime

Set a positive page size for large searches or child enumeration; entry enumeration
paging defaults to disabled. Server limits still apply. Asynchronous searches can
queue results faster than you consume them, so `CacheResults=false` is not a
constant-memory guarantee. Bound queries and dispose results promptly.

On Linux, partial referral-chasing modes map to full chasing because the native
client cannot represent partial modes. If searches must stay on one server, select
`ReferralChasingOption.None` explicitly. Identity translation uses stricter,
single-domain rules described in the [identity guide](identity-resolution.md).

Attribute-scoped queries on servers without the native control may issue one
request per referenced entry. This can be slower and have different referral behavior.

Do not share mutable entries/principals across threads without coordinating access.
Keep owner contexts alive and reacquire identity resolvers after rebinding.

## What validation means

The project has offline tests and Windows comparisons, but does not claim complete
Microsoft parity or production security certification. Validate authentication,
referrals, permissions, and write recovery for your deployment before adoption.
