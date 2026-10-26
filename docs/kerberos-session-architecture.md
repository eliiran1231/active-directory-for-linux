# Bound sessions and Kerberos policy

This implementation keeps the existing public APIs and Protocols behavior. It supplies a
native OpenLDAP/MIT transport and executable recording demonstrations, but **production native
authentication and ambient Kerberos reuse remain disabled**. No real credentials or directory
authentication were used to validate this work. The branch starts at PR235 head
`3efcdf45e2d6d2f676e73abbe86c8155007f29a8` and does not change that completed PR.

## Run offline

Use a .NET 10 SDK with the selected runtime installed. Restore/build prerequisites first:

```sh
dotnet build AdForLinux.sln --configuration Release
bash docs/examples/kerberos-session-demo.sh net8.0
bash docs/examples/kerberos-session-demo.sh net10.0
bash tests/native-session/run-demo.sh
bash tests/native-session/run-managed-demo.sh net8.0
bash tests/native-session/run-managed-demo.sh net10.0
ADFL_NATIVE_OUT=/tmp/adfl-native-sanitized \
  ADFL_NATIVE_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  bash tests/native-session/run-demo.sh
```

`ADFL_DEMO_DOTNET` selects a dotnet executable. The managed demonstrations use the permanent
offline guard. Native tests compile the actual bridge against installed OpenLDAP/MIT development
libraries, Cyrus runtime, and a C11 compiler; they run recording dependencies and a metadata-only
probe. No package is installed or downloaded. The source-reviewed versions are MIT 1.21.3,
OpenLDAP 2.6.8/2.6.10 and Cyrus 2.1.28. Version agreement is necessary, not authentication proof.
MIT is checked by pkg-config at build time, not attested at runtime. If Cyrus development headers
are absent, the runner uses the licensed upstream headers in `tests/native-session/headers`;
`ADFL_SASL_INCLUDE` can select another header root.

The demonstrations traverse actual managed/C ABI orchestration, public discovery in both
namespaces, streaming/buffered searches, public property loading and mutation dispatch. Fake
native dependencies establish lifetime, routing and outcome behavior; they do not establish
real MIT cache stability, plugin loading, network deadlines or successful authentication.

## Ownership and freshness

`LdapAuthenticationSource` snapshots a connection recipe and owns binding provenance/policy.
`BoundLdapSession` owns an authenticated resource; `LdapConnectionProvider.Session` exclusively
leases it. Clones copy recipes, never connections. Pool keys retain endpoint, credentials,
transport and referral settings. Connection failures retire resources; sent operations are
never replayed. Legacy raw getters cannot retain platform-authentication sessions.

The native operation owner resolves one target-specific authority after atomic admission and
before its first bind. Same-target paired sessions consume that owner; the final member closes
LDAP/SASL before releasing GSS and cache resources. Impossible admission performs no resolution.
Cross-target groups require separate target resolution. Scope IDs, cache paths and usernames
are provenance, not proof that authority was captured or consumed.

| Source/backend | Ordinary reuse |
| --- | --- |
| Explicit Basic, no referrals | Compatible established session |
| Explicit Basic, Linux referrals | Existing policy, including anonymous referral children |
| Explicit Basic, Windows referrals | Fresh except the existing scoped read path |
| Ambient/explicit Negotiate | Fresh; native authority/reuse proof unavailable |
| Anonymous or other mechanisms | Fresh |
| Credential validation | Always fresh |

`CompatibleEstablishedSession` does not promise fresh-bind success/failure equivalence after
revocation, disappearance or authorization-data changes. Same-authority ticket renewal need
not retire a session merely because bytes changed. Current target-specific identity must be
resolved at operation entry; unknown compatibility stays fresh. Epochs implement controlled
invalidation and cannot detect arbitrary external kinit. A fresh Protocols fallback can still
report unsupported authentication; this code does not pretend otherwise.

Both namespaces derive the same recipe, for example DirectoryEntry with Secure/Signing/Sealing
and PrincipalContext with Negotiate/Signing/Sealing. Their `.invalid` recording examples are
executable in the demonstrations; they are not instructions to authenticate.

## Request and result contract

Internal transports preserve owned binary entries, references, terminal result codes, matched
DNs, diagnostics, referrals and controls. No private Protocols handle or reflection is used.
The bridge delegates LDAP, GSSAPI and SASL security framing to their native libraries.

Streaming cursors retain one lease across opaque paging cookies and ordered `LDAP_MSG_ONE`
events. DirectorySearcher retains an atomic search/schema pair through its producer lifecycle.
Asynchronous searches publish partial entries; non-asynchronous streaming buffers each page
until a successful or size-limited terminal response. Cached FindAll and FindOne drain the
cursor, close it, then materialize using the same idle session; capacity one suffices. FindOne
materializes only its first entry after consuming the terminal response. Cached searches
preserve duplicates and do not return a partial collection on later failure.

The neutral producer uses a total deadline across admission, cursor work and schema conversion.
Each open/read/page transition receives the remaining budget. Existing Protocols timing stays
unchanged. Schema caches belong to the resource; scalar/binary/ranged/types-only materialization
and binding-authority checks are shared. Returned results retain no borrowed schema transport.
Unfinished or uncertain cursors retire their session; cleanup never starts an implicit search.

Add, Modify, Delete and ModifyDN share a native write coordinator using public asynchronous
libldap APIs. Ordered values, empty Add/Modify lists, a missing value list, zero-length binary
values, and nullable rename parents retain their meanings. A callback marks possible submission
immediately before libldap dispatch, after allocation. `NotSent` leaves intent retryable;
`Indeterminate` requires reconciliation; `Completed` preserves the full terminal envelope even
for LDAP rejection or late cancellation. Successful commits still require checked local
publication. No outcome causes automatic replay or backend switching.

Server controls share one allocator across buffered searches, cursor pages and all writes.
Cursor copies survive caller-buffer disposal. Adapter-owned paging controls cannot collide
with caller controls. Explicit empty server/client arrays suppress inherited handle defaults.
Absent and present-empty values remain distinct internally; the public DirectoryControl mapping
retains Protocols' empty-to-absent behavior. Protocols refuses internal present-empty controls
it cannot represent. Response criticality and value presence are independent flags.

Default property security-mask controls use a managed BER SEQUENCE/INTEGER encoder for the exact
public SecurityDescriptorFlagControl type; subclasses retain their virtual encoding behavior.
Native ABI version 2 is checked before real resolution/bind and request dispatch. A mismatch
cannot silently discard the new control fields. ABI agreement is not authentication proof.
DirectorySearcher still rejects unimplemented control-response state, aliases and server limits;
generic control transport does not implement those public semantics.

## Binding implementation and enablement boundary

The source implementation selects a cache using the exact target hostname and MIT `krb5_cc_select`.
It falls back to the default cache only when selection supplied neither a cache nor an
authoritative principal. A selected principal with missing credentials fails. Acquisition
names the principal/cache explicitly, requests Kerberos, and supplies an owned verified-empty
MEMORY client keytab; it does not mutate process environment or inspect user stores in tests.

The binder installs the owned GSS handle in OpenLDAP's supported SASL interaction callback
after SASL context creation. Proving that this callback precedes initiation in the loaded
plugin composition remains an activation requirement. The option receives the handle value,
not its address. The
first exact-host connection is admitted; automatic reconnect/referral children are vetoed.
Requested referrals, TLS or unrepresentable protection policy are refused rather than weakened.
No in-place rebind is used. Native cleanup orders LDAP/SASL before GSS release.

Version strings cannot prove which plugin initiates GSS or whether the callback ran first.
A post-bind check cannot undo wrong-identity authentication. Consequently
`authority_binding_enforced=0`, `compatible_session_reuse=0`, and managed
`SupportsFacadeRequests=false` are hard gates with no environment/feature-flag override.
Recording dependency injection exists only in the separate test library.

The minimal pinned Cyrus patch requires the consumed `client_creds` after initial interaction
but before *any* client credential fallback or GSS initiation, including the TLS/no-CI branch:

```sh
python3 tests/native-session/verify-plugin-guard.py /path/to/cyrus-sasl-2.1.28/plugins/gssapi.c
python3 tests/native-session/verify-plugin-guard.py /path/to/cyrus-sasl-2.1.28/plugins/gssapi.c --sanitize
```

This verifies the source hash, applies the patch and runs an extracted-source ordering harness.
It does not verify a built plugin or deployment. Activation requires controlled dependency
composition from Cyrus initialization onward; a plugin name, GETPATH/VERIFYFILE callback or
version string cannot retrofit an already initialized host-global instance. A separately owned
helper process with a pinned private dependency/plugin closure is the proposed packaging
boundary; it is not implemented or attested here.

Remaining proofs/work include mutable-cache authority compatibility, controlled native
composition, hard socket-write deadlines, requested referral/TLS semantics, paged total-size
limits, advanced search response-state handling, and remaining raw Protocols consumers.
`LDAP_OPT_NETWORK_TIMEOUT` bounds connection setup, not arbitrary blocked sends. Cancellation
and bounded polling are cooperative; a complete hard native deadline is not claimed. Windows
retains its existing backend; WinLDAP does not accept an arbitrary SSPI credential handle.

## Primary source basis

- [MIT GSSAPI/cache semantics](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html)
- [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html) and [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513.html)
- [OpenLDAP SASL integration](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/cyrus.c), [connection veto](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/os-ip.c), [controls](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/controls.c), [Add](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/add.c), [Modify](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/modify.c)
- [Cyrus 2.1.28 GSSAPI](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/plugins/gssapi.c)
- [Protocols 9 control marshaling](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapConnection.cs)
- [MS-ADTS security-mask control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0)

The borrowed entry-search dispatcher also serves schema lookup, immediate binary security
reads and ranged attributes. Stock requests retain their original object, controls, exception
path, raw value conversions and connection-keyed schema cache. Neutral ranges use one lease and
a total deadline across all chunks and schema reads. Range-name priority/progress checks and
strict stock binary-security validation are preserved; partial data is not reconciliation proof.
