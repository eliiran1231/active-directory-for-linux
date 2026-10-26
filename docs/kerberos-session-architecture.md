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
Native ABI version 3 is checked before real resolution/bind and request dispatch. A mismatch
cannot silently discard the new control fields. ABI agreement is not authentication proof.
The native search adapter explicitly pins per-handle aliases to Never and server time limit
to zero before every send; it does not inherit handle defaults. DirectorySearcher still rejects
unimplemented control-response state, aliases and server limits;
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
helper process with a pinned private dependency/plugin closure is the selected packaging
boundary. The process/IPC boundary and explicit source-recipe transfer are executable; the full
private dependency closure and live authority semantics are not yet proven. The production host refuses
before credential resolution; only the separate demo host injects recording dependencies.

Run the actual exec/IPC/native-dispatch demonstration (Linux with pidfd and glibc closefrom):

```sh
ADFL_DEMO_DOTNET=/path/to/dotnet bash tests/native-session/run-process-demo.sh net8.0
```

`NativeLdapWorkerPool` separates worker ownership from an exclusive operation lease. One
worker owns both search/schema sessions and cursor pages; current policy retires it after
one operation. Future reuse still needs target-aware authority compatibility. The libc-only
supervisor starts an exact executable over a private socketpair with explicit environment,
closed inherited descriptors and no shell. The child supplies a kernel-verified pidfd before
backend initialization. Retirement signals that retained handle and reaps asynchronously;
caller timeout does not wait for blocked IPC, native sends, exit or drains. Dying workers
retain their capacity slot. An unverifiable startup remains quarantined: this implementation
cannot promise bounded OS cleanup, and never falls back to rediscovering a numeric PID.
Windows identity transfer is unsupported; ordinary process creation does not transfer thread
impersonation. The helper environment deliberately disables live access and inherits no
credential or loader environment.

Bounded, versioned IPC preserves binary values, result/error categories and request sequence.
A mutation is prepared with its immutable request and operation ID before the child asks to
execute. The parent checks cancellation/deadline and marks potential submission *before*
sending authorization. Unknown delivery after that point is indeterminate, never replayed.
The child rechecks its remaining preparation budget after authorization. Killing a worker
does not prove cancellation of server execution. Complete responses remain complete.

The recording demo blocks real native dependency callbacks before/after write authorization,
checks parent return and verified reaping, exercises late startup/capacity retention, malformed
peers, paging and dependent schema reads, and verifies production refusal. These are process
and orchestration proofs, not real Kerberos authentication or private-plugin attestation.

The private Cyrus component can now be built from the exact official 2.1.28 release
archive with its checked-in guard, without downloading or installing anything:

```sh
python3 src/AdForLinux.DirectoryServices.Native/packaging/build-private-cyrus.py \
  /path/to/cyrus-sasl-2.1.28.tar.gz /new/private/build-directory
bash tests/native-session/run-private-cyrus-demo.sh \
  /new/private/build-directory/cyrus-sasl-2.1.28
```

The recipe pins the whole archive and guard source hashes, disables shared Cyrus/dynamic
plugin loading and optional mechanisms, builds position-independent static objects, and checks
the static GSSAPI member/entry point and absence of dynamic-loader references. The full built
Cyrus/plugin demo exercises initial interaction followed by missing-credential refusal with
and without external protection; ABI-correct linker traps abort before real GSS acquisition or
context initiation. This demonstrates the built guard, not successful credential injection or
authentication. The companion bridge recipe performs that private linking with pinned OpenLDAP 2.6.10:

```sh
python3 src/AdForLinux.DirectoryServices.Native/packaging/build-private-bridge.py \
  /path/to/cyrus-sasl-2.1.28.tar.gz /path/to/openldap-release-tag.tar.gz \
  /new/private/bridge-directory
bash tests/native-session/run-private-bridge-demo.sh /new/private/bridge-directory
```

Source URLs and exact archive hashes are recorded in the recipes. The bridge build verifies
Cyrus enabled/TLS disabled, uses explicit static archive paths, hides their symbols and
requires all link references to resolve. It checks the embedded local GSSAPI entry point and
rejects a dynamic dependency on host LDAP/Cyrus. The actual built bridge's metadata and both
ambient/explicit-source refusal paths are tested before credential resolution. This build
profile cannot represent requested TLS, so it remains ineligible for that policy.
Add `--mit-archive /path/to/krb5-1.21.3.tar.gz` to build pinned MIT static client
libraries as well. The full build uses private headers and exact archives and rejects any
final dynamic dependency beyond the supported libc/resolver/system runtime list. Its actual
ELF dependency list here is libc and libresolv; embedded MIT/GSS symbols are hidden too.
No manifest or build result overrides the hard authentication gates. The library versions are
reviewed prototype pins, not a claim that these versions are the current deployment choice.

Static linking alone does not disable MIT modules. The full private build additionally
hash-checks and modifies pinned MIT `util/support/plugins.c` to select its existing dummy
loader on Linux. Direct, directory, modern plugin, GSS and dynamic-profile loading share
this backend. Archive/final-bridge checks reject runtime loader imports. An actual loadable
canary is refused by the modified loader, while built-in realm selection and GSS metadata
survive. This restriction belongs to this modified MIT composition, not all libc/.NET
loading in a process. Configuration files and directory scans remain possible. MIT's default profile
search includes `/etc/krb5.conf` even with a private sysconfdir. Therefore the restricted worker
path explicitly sets `KRB5_CONFIG` and `GSS_MECH_CONFIG` before exec, without changing the
parent or host environment. Supervisor ABI 2 passes fully sealed memfds as descriptors 4/5;
all sources are duplicated above the child targets before validation/spawn, and parent copies
close after spawn. The child compares the profile against the immutable START recipe using
pread before creating backend resources. Unreaped-worker accounting is unchanged.

`LdapWorkerKerberosProfile` generates a deliberately restricted exact-host/default-realm
profile with only the realm selector and an optional typed single-realm KDC endpoint.
There are no raw configuration fragments, includes, modules or k5identity. The endpoint
accepts only an ASCII DNS/IPv4 hostname and port; it is routing, not network confinement.
IPv6, alternate realms and discovery are currently unsupported. An explicit FILE/DIR source is required. This is an executable synthetic
policy boundary, not a transparent import of a user's Kerberos configuration. Unsupported
custom policies cannot be silently replaced by it. An empty sealed GSS mechanism file prevents
normal host mechanism-file discovery; ordinary GSS contexts use the explicit profile through
MIT's documented environment path. Secure/setuid or other configuration semantics are not
represented or enabled.

```sh
ADFL_PRIVATE_MIT_SOURCE=/private/bridge/mit/krb5-1.21.3/src \
  ADFL_DEMO_DOTNET=/path/to/dotnet bash tests/native-session/run-process-demo.sh net8.0
bash tests/native-session/run-private-bind-demo.sh /private/bridge
```

The optional worker probe uses real private MIT profile reads and GSS mechanism enumeration;
file, module-loading and resolver/connect traps reject unexpected accesses. It does not acquire
credentials or exercise GSS Kerberos-context initialization. Separately, the supplied-handle
demo traverses production bind coordination plus real private OpenLDAP/Cyrus callbacks using
an AF_UNIX socketpair. Instrumented GSS verifies the exact synthetic authority pointer and
service target, then fails before returning a token. Interleaved failing binds verify isolation
and replacement ownership. This proves successful handle injection, not successful
Kerberos authentication, concurrent bound sessions or reconnect enforcement. The fixture
shuts down its socket before cleanup so even the unrelated LDAP Unbind cannot be emitted.
Real credential acquisition, wire authentication/security layers, deployment integrity and
policy compatibility remain unverified; authentication/reuse gates stay closed.
No `make install`, account, cache or host configuration operation is part of these scripts.

Worker protocol 4 and native ABI 3 carry an explicit source recipe. Protocol 4
requires the new optional KDC field to be present (possibly null); older internal
worker frames are deliberately rejected. `LdapCredentialSource`
represents only a FILE absolute path or DIR collection absolute path, supplied explicitly;
no code captures a user environment or reads credentials in the demonstration. The source
travels through START and the shared operation owner into `adfl_authority_resolve_from`.
An older binding API cannot silently ignore it. A fresh MIT context uses
`krb5_cc_set_default_name` before target selection. Before GSS acquisition, the selected
full cache name must equal the FILE source or a direct DIR collection child, including when
selection legitimately falls back to the default. Authoritative missing selection stays failed.
The existing ambient API remains separate and unchanged.

This is a source-routing policy, not filesystem confinement: symlinks and configured cache
selection plugins can access other stores while selecting. MEMORY, KEYRING, KCM, Windows
stores, ambiguous paths and credential-byte transfer are not represented. Neither a path nor
a selected principal proves mutable-cache compatibility; session reuse stays disabled.
Recording tests carry synthetic names through actual worker/native orchestration and verify
one source selection for paired binds and rejection before acquisition on mismatch.

Remaining proofs/work include mutable-cache authority compatibility, controlled native
composition, native/helper facade activation, requested referral/TLS semantics, paged total-size
limits, advanced search response-state handling, and remaining raw Protocols consumers.
`LDAP_OPT_NETWORK_TIMEOUT` bounds connection setup, not arbitrary blocked sends. Cancellation
and bounded polling in the in-process adapter are cooperative. The isolated boundary bounds
parent waiting; neither OS resource reclamation nor managed CPU work has a hard deadline. Windows
retains its existing backend; WinLDAP does not accept an arbitrary SSPI credential handle.

## Primary source basis

- [MIT context-local cache source](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_cc_set_default_name.html), [target selection](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_cc_select.html)
- [Cyrus static loader](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/lib/dlopen.c), [static archive construction](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/lib/Makefile.am)
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

### Opt-in disposable real-login lab

The lab is separate from offline tests and production activation. It builds pinned
MIT KDC/local administration tools and OpenLDAP slapd, then runs a `FROM scratch`
container with no network except loopback, no host mounts or ports, an unprivileged
UID, dropped capabilities, a read-only root and one temporary state filesystem.
It creates only the `ADFL.TEST` realm, two test client principals and one LDAP
service principal. Keys, tickets, databases and diagnostic logs stay in that
filesystem and disappear when the container is forcibly removed. The server's
replay cache also lives there; replay protection is not disabled.

Compile-only preparation, using the already described private bridge and pinned
archives (plus Berkeley yacc 2.0.20221106, whose digest the script checks):

```sh
bash tests/native-session/lab/build-servers.sh MIT_ARCHIVE LDAP_ARCHIVE BYACC_ARCHIVE PRIVATE_BRIDGE NEW_SERVERS
bash tests/native-session/build-private-login-lab.sh PRIVATE_BRIDGE
dotnet build tests/native-session/worker-demo/AdForLinux.NativeWorkerDemo.csproj -c Release -f net8.0
ADFL_OFFLINE_TESTS=1 dotnet tests/native-session/worker-demo/bin/Release/net8.0/AdForLinux.NativeWorkerDemo.dll --generate-lab-profile > LAB_PROFILE
python3 tests/native-session/lab/assemble-image.py NEW_SERVERS /tmp/adfl-private-login-lab-build/private-login-lab LAB_PROFILE NEW_IMAGE_CONTEXT
docker --config DOCKER_CONFIG build --network none --pull=false -t adfl-disposable-lab NEW_IMAGE_CONTEXT
```

Only with explicit authorization for real test credentials/authentication:

```sh
python3 tests/native-session/lab/run-container.py --authorize-disposable-lab --docker-config DOCKER_CONFIG adfl-disposable-lab
docker --config DOCKER_CONFIG image rm adfl-disposable-lab
```

The controller verifies isolation configuration before starting the container,
allows 90 seconds for completion, and forcibly removes its uniquely named
container in cleanup. A nonresponsive Docker daemon remains an infrastructure
failure, not a claim of verified teardown. No credential directories are mounted
or copied out. The scratch image contains binaries/configuration source only.

The harness enables binding only in its copied test operations table. Resolution,
credential acquisition, LDAP connection creation, interaction callback, bind and
requests use the actual private implementations. It checks exact WhoAmI results
for both identities, multiple simultaneously live sessions, owner/session lifetime,
cache-path replacement routing a fresh operation to the replacement identity while
an established session retains its bound identity, and negotiated SASL SSF minima of 1 (signing requested) and 56 (sealing requested).
Signing-only policy may negotiate sealing; this is not proof of a distinct
integrity-only negotiation. Synthetic no-credential refusal and exact-handle
orchestration checks remain separate evidence.

This lab does not establish safe dynamic ambient reuse, Windows identity transfer,
referrals, TLS/channel binding, deployment integrity, or a production-compatible
restricted configuration. Production must require an audited configuration and
composition policy; optional protocol metadata and static linking alone are not
sufficient. All existing production authentication and reuse gates remain closed.

Validated in the disposable lab: nine successful real binds, exact identity and
protected WhoAmI exchanges, cache replacement and teardown. This does not prove
that an old GSS credential handle snapshots a mutable cache, or that concurrent
external cache mutation is safe. No production source gate was changed.

Production worker admission now explicitly requires both the typed restricted
configuration and an explicit source, independently of optional protocol fields.
It still unconditionally rejects unavailable production composition. The child
duplicates each inherited configuration descriptor into an owned CLOEXEC handle,
requires kernel WRITE/GROW/SHRINK/SEAL seals before checking sizes or reading,
and reads those same owned handles. Identical bytes in unsealed, partially sealed
or FUTURE_WRITE-only memfds are rejected before the backend factory. These checks
prevent mutable configuration admission; they do not establish plugin/deployment
closure or enable authentication.

The real-login lab also passes with the module-restricted private client build and
configuration emitted by the actual production profile generator. Before binding,
the harness verifies both fresh caches contain only a TGT (ignoring MIT cache
configuration entries); successful binding therefore exercises service-ticket
acquisition through the explicit loopback KDC endpoint. The KDC/server tools remain
separate test fixtures. No ambient cache or user configuration is imported.

Offline module-denial proof (no credentials):

```sh
bash tests/native-session/run-private-plugin-probe.sh PRIVATE_BRIDGE
```
