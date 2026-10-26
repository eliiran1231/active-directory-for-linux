# Bound sessions and Kerberos policy

Run the deterministic demonstration from the repository root after restoring/building
with the .NET 10 SDK and installing the chosen runtime:

```sh
dotnet build AdForLinux.sln --configuration Release
bash docs/examples/kerberos-session-demo.sh net8.0
bash docs/examples/kerberos-session-demo.sh net10.0
```

`ADFL_DEMO_DOTNET` can select an SDK executable. The demonstration uses the reviewed
offline runner and synthetic transports. It does not contact a directory or acquire
credentials. It exercises creation, exclusive leases, reuse, retirement, failed-send
non-replay, retained-handle isolation, and configuration across both namespaces.

## Implemented ownership

`LdapConnectionOptions` is the immutable recipe. `LdapAuthenticationSource` owns a
snapshot and the bind action, classifies provenance, and declares current backend
capabilities. `BoundLdapSession` owns the resulting connection, profile, provenance
and native referral children. `LdapConnectionProvider.Session` is an exclusive lease,
not the authentication owner. All ordinary acquisitions, validation and cross-target
pairs use this resource. The existing scoped Windows Basic path retains its additional
context checks. No public API changes are needed.

Each batch creates one authentication owner before acquisition; each destination in a
pair creates its own. Replacements consume that owner's recipe. Pool keys still include
all existing credential, endpoint, transport and referral settings. Clones copy recipes,
not connections. Connection failures retire the resource; sent operations are never replayed.
The internal raw getters reject platform authentication, and operation/schema acquisition
cannot bypass the policy through retained platform handles.

## Explicit policy

| Source/backend | Ordinary reuse | Reason |
| --- | --- | --- |
| Explicit Basic, no referrals | Compatible established session | Complete repeatable bind recipe |
| Explicit Basic, Linux referrals | Compatible established session | Preserves the existing native referral policy, including anonymous children |
| Explicit Basic, Windows referrals | Fresh, except existing scoped read | General referral authority compatibility is not established |
| Ambient or explicit Negotiate | Fresh bind per operation | Protocols cannot resolve and consume a proven target-specific authority here |
| Anonymous / other mechanisms | Fresh | No reuse capability established |
| Credential validation | Always fresh | Validation asks for a bind result; preserves native default referrals |

`CompatibleEstablishedSession` does **not** promise the same result as a new bind after
credential revocation/disappearance or changed authorization data. A same-authority ticket
renewal need not retire an established session solely because bytes changed. The current
backend cannot prove this compatibility for Negotiate, so it stays fresh. Epochs are
controlled invalidation, not detection of external `kinit`.

Both APIs reach this policy without a method allowlist:

```csharp
// DirectoryServices: BuildOptions maps Secure to Negotiate.
using var entry = new DirectoryEntry("LDAP://dc.example/DC=example", null, null,
    AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing);
// AccountManagement: the context and derived entries preserve the same recipe.
using var context = new PrincipalContext(ContextType.Domain, "dc.example", "DC=example",
    ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing);
```

These are recipe examples, not offline authentication commands. The demo tests compare
both recipes and derived entries using `.invalid` targets and no bind.

## Concrete native binding and search bridge

The selected backend seam is a small native OpenLDAP/MIT bridge, **not** reflection into
Protocols or a replacement SASL implementation. Source lives in
`src/AdForLinux.DirectoryServices.Native`; `NativeLdapBindingBackend.cs` supplies managed
SafeHandle ownership. A rootDSE discovery slice crosses both public facades and this bridge
with recording native dependencies. Real native backend selection remains disabled.

Run the actual adapter with recording native dependencies, then a metadata-only library probe:

```sh
bash tests/native-session/run-demo.sh
bash tests/native-session/run-managed-demo.sh net8.0
bash tests/native-session/run-managed-demo.sh net10.0
ADFL_NATIVE_OUT=/tmp/adfl-native-sanitized \
  ADFL_NATIVE_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  bash tests/native-session/run-demo.sh
```

This compiles/links with installed OpenLDAP and MIT development libraries, Cyrus runtime,
and a C11 compiler. No package is installed or downloaded. The reviewed composition is
MIT 1.21.3, OpenLDAP 2.6.8 or 2.6.10, and Cyrus 2.1.28. OpenLDAP/Cyrus runtime/header version disagreement
refuses the binding path. MIT 1.21.3 is checked at build time through `pkg-config`,
not attested at runtime. If installed Cyrus headers are absent, the runner explicitly uses
the unmodified upstream public `sasl.h`/`prop.h` under `tests/native-session/headers`; their
original license notices are retained. `ADFL_SASL_INCLUDE` selects an alternate header root.
This fallback is source-header compile/link evidence, **not a live authentication test**.

The executable decisions are:

1. `adfl_operation_open` resolves anew at operation entry. The MIT implementation constructs
   the target service from the exact profile hostname, uses `krb5_cc_select`, and falls back
   to the default cache only when selection yields neither a cache nor an authoritative
   principal. A selected principal with missing credentials fails rather than switching user.
2. Acquisition names the selected principal and cache explicitly, requests only Kerberos,
   and passes an owned, verified-empty MEMORY client keytab. This excludes default-client-keytab
   acquisition/refresh; specifying a ccache alone (or importing it) does not. The memory
   keytab receives no keys. No process credential environment is changed.
3. An opaque resolved authority owns the resulting GSS credential and its cache/keytab/context
   lifetime. The bind callback installs that exact **handle value** after OpenLDAP creates
   its SASL context, before the pinned Cyrus GSSAPI implementation initiates GSS. Only the
   expected USER prompt is accepted, with empty authorization identity. Success without
   credential installation is rejected; no bind is retried.
4. Replacement and parallel binds retain that same authority. LDAP/SASL disposal precedes
   release of GSS and the remaining authority resources. New logical operations must resolve
   again; explicitly binding an old authority is only a replacement/parallel-session primitive.
   C callers must keep their authority reference alive through bind; the managed SafeHandle
   marshaler supplies that call lifetime. Tests assert selected identity and target, not only
   allocation counts.
5. Requested referrals, TLS, unsupported mechanisms/explicit credentials, or unprotected
   profiles are refused before resolution. The existing managed backend retains the caller's
   original profile and conservative fresh policy; the bridge does not turn off requested
   referrals to obtain eligibility. `NOCANON` makes Cyrus receive the resolver's exact host
   recipe, but does not prove atomic DNS or cache stability.
6. Cancellation is checked between native calls and at the interaction callback. LDAP
   timeouts are configured; resolution/DNS/cache plugins and synchronous GSS calls do not
   have a universal hard cancellation deadline. No post-send operation replay exists.

The recording driver traverses the **same native acquisition/bind orchestration** as the
system backend, injecting only native dependencies. It covers target/current-source changes,
authoritative missing-cache refusal, default-cache selection, replacement and simultaneous
binds, partial failures, unexpected/missing callbacks, cancellation and disposal ordering.
System credential functions and actual LDAP authentication are never invoked by these demos.
The separate probe reads version metadata and verifies refusal before credential resolution.

## Pre-authentication enforcement gate

Version strings do not attest the loaded MIT/GSS plugin or prove that it requests interaction
before initiating GSS. A post-bind `installed` check cannot undo wrong-identity authentication.
Therefore the system backend's `authority_binding_enforced` capability is **hard-false**,
with no runtime/environment override, and orchestration checks it before even allocating
credential material. The recording dependencies explicitly supply the capability only for
tests. Adversarial missing-callback tests verify that an untrusted composition receives no
resolution or bind call. Public shared-library exports exclude dependency injection and the
recording factory; the latter exists only in the separately built test library.

`request_transport=1` describes implemented search dispatch, not permission to authenticate.
`compatible_session_reuse=0` and managed `SupportsFacadeRequests=false` remain unchanged.
The real MIT implementation is source/compile evidence; immutable fake identities prove
routing/lifetime orchestration, not the stability of a real mutable cache. A credential's
principal equality does not certify compatibility, and ticket-byte changes are not treated
as an invented universal generation. No real credentials or directory authentication were used.

## Executable facade and transport decisions

`ILdapRequestTransport`, `LdapSearchCommand`, and owned `LdapSearchResult` are internal; public
DirectoryServices/AccountManagement types stay unchanged. `BoundLdapSession` can own either
adapter. Legacy raw-connection consumers explicitly require a Protocols handle; a native
resource cannot fabricate one. The default remains Protocols. The implemented vertical slice
is `DirectoryEntry.Options.GetCurrentServerName` plus `PrincipalContext` connected-server and
naming-context discovery, all using shared leases, RootDse and `LdapRequestDispatcher`.

The managed demo forwards the facade-derived target, protection and timeout profile into
the recording native factory, then uses the actual SafeHandle/PInvoke search, C dispatcher,
native result callback and managed parser. It checks three balanced requests/message chains/
sessions/authorities across both facades. It does not replace the dispatcher with a second
managed imitation, and the permanent offline guard stays enabled.

The common command contains search base/filter/scope, attribute selection, types-only,
size limit, local deadline and server-side controls. Controls unsupported by an adapter are
refused before dispatch; the native subset currently accepts no request controls. Local/client
controls, paging and alias-dereference overrides are not represented by this slice. No public
method allowlist decides eligibility. Native-specific deadline limits do not restrict Protocols.
Results retain binary values, per-entry/reference/result controls, references, final referrals,
result code, matched DN and diagnostic text. Public LDAP decoding APIs do the parsing;
managed buffers own copies before the native message chain is freed. No raw handle escapes.

Native dispatch permits one active request per session, sends once, polls by monotonic deadline,
and rechecks cancellation/deadline during conversion. It abandons a pending request at most
once and retires on failure, cancellation, timeout or rejected conversion. Completed-message
conversion failures still free the chain but need no abandon. Deadline checks prevent late
success; they are not a hard interrupt of a synchronous native call. There is no replay.

A session-owned `LDAP_OPT_CONNECT_CB` permits only the first exact target/port connection.
Later connection additions are vetoed before LDAP uses them, and deletion retires the session.
Callback storage lives through unbind; callbacks never reenter LDAP under native locks.
Requested referral chasing remains unsupported by this native profile rather than being
silently disabled. Returned referral information is preserved. RootDse translates non-success result codes
and preserves existing first-entry behavior for successful responses, including responses
containing references or referral URLs. Receiving these URLs does not itself follow them.

## Streaming, paging and write outcome contract

`LdapConversation` is an executable internal coordinator, exercised by recording transports
in `ConnectionPoolOperationTests.Conversation.cs` through real pooled session leases. Existing
adapters advertise none of its new capabilities; no existing public search/write path changes.
Run it with the guarded demonstration at the top of this document.

Search exposes owned entry/reference events followed by a full page-result envelope. Entries
already delivered remain observable if a later result reports a limit or failure. Only success
with a continuation advances; a non-success envelope is terminal even if the backend reports
more pages. The cursor owns opaque cookies and native message state. One exclusive lease and
one cursor span all pages; the next page is requested only on the consumer's next pull, never
prefetched or rebound. Unpaged continuation is a contract error. Terminal state is recorded
before yielding the final envelope, so stopping there does not retire a healthy session.

Cursor disposal precedes lease return. Early stop, cancellation, deadline expiry or uncertain
cleanup retires the session; cleanup failure still returns pool capacity. The coordinator uses
one monotonic deadline including acquisition and consumer pauses, with checks before/after
awaited reads. Open receives the original timeout minus elapsed acquisition/preparation time;
each read and page advance receives the current remaining budget. Modify likewise receives
only the budget remaining after acquisition. Backends must enforce these budgets during native
waits; expired acquisition cannot start a request. Cancellation is cooperative:
a still-running backend call is awaited before native state or its lease can be released.
Recording tests cover pending reads, partial results, page boundaries, early disposal and
cleanup failure; they do not prove native streaming or cookie encoding.

The typed modify slice snapshots binary attribute changes and controls before dispatch.
A backend calls `LdapSubmission.BeforeSend` immediately before entering the native send.
Errors before that boundary are `NotSent`; errors afterward are `Indeterminate` because the
server may have applied the write. Neither outcome is automatically retried. A complete LDAP
response, including an error result, is `Completed` with matched DN, diagnostics, referrals and
controls preserved. Cancellation racing an accepted response cannot erase that known outcome.
The marker records possible submission, not proof of delivery. Native/Protocols adapters for
this contract remain to be implemented; it is not a working public mutation API.

## Fail-closed plugin patch and composition boundary

`src/AdForLinux.DirectoryServices.Native/patches/cyrus-sasl-2.1.28-explicit-credential.patch`
is a minimal patch against the exact official source. Supply a local, unmodified upstream
`plugins/gssapi.c` to run its offline proof (the verifier never downloads or installs anything):

```sh
python3 tests/native-session/verify-plugin-guard.py /path/to/cyrus-sasl-2.1.28/plugins/gssapi.c
python3 tests/native-session/verify-plugin-guard.py /path/to/cyrus-sasl-2.1.28/plugins/gssapi.c --sanitize
```

The verifier checks the source hash, applies the patch, checks ordering and compiles the actual
extracted initial-interaction/guard fragment with recording stubs. The guard rejects a missing
**consumed** `client_creds` after initial `SASL_INTERACT` can install it, but before any client
GSS call. It does not merely inspect a later `params->gss_creds` value. Initial interaction,
resumed missing credentials, prefilled user, explicit handles and callback mutation are tested.
This is not a full plugin build, authentication test or loaded-plugin identity proof. A future
port must guard before any credential-acquisition fallback, not only `gss_init_sec_context`;
the newer TLS/no-confidentiality path makes that distinction material.

The required composition owns its libsasl instance from initialization and admits only the
reviewed guarded plugin and dependency closure. `SASL_CB_GETPATH`/`VERIFYFILE` cannot retrofit
an already initialized host-global instance; a mechanism name is not implementation identity.
The current in-process system bridge has no such composition proof and remains hard-disabled
before credential resolution. The patch and tests add no environment flag or enable switch.

## Mechanically specified extension boundary

Real native activation requires pre-auth authority enforcement from a supported, controlled
dependency composition; version metadata alone cannot provide it. That gate is unresolved,
not an approval to acquire credentials. Existing Protocols/Linux Negotiate limitations remain.

Further commands must add typed internal command/response data and adapter capability checks,
then use the same lease, single-dispatch, cancellation, result ownership and retirement rules.
Native add/modify/delete/modify-DN/compare/extended adapters and full DirectorySearcher
paging/streaming integration have not been implemented; the conversation contract above
settles lifetime/outcome rules but does not implement their native protocols. Move their existing raw-connection consumers to
this transport contract before enabling a native backend for them; keep streaming cursors
inside the producer's retained lease. Do not add method allowlists, private-handle reflection,
in-place rebind, managed replay or home-grown SASL/security framing. Windows remains on its
existing backend; this bridge does not invent SSPI credential injection.

Source basis: [MIT initiator/cache semantics](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html),
[MIT 1.21.3 acquisition](https://github.com/krb5/krb5/blob/krb5-1.21.3-final/src/lib/gssapi/krb5/acquire_cred.c),
[OpenLDAP 2.6.10 callback/option implementation](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/cyrus.c),
[Cyrus 2.1.28 GSSAPI](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/plugins/gssapi.c),
[OpenLDAP connection callback veto](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/libraries/libldap/os-ip.c),
[OpenLDAP public result-decoder usage](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_10/clients/tools/ldapsearch.c).
Vendored public headers: [sasl.h](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/include/sasl.h)
and [prop.h](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/include/prop.h).
