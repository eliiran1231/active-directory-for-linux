# LDAP connection lifecycle design (issue 15)

## Audit and integration boundaries

`LdapConnectionFactory.Create` configures Protocols 9.0.0 connections (net8.0 and
net10.0). `CreateBound` owns setup/bind failure cleanup. There are four owners:

* `PrincipalContext` discovery calls own a connection for one request sequence.
  Credential validation also calls the factory, but must always bind afresh.
* `LdapIdentitySearchSession` owns a referral-disabled connection for the full
  domain-discovery and identity-translation sequence.
* `CrossContextSaveSession` owns a referral-disabled preflight connection and
  changes its timeout. Live writes are intentionally disabled in this transport.
* `DirectoryEntry` retains primary and schema connections. Its raw connections
  reach mutations, security persistence, schema caches and ranged reads.
  `DirectorySearcher` borrows them, changes referral/timeout state, and keeps a
  separate copied entry alive for streaming work, including native async Abort.
  Close and even same-value credential setters explicitly invalidate bindings.

The integration uses operation ownership rather than returning retained entry
handles on entry disposal:

| Consumer | Lease boundary |
| --- | --- |
| Context discovery | One request sequence; nested default-NC lookup before acquisition |
| Identity lookup | Entire domain discovery / translation sequence |
| Entry read, configuration, mutation, security persistence | Request and dependent decoding; release before separate readback |
| Ranged attributes | Entire range loop, with sequential schema decoding |
| Buffered search | All pages and result materialization, including sequential schema decoding |
| Streaming search | Producer lifetime; atomic pair for native search and concurrent schema requests |
| Cross-context preflight | Atomic source/destination pair; stable configured keys, per-bind/request deadlines |
| Credential validation | Capacity-accounted fresh bind, always disposed, never reused |

The existing internal raw entry getters remain directly owned for controlled test
transports and native compatibility fixtures; production call sites use leases.
Public APIs are unchanged. Live cross-context writes remain disabled. No request,
including a write, is automatically replayed.

## ObjectPool evaluation, before implementation

Evaluated Microsoft.Extensions.ObjectPool **8.0.0**, including the official
[package frameworks](https://www.nuget.org/packages/Microsoft.Extensions.ObjectPool/8.0.0),
[versioned DefaultObjectPool source](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/ObjectPool/src/DefaultObjectPool.cs),
and [provider source](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/ObjectPool/src/DefaultObjectPoolProvider.cs).
It is a Microsoft-maintained ASP.NET Core component with compatible net8.0 and
netstandard2.0 assets; this version is a reproducible comparison, not a proposal
to pin the project to an older package. `Get` creates on empty;
`maximumRetained` only bounds returned objects. The provider supports disposable
objects, but neither API supplies bounded acquisition, cancellation, idle ages,
key isolation or registry eviction.

Option A would require an outer capacity reservation system, timestamps, a keyed
registry and shutdown coordination, while the retained queue is not exposed for
age eviction. Option B owns a small keyed idle list and one synchronization gate.
Choose B: adding ObjectPool would duplicate ownership without removing the hard
lifecycle work. No new package dependency.

## Code-level design

`BoundedConnectionPool<TKey,T>` reserves per-key/global capacity under one gate,
creates outside that gate, and returns an exclusive idempotent lease. The cap
includes connections being created and destroyed. An operation needing multiple
connections reserves all of them atomically, including different endpoint keys;
it never holds a partial reservation while waiting. A cap smaller than the entire
operation fails before native work. Streaming needs two slots even when no schema
lookup ultimately occurs; this avoids deadlock during partial-result decoding.

Waiting has a monotonic deadline and cancellation; waiters do not register new
keys. Idle slots are timestamped on return, checked on acquisition and swept by
a timer. Active leases never expire. Shutdown rejects acquisition and drains idle
resources; outstanding leases dispose on return. Empty key records are removed.
Factory failures release all reservations, including partially created pairs.

`LdapConnectionProvider` maps immutable configuration to an opaque keyed HMAC,
with exact length-delimited UTF-16 inputs including the password and all
transport/session settings. No entry DN appears in the key. Neither keys nor
identities are logged. Internal snapshots expose only aggregate creation, reuse,
destruction, failure, wait/timeout counts and current resources/keys/waiters.
There is no checkout rebind or artificial health probe.

Explicit nonempty Basic credentials are reusable with unchanged referral settings
on Linux. The entire native session (including native referral children) remains
under the exact immutable credential/configuration key. No checkout rebind,
credential forwarding callback or referral-policy override is introduced.
[OpenLDAP 2.6.8 request.c](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_8/libraries/libldap/request.c)
keeps referral connections on the owning LDAP handle and binds them anonymously
when there is no rebind callback, as in this library. Reuse preserves that behavior;
it does not grant referral targets the primary Basic identity. External/Subordinate
still map to All on Linux because Protocols cannot represent partial modes there.

Windows and other backends retain fresh, capacity-accounted sessions when referrals
are enabled. MS-ADTS supports fixed Basic credential propagation, but native
Windows TLS referral identity and reuse validation remains incomplete. Basic with
referrals disabled remains reusable on those platforms. This platform limitation does not change caller referral settings.

Ambient/default, anonymous, Negotiate/Kerberos and other mechanisms remain fresh
and capacity-accounted. Current DirectoryEntry authentication defaults are Secure
(Negotiate), and PrincipalContext defaults add signing/sealing: these fully default
authentication workloads still gain no bind reuse. Explicit Basic workloads on
Linux now gain reuse without changing default entry/search referrals (External).
Kerberos pooling is tracked separately in [issue 236](https://github.com/eliiran1231/active-directory-for-linux/issues/236).
Validation always executes the original fresh bind and disposes it, even for
credentials matching a warm connection. No authentication fallback is introduced.

Close and explicit credential/configuration rebinds advance a freshness generation
and require a fresh checkout. Binding copies carry the generation floor. A late
return from an older operation cannot undo that floor. Generations are lease
metadata, never per-entry pool keys. Closing/disposing an entry does not close a
physical connection still held by another operation.

Referral policy participates in the key and is applied before bind. Temporary
request timeouts are restored or passed to the per-request overload. DirSync/VLV
sessions are conservatively discarded. Transport/unknown failures poison leases;
ordinary LDAP operation rejections do not establish a broken connection. Schema
helpers report failures even when their compatibility fallback swallows them.
Abandoned page cookies and interrupted async requests cause discard. Native Abort
is attempted before disposal; it does not prove all runtime background work has
completed. See the versioned [Protocols 9.0.0 implementation](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapConnection.cs).
An interrupted connection is never handed to another borrower. Result collection
Dispose cancels the producer; the producer owns both leases until its cleanup.

## Settings and limits

Internal constructor defaults: **8 per key, 64 total managed connections, 256
concurrent waiters, 60 seconds idle from return, 30 seconds acquisition wait,
5-second sweep interval**. Eight accommodates ordinary concurrency and paired
streaming/preflight work without an unbounded registry; these are initial limits,
not production tuning claims. Tests inject smaller limits and a monotonic clock.
FIFO fairness is not promised. Maximum connection lifetime was considered but is
not imposed: it is separate from idle age and must never interrupt active work.

The acquisition timeout bounds capacity waiting, not an in-progress native bind.
Bind retains the existing LDAP timeout; cancellation is checked before/after
creation but cannot interrupt synchronous native bind. Existing synchronous APIs
have no new cancellation parameter. Cross-context deadlines cancel admission;
streaming cancellation is handled by the producer after admission.

Caps cover managed connection objects, including fresh validation and conservative
authentication bypasses. They do not count sockets created internally by native
referral chasing, external callers' Protocols objects or internal raw test fixtures.
Cleanup disposes idle resources synchronously unless a concurrent sweep already
owns them; that sweep completes disposal. Process exit/assembly unload stops the
shared manager. Active native operations are not forcibly closed at shutdown.
All production acquisition retains the pre-native offline guard.

## Validation and review

`ConnectionPoolTests` and `ConnectionPoolOperationTests` are allowlisted by
`tests/run-offline-tests.py`. Fake resources/connections and a monotonic clock
cover expiry, exact key isolation, hard caps, cancellation, delayed creation and
destruction, partial pair failure, opposing endpoint acquisition order,
concurrent return/sweep/shutdown, entry reuse, no write retry, and copied freshness
floors. These tests create no native LDAP handles. Use the guarded runner, e.g.:

```sh
python tests/run-offline-tests.py functional --framework net10.0 --class ConnectionPoolTests --class ConnectionPoolOperationTests
```

Independent review corrected bypass capacity accounting, timeout-key fragmentation,
UTF-8 replacement collisions, inappropriate cross-key eviction under per-key
saturation, and loss of freshness when copying a search binding. Pair tests exercise
all-or-none admission rather than assuming the single-connection tests suffice.

`ConnectionPoolSambaTests` is deliberately excluded from offline runs. Disposable
CI records direct versus pooled rootDSE and entry-read creation/explicit-bind
counts and elapsed time, plus concurrent entry reads, buffered/streaming page
agreement, early cursor disposal and invalid credentials after warm discovery.
Entry, paging and concurrent checks leave referral defaults unchanged. A small
loopback LDAP source returns only referrals to the existing disposable Samba
rootDSE: receiving actual target attributes proves native chasing occurred, and
its bind counter proves primary-session reuse. This requires no second DC or
changes to Samba security settings. It does not measure native child socket/bind
counts or prove authenticated cross-domain referrals. The helper is used only with
synthetic test credentials and is never part of the guarded offline suite.
The entry comparison includes public schema/materialization overhead; it is not
an identical wire-request benchmark. Both existing Linux/Windows offline CI and
disposable Samba CI run for PRs targeting dev. These checks do not establish lab AD,
Kerberos identity-switch, Windows referral identity, production TLS, network-partition,
throughput or tail-latency parity. No lab AD testing is authorized for this work.

## Windows Basic referral investigation

The Windows eligibility extension is gated on native Windows tests, not only the
managed pool tests. The initial investigation commit leaves eligibility unchanged.
The [MS-ADTS referral task](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b2edefdd-16f9-413d-88c5-a2f5c137bafe)
associates referred connections with the containing ADConnection; the
[bind task](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7a6dad48-8a6f-4704-8308-e3367ab7440a)
constructs authentication from that connection's LDAP_OPT_AUTH_INFO. Its ambient
thread-identity behavior is in the SASL branch. This supports whole-handle reuse
under fixed explicit Basic credentials without changing native referral callbacks.

The intended integration boundary remains `LdapConnectionProvider.CanReuse`:
retain the exact existing credentials, transport, referral mode and other settings
in the key; retain exclusive operation ownership and failure disposal. Do not
introduce credential-forwarding callbacks or cache borrowed callback wrappers.
Protocols 9.0.0 only takes ownership of a notified referral handle when its callback
returns true; native null credentials become an empty managed NetworkCredential.
Neither callback non-nullness nor a primary-bind success proves referred identity.

`WindowsBasicReferralTests` uses real WinLDAP against loopback BER/TLS endpoints
on hosted Windows, separately from the offline suite. It parses target binds and
accepts only two synthetic Basic identities/passwords; SASL receives no challenge.
Ordinary CI certificates exist only for the fixture lifetime, without trust-store
changes. The test's existing SkipCertificateCheck option is confined to fixture
connections. The separately authorized, single-job trust diagnostic is described
below; it does not change ordinary CI or production validation.
This is native client integration evidence, not an AD server or domain trust test.
Microsoft documents refusal to forward plaintext Basic credentials, while older
material describes anonymous referral binds; preserve observed backend behavior
rather than add forwarding to make a test pass. StartTLS has separate documented
referral/autoreconnect restrictions and must not be treated as LDAPS.

The Windows .NET 8/10 native baseline at `2243542` reached the LDAPS referral
target but completed zero TLS handshakes and sent zero binds. Only the two primary
connections invoked the certificate callback. This is consistent with the callback
not applying to the referral child, but does not prove certificate trust caused the
failure. The subsequent two-identity, impersonation and retained-primary assertions
have not passed; Windows referral-enabled pooling remains disabled. Plaintext
referrals did attempt an anonymous bind and forwarded no explicit Basic credentials.

At `7ce7bcc`, [native Windows CI](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39662334153)
classified the referral target's first socket record as a TLS handshake on both
.NET 8 and .NET 10. After endpoint shutdown, each recorded one closed connection,
zero completed TLS handshakes, zero binds/searches, and IOException HRESULT
`0x80131620`. No payload bytes or exception messages were logged. This rules out
plaintext transport on that observed LDAPS connection; it does not identify the
TLS failure cause. The plaintext safeguard still passed, with one anonymous bind
and no credentialed Simple or SASL binds.

One explicitly authorized [trust diagnostic job](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39661592499)
was launched at `31ae9c0538a061a71672e4994b3f87a37c66a4e0` on a disposable hosted
Windows runner, using one short-lived public TEST certificate in CurrentUser Root.
The helper records the exact thumbprint before import, removes and verifies it in
`finally`, and is followed by an `always()` cleanup step. Runner destruction is the
final isolation boundary if termination interrupts cleanup. Consult the run logs
for the actual import, test and cleanup outcomes; launching a job is not evidence
that these actions succeeded. This authorization applies to that one job only.
The trigger workflow has been removed from the PR branch. The retained
[opt-in helper documentation](../tests/windows-referral-diagnostic/README.md)
requires new authorization before any further trust job.

A possible additional diagnostic infrastructure limitation is Windows displaying
an interactive confirmation for CurrentUser Root `X509Store.Add`, as documented in
[dotnet/runtime #24160](https://github.com/dotnet/runtime/issues/24160). A long-running
step alone does not prove that this dialog appeared. CurrentUser Root visibility
under anonymous impersonation is also a separate confounder. Neither a stalled
import nor a TLS failure establishes unsafe credential substitution. Windows
referral-enabled pooling remains disabled until successful native identity,
reuse, isolation and failure-cleanup evidence supports a precise transport scope.

### Direct Windows TLS controls

[Control-only run 39680706941](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39680706941)
at `dd368f5c519b8ec62c06a939fca36fa5d4fc93e5` passed both direct-to-target tests
on .NET 8 and .NET 10. Each runtime tested the original Windows identity and
anonymous impersonation independently, after a separate warmup endpoint loaded
the client code. Each target recorded one connection, completed TLS handshake,
explicit synthetic Basic bind, search, pin-callback invocation and closed
connection; no anonymous LDAP bind, SASL bind or transport failure occurred.

The callback accepts only the exact DER certificate generated for that direct
target. It is attached only to that test client before binding, with no system
trust import or native referral callback changes. The earlier native referral
baseline had one target connection but zero completed TLS handshakes, binds or
searches on both runtimes. These results narrow the blocker: the target and direct
client can work under either ambient identity with pinning, but native referral
children and their default certificate-validation path remain unvalidated.
The controls are not evidence that referral pooling is safe; eligibility is unchanged.

The next diagnostic should compare an unpinned direct control using normal
certificate validation with the pinned result, then collect available native TLS
failure status before changing any referral behavior. Pinning success alone does
not prove certificate trust caused the referral failure. StartTLS, referral identity
propagation, isolation, reuse and failure eviction remain separate requirements.

### Normal-validation comparison

[Run 39698240874](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39698240874)
at `188f48f0ad24e78900c555c2d9ef38572a49826b` compared fresh self-signed target
certificates on .NET 8 and .NET 10. All four direct-control assertions passed per
runtime: both pinned controls completed one TLS handshake, explicit Basic bind
and search; both normal-validation controls rejected the connection at bind with
`LdapException`, HResult `80131500`, LDAP error `81`. Each unpinned target recorded
one closed connection, zero completed TLS handshakes/binds/searches and zero
certificate callbacks. Negative counters are checked after endpoint teardown.
No system trust changes or referral callback overrides were used.

The unchanged referral baseline failed on both runtimes: the client received
`ResultCode.Referral`, zero entries and one unresolved referral; the target
recorded one closed connection, zero completed TLS handshakes/binds/searches and
`IOException` HResult `80131620`. This was an assertion failure on an unresolved
referral, not a native LDAP exception exposing the child TLS status. The one-off
diagnostic workflow allowed that known failure to continue; its green job status
does not mean the referral baseline passed. Its trigger was removed after the run.

The initial read-only Schannel lookup reported only a generic exception; no
specific TLS status was recovered. The retained reader distinguishes a missing
event from other read errors, reports only event IDs and selected numeric status
fields, and never enables logging or changes registry/policy. Existing events
within a test window cannot automatically be attributed to a particular socket.
[Microsoft documents the Schannel event categories](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786445(v=ws.11)).

The comparison supports certificate validation as a candidate for the referral
TLS blocker and shows that direct pinned TLS works under both ambient identities.
It does not establish the precise child TLS failure or native referral identity,
reuse, isolation or eviction safety. Production eligibility remains unchanged.
A successful native referral baseline with valid normal certificate trust is
still needed before positive pooling tests can proceed; process-local pinning
of a direct client cannot substitute for that evidence. Further trust changes
require new authorization and are not part of ordinary disposable CI permission.

### Rejected certificate attribution

Microsoft's event 36882 description explicitly states that its attached data
contains the rejected server certificate. An opt-in observer now compares only
complete DER certificate binary properties from existing System/Schannel 36882
events with the unique referral target certificate, in memory. Public target DER
travels only over redirected process stdin; no certificate blobs, private keys,
rendered event messages or unrelated fields are emitted. The C# caller also
allowlists the observer's metadata-only output. Observation is bounded and does
not enable logging, change trust or modify native referral callbacks.

[Isolated run 39699983904](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39699983904)
at `bc4fa069aeaf6b0d7e4622888c54528ff82d83e5` ran only the native referral baseline
on each runtime. The shared parser's exact, different, invalid and prefixed DER
self-tests passed before the native tests. Both runtimes observed event 36882
with `context=whole-DER payload; exact-target-match=True`. Thus the untrusted-CA
event is attributed to this fixture's referral-target certificate, rather than
merely correlated by timestamp with several direct/referral tests. The baseline
still failed: one target connection closed, zero completed TLS handshakes, binds
or searches, and a client response containing one unresolved referral.

The first attempt, [39699679998](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39699679998),
failed its synthetic harness check before either native baseline ran. It supplied
no attribution evidence. The corrected harness tests the shared pure comparison
function directly, without mocked event-log lookup or redirected console input.
The one-off trigger was removed after the corrected run; the observer remains
opt-in through `ADFL_REFERRAL_MATCH_EVENT=1` on a disposable hosted runner only.

This establishes rejection of the target certificate as untrusted in these runs.
It does not establish successful referral authentication, pooling safety or the
behavior after trust succeeds. The production guard remains unchanged. Positive
native TLS/referral validation still needs valid normal trust under the relevant
identities; the consumed individual trust approvals do not authorize another
import or broader trust, registry or policy changes.

### Single LocalMachine trust diagnostic

With separate authorization for one disposable hosted Windows job,
[run 39832451191](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39832451191)
at `cb87f519a988e23523a07024502768cbd740ef38` imported only a unique, one-hour
public test certificate into LocalMachine Root. Setup completed within the
60-second watchdog, including public/PFX export, file writing, ownership manifest,
import, exact public-only presence check and default chain validation. There was
no import hang. No other policy, registry or trust changes were made.

The .NET 8 and .NET 10 controls ran sequentially in that VM. On each runtime:

- The original-identity control passed default chain validation and normal native
  TLS, one explicit Basic bind and one search, with zero certificate callbacks.
- The anonymous-identity control failed in the additional managed
  `X509Chain.Build` precheck with `CryptographicException`, HResult `80131501`
  ("An unknown chain building error occurred"). It opened no target connection:
  TLS, binds and searches were all zero.
- The helper skipped native referral tests because the two-identity trust gate
  did not pass. The job failed; no referral identity, reuse or pooling conclusion
  can be drawn from it. In particular, this precheck failure does not establish
  that native WinLDAP TLS would fail under anonymous impersonation.

Finally cleanup removed the single owned public certificate with exact thumbprint
`9EC4633FA217A333A655241B3CABC4F50EBE23DE` and verified its absence from
LocalMachine Root and deletion of the temporary PFX. A separate always-run cleanup
step found zero matches and independently repeated both absence checks. Only TRX
results were uploaded; no certificate or private-key artifacts were uploaded.

The reviewed helper remains opt-in with no workflow trigger. Both one-off
workflows were removed after the run; this approval is consumed and no automatic
rerun was attempted. The no-trust
[preflight 39831920028](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39831920028)
passed parsing, compilation and all four existing direct controls on each runtime.
An earlier preflight caught a PowerShell interpolation error before executing any
trust operation; it was corrected before the authorized diagnostic.

The next investigation should distinguish the managed chain-precheck failure
from native WinLDAP normal validation under anonymous impersonation, without
changing certificate validation or authentication semantics. Another trusted
fixture execution requires fresh authorization. Windows referral-enabled pooling
remains disabled; successful native referral, credential isolation, ambient
identity, transport and failure-eviction evidence is still missing.

### Prepared separation of managed and native validation

The test-only control now records managed chain validation as `valid`, `not valid`
or an exception HResult, without messages, certificate data or inner exceptions.
It then attempts native WinLDAP TLS regardless of that managed outcome. Native
creation, bind and search errors still propagate and fail the control; normal
native certificate validation is unchanged, with no callback, pinning, custom
roots or authentication override in the trusted diagnostic path.

Six pure-delegate regression cases cover valid, invalid and throwing managed
diagnostics followed by either successful or throwing native controls. They check
that the native action executes once, diagnostic details are sanitized, and a
native failure stops dependent assertions. These cases are safe offline tests;
they do not establish actual Windows TLS or referral safety.

For a future separately approved single disposable Windows job, the retained
helper would use the same unique public certificate, ownership manifest,
60-second setup watchdog, exact-thumbprint finally/independent cleanup and PFX
deletion. It would run .NET 8 then .NET 10. Each runtime must pass both actual
native normal-validation controls (original and anonymous identities), including
TLS, explicit Basic bind, search and endpoint counters, before its native
referral stages run. Managed chain observations would no longer block those
native controls. No trusted job or certificate import is authorized or triggered
by this preparation, and no recurring trust workflow is installed.
