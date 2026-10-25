# Windows Basic referral pooling: evidence and production boundary

Current implementation decision (2026-10-25): enable only the existing exact
Windows synchronous Base FindOne / validated LDAPS / `127.0.0.1` / External
subset, with token-isolated keys and lifecycle checks. The primary host predicate
is not a target allowlist. Other Windows referral paths stay fresh. This is a
limited feature, not completion of general remote-host Windows pooling.
[Supported contract](connection-pooling.md#supported-windows-scoped-findone-subset).

[Run 40214586987](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40214586987)
passed all 31 candidate cases on both runtimes, including real FindOne and
anonymous fresh-path parity; exact cleanup was independently verified. Final
ordinary exact-head CI is tracked separately. The assessments below preserve
chronological context: earlier disabled/untested statements are superseded only
for this exact subset by the [validation record](windows-context-candidate-validation.md#corrected-candidate-verification-2026-10-25).

Assessment after [run 40123894559](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40123894559)
at 0615f46c2482b8939afc03ef6ebcc31012e3de67. Both .NET 8 and 10 passed
37/37 comparison cases and all 11 authenticated native stages. The separate
anonymous direct TLS control failed with LDAP 81 before TLS/bind/search, correctly
keeping the overall job failed. Exact cleanup was independently verified.
[Full results and chronology](windows-authenticated-referral-plan.md).

**Decision: no additional production Windows referral path can yet be enabled
from this evidence alone.** The existing Basic/referrals-None path and Linux
behavior remain unchanged. The test-only candidate stays restricted. This is a
specific boundary gap, not a claim that the positive tests failed or that all
possible LDAP deployments must be tested before any supported subset can ship.

## Evidence matrix

| Dimension | Established evidence | Production decision |
| --- | --- | --- |
| Explicit Basic credentials | Two synthetic LDAP identities; password/key isolation, rejected binds, no silent SASL or anonymous fallback in authenticated cases | Necessary but insufficient. Empty/ambient credentials and non-Basic authentication stay unpooled |
| LDAPS | Normal native certificate validation; TLS 1.2 loopback endpoints, exact IPv4 address, factory SSL flag | Candidate evidence only. Primary LDAPS does not express the entire returned referral graph |
| StartTLS | Not covered by the passing provider suite | Exclude from any proposed initial extension; do not treat as LDAPS |
| Plaintext primary | Earlier raw negative controls observed anonymous referral behavior without explicit credential forwarding | No referral-enabled real-provider safety proof; exclude |
| Mixed referral URLs | LDAPS primary with an ldap URL sent TLS to the deliberately plaintext target; raw and pooled both failed without binds/searches | Negative parity for this one case, not proof of every mixed transport policy |
| Referral mode | External provider path tested; None is already supported separately | Do not enable Subordinate/All from External evidence |
| Caller identities | Original runner plus two standard local accounts; A/B acquire-return-reacquire and first referral after switching passed | Authenticated fixture evidence, not all restricted tokens, domain identities or anonymous contexts |
| Anonymous Windows impersonation | Fresh native direct TLS failed before LDAP identity assertions | Distinct from LDAP AuthType.Anonymous. Warm pooled versus fresh behavior is untested |
| Session configuration | Exact credentials, host/port, SSL/StartTLS/skip, auth, signing/sealing, timeout and referral mode are keyed; actual isolation suite covered identity/password/port/timeout/mode | Key separation is not equivalent to validation of every mode; unsupported combinations stay excluded |
| Certificates | Normal validation used; untrusted referred target failed with no bind/search; no new callback/forwarding installed | SkipCertificateCheck, custom client certificates and callback-dependent behavior are not validated by this suite |
| Native sharing/concurrency | Distinct primary connections overlapped; one search per operation, no timeouts; an unpooled case shared one bound target connection | Exclusive primary leases are established. Independent or simultaneous child sessions are not promised |
| Failure handling | Failed binds released reservations; classified primary/referred-target failures evicted leases; no extra managed operation callback | Native reconnect/retry is separate from managed replay; do not promise exactly-once execution after transport failure |
| Destinations/topology | Controlled single-hop loopback endpoints | No hostname/SAN variants, recursive graphs, cycles, cross-domain delegation or live AD evidence |

The runtime package remains pinned to System.DirectoryServices.Protocols 9.0.0.
The repository factory supplies Basic credentials without domain rewriting and
sets native referral policy. The pinned
[LdapConnection implementation](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapConnection.cs)
uses its Basic branch to pass the supplied username/password to BindToDirectory;
the Windows
[session-options implementation](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapSessionOptions.Windows.cs)
passes the selected referral mask to LDAP_OPT_REFERRALS. These do not implement a
managed child-destination allowlist or isolate Windows token context.

Microsoft's [referral task](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b2edefdd-16f9-413d-88c5-a2f5c137bafe)
derives the destination from the server's URL and associates the referred
connection with the containing connection. Its
[bind task](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7a6dad48-8a6f-4704-8308-e3367ab7440a)
constructs authentication using LDAP_OPT_AUTH_INFO; ambient thread authentication
is described in the SASL branch. That supports explicit-Basic identity reasoning,
but does not establish TLS certificate access equivalence across caller contexts.
Microsoft also documents that
[StartTLS disables automatic referral chasing and autoreconnect](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_start_tls_sw).
The repository configures referral mode after its factory's StartTLS call, so
source inspection alone does not establish the resulting StartTLS behavior here.

## Why an LDAPS/External predicate is not enough yet

LdapConnectionProvider.CanReuse receives primary options and referral mode.
It cannot know the destinations, schemes or recursive referral graph a server
will return. Even restricting the primary to 127.0.0.1 would not restrict its
returned URLs. Such a rule would resemble the fixture configuration without
enforcing the fixture's network scope.

ConnectionKey.Create intentionally isolates exact LDAP credentials and
configuration, not Windows token identity or certificate-access context.
Neither Session.Execute nor SendRequestTracked rechecks Windows context.
An authenticated check at acquisition would not cover a later switch during
the active lease. Streaming result collections can retain leases after
acquisition. Adding a SID/token field only to the key likewise would not enforce
a stable execution context during an active lease.

The observed anonymous fresh-TLS failure makes this a concrete differential to
test. A warm handle might bypass some fresh connection/TLS work; that is a
hypothesis, not an observed bypass or credential-forwarding defect. It can also
matter for a non-referring response while External is configured. Do not equate
LDAP's explicit Basic identity with all OS permissions used during native TLS.

A correct boundary could eventually exclude unsupported transports/modes and
enforce a demonstrated caller-context rule throughout acquisition, execution and
return. That requires evidence and lifecycle design; silently changing
impersonation, dropping referrals, adding forwarding callbacks, pinning certificates
or replaying an operation on a fresh connection would change semantics. None is
introduced by this assessment.

## Smallest next evidence-producing comparison

Use the existing synthetic loopback harness, leaving native validation and
referral handling unchanged. Compare a fresh raw connection against the same
candidate pool path after warming under an authenticated identity:

1. Return the authenticated lease, switch to anonymous, then acquire/execute.
2. Acquire authenticated, switch within the active lease, then execute.
3. In each form compare first-discovered and repeated referrals; include a normal
   non-referring primary response because referral mode does not guarantee every
   response contains a referral.
4. Record native result, observed LDAP identity (only if a bind/search occurs),
   connection/TLS/bind/search counts, exact operation IDs and cleanup; repeat the
   authenticated control to ensure fixture readiness.

The minimal comparison needs only the original runner and the existing anonymous
impersonation primitive, not new A/B accounts. The current full authenticated
harness creates those accounts, so a smaller execution mode would need separate
preparation, pure preflight and review before any approval request. No such mode
is implemented or claimed run-ready here.

These comparisons must run even if the fresh anonymous control fails: failure
parity is the question, not a reason to skip the comparison. The separate adverse
verdict remains failed; it is never relabeled a successful anonymous bind. A warm
success/fresh failure would demonstrate context-dependent behavioral divergence,
not by itself an authorization bypass. Equal failure does not establish all
transports or referral graphs.

This is the smallest next investigation, not a promise that one more run completes
Windows support. It should first be prepared/reviewed with pure orchestration
tests. Any execution that creates accounts/keys or imports the test certificate
needs a new single-job approval; none exists now. No new policy/ACL/profile/account
scope, callback or trust change is proposed. Production eligibility stays guarded,
and issue #236 remains deferred until Windows is actually completed.

Validation of this assessment: 58 focused pool/preparation tests passed on each
runtime after rebuilding. The new regression covers ten primary configuration
variants across every referral mode; no production eligibility behavior changed.
No external publication, trusted Windows execution or security mutation occurred.


## Feasible authenticated-context design (source review only)

Anonymous pooling need not succeed to support an authenticated subset. The
practical distinction is **ineligible for reuse**, not prohibited from LDAP:
anonymous, unreadable or unsupported contexts should follow the existing fresh
connection path with their requested explicit credentials and normal native
validation. Do not turn a token-query failure into a new LDAP authentication mode
or silently substitute the process identity.

A conservative context identifier would include the effective token's TokenId,
AuthenticationId, ModifiedId and TokenType, plus ImpersonationLevel only when
valid for an impersonation token. Include whether the effective context came
from the thread or process token. Normalize the unused primary-token level.
Microsoft's
[TOKEN_STATISTICS documentation](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics)
distinguishes a token object instance from its logon session, allows multiple
tokens in one logon session, and specifies a modification identifier that changes
when the token changes. Thus SID alone and AuthenticationId alone are insufficient.
A TokenId/ModifiedId key conservatively separates filtered/restricted or duplicate
token objects rather than assuming their equivalence. These identifiers are
process-local pool metadata, never credentials or public log fields.

The query design would use TOKEN_QUERY only, with owned safe handles closed
promptly. Query the effective thread token first; only the precise no-thread-token
condition permits querying the process token. Other errors mean no reuse.
[OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
cannot open an anonymous-level token. OpenAsSelf governs the access check for
opening the handle, not which identity LDAP should use; it must never be treated
as permission to perform LDAP under the process identity. Read
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
results with exact native layout/error handling, and reject unknown, anonymous
or identification-level contexts from the first supported reuse subset.
Unsupported restricted/AppContainer cases can also remain fresh until audited.
No token duplication, privilege adjustment, logon, impersonation or profile load
is needed for this query-only design. No token APIs were executed for this review.

The fingerprint belongs beside the existing exact LDAP configuration key, not in
place of it. Acquisition must sample before selecting an idle entry and verify
again after waiting/creation. A pre-send check must occur before any native
request on the selected connection, not merely before invoking an arbitrary
delegate. Completion and return checks must invalidate on mismatch or query
failure, and an idle entry must remain associated with its ORIGINAL fingerprint,
never rekeyed to whoever returns it.

| Boundary | Conservative behavior | Limit |
| --- | --- | --- |
| Before selecting a lease | Unknown/anonymous/unsupported context uses existing nonreusable path | Fresh LDAP may naturally fail; report its original result |
| After acquisition, before first request | Verify effective context still matches; discard stale selection and choose fresh under current context only at a boundary that owns connection selection | Preserve exact auth/referral/validation settings; no unbounded retry loop |
| Before another request in an active multi-request operation | Detect mismatch; never continue using the cached context as though unchanged | Cannot silently replace a paged/cursor/stateful session while preserving its semantics |
| After request/completion | Mismatch makes the connection nonreusable; preserve native result/error | A completed operation cannot be undone; do not retry or invent an authentication failure after a successful write |
| Return/disposal | Check again and dispose on unknown/mismatch | No cross-context idle retention; disposal still runs under failures |

These are detection boundaries, not an atomic lock on Windows security context.
Another component can modify a token or change a thread's impersonation between
checks. ModifiedId detects persistent mutation; checks cannot undo work already
performed under a changed context. A public guarantee against arbitrary concurrent
external token mutation would need a different contract and cannot be claimed
from this design. Holding a token handle does not itself freeze that token or
pin the thread identity. Automatically impersonating a captured token would
change caller semantics and is not proposed.

### Costs and bounded implementation scope

The current APIs do not implement those boundaries. Session.Connection exposes
a stable native object, DirectoryEntry.ConnectionLease forwards it, and most
operations use SendRequestTracked after obtaining that object. Session.Execute
only wraps a delegate. It cannot assume the delegate sends exactly once, never
changes context, or does not retain the connection. DirectorySearcher streaming
captures two leases and uses BeginSendRequest/GetPartialResults/EndSendRequest,
which bypass the synchronous tracked-send helper. A key-only or Dispose-only
change would therefore be incomplete.

A practical first implementation can keep Windows referral sessions nonreusable
by default and explicitly opt in only audited **synchronous, operation-owned**
request paths whose internal API performs acquisition, context verification and
native send without exposing the selected connection to caller code. Start with
buffered single-request reads; keep streaming, asynchronous, paging, callbacks,
retained leases and stateful multi-request operations on their existing fresh
path until separately adapted. The exact list must come from a call-site audit,
not a caller-controlled public override. This sacrifices coverage and reuse
benefit to keep scope understandable.

Before a first send, that internal boundary can discard an unused selection and
use a fresh same-configuration connection when reuse is ineligible. It must not
implement this by catching a native failure and replaying the request. If an
already-started stateful operation changes context, only invalidation is generally
safe without an explicit new API contract; a generic transparent rebind is not.
Keeping those paths fresh initially avoids adding that new contract.

Costs include native query calls at several boundaries, safe-handle lifetime,
Windows-specific interop/layout tests, smaller pools fragmented by exact token
instance and modification, and more fresh binds when query rights are unavailable.
Two token handles referring to the same token can share a fingerprint; two newly
duplicated but otherwise equivalent tokens may not. That loss of reuse is safer
than collapsing them by SID or logon ID. Token scoping also does not snapshot
certificate-store/policy state or enforce the full server-supplied referral graph.

### Recommendation

This design is feasible for a bounded authenticated synchronous subset and does
not depend on making anonymous pooling work. The local candidate now implements an operation-owned boundary and pure
context/lifecycle tests, but ordinary production activation remains disabled.
The tests cover: same SID/different logon, same logon/different token, modified
token, query failure, no-thread-token versus anonymous error, changes before send,
after send and at return, cancellation, and no replay. Audit the selected call
sites and keep every other Windows referral path fresh.

Then the native warm/fresh original-to-anonymous comparison above can verify
exclusion/fallback behavior, alongside same-token reuse and different-token
isolation under normal certificate validation. Only a newly approved disposable
run may execute the security setup. The transport/topology evidence matrix still
applies; context isolation solves one boundary, not every missing dimension.


### Local bounded candidate implementation

The candidate uses a separate HMAC pool-key namespace containing exact token
instance, authentication session, modification ID, token type and valid
impersonation level. It queries only TOKEN_QUERY, closes each handle, and never
substitutes process identity for anonymous/access-denied thread-token failures.
Unknown, anonymous, restricted, AppContainer, identification and delegation
contexts remain fresh-only. Offline tests block all native token queries.

The only proposed caller is synchronous `DirectorySearcher.FindOne` with a Base
search, no controls, paging, asynchronous mode or configuration override, and no
retained connection. Its configuration predicate is still only explicit Basic,
LDAPS on 127.0.0.1, External referrals, normal certificate validation, and no
StartTLS/signing/sealing. All other paths retain their existing behavior. Linux
and non-referral pool keys and eligibility are unchanged.

The internal boundary owns acquisition, preparation, one native send and return.
It checks context after acquisition, immediately before send, after completion
and at return. A pre-send mismatch discards the unused selection and acquires one
fresh connection with unchanged authentication/configuration. Once send starts,
errors or mismatches evict without replay; the native result/error is preserved.
Schema materialization uses a separate explicitly fresh External connection,
including when the root's own referral policy differs. This costs another bind
when schema access is needed. Streaming and retained sessions never opt in.

`ContextScopedProductionEnabled` remains false, with no public or environment
activation switch. The restricted diagnostic entry calls the same core and real
token reader, but has not been executed. Pure tests verify lifecycle decisions,
key separation, cancellation, concurrent exclusive leases, query classification,
interop layout and bounded SID parsing; they do not validate Windows interop or
WinLDAP behavior. Native queries add several system calls per request, and exact
token-instance scoping deliberately sacrifices reuse across equivalent tokens.

The smallest next native validation must exercise this core on both runtimes:
stable-context reuse; distinct token/modification separation; warm-to-anonymous
versus fresh behavior before first and repeated referrals and for a non-referring
primary response; cancellation/failure eviction; and no replay. The eventual
FindOne integration also needs normal native validation including fresh schema
materialization and entry lifetime changes. Existing authenticated ownership
harness can supply the contexts under a separately approved one-job scope. The
new diagnostic entry alone does not activate or validate FindOne. Referral graph,
transport and externally concurrent token mutation limits above still apply;
passing earlier raw/provider tests does not complete this new candidate's proof.


Local validation of this implementation (Linux executor, .NET 8 and 10):

- Focused pool/context regressions: 77 passed on each runtime.
- Full guarded functional group: 13,528 passed and one existing deferred skip
  on each runtime.
- Guarded companion group: 113 passed and 15 platform skips on each runtime.
- Guarded surface group: 34 passed and 12 failed on each runtime. Ten failures
  were Microsoft API PlatformNotSupported exceptions; two compared serialization/debugger
  attributes against the loaded non-Windows Microsoft assemblies. These are
  recorded failures requiring Windows validation, not a passing surface suite.
- Worker Release builds and pure worker/report self-tests passed on both runtimes;
  five offline-runner admission tests passed. No native token, account, key,
  certificate-store or LDAP calls were executed.

Commands used the reviewed `tests/run-offline-tests.py` runner for all three
full groups and both frameworks, with restored dependencies and TRX results.
Focused tests used `ADFL_OFFLINE_TESTS=1` with the context, preparation, pool and
pool-operation classes. Independent static review found no remaining blocker;
this does not replace the outstanding native and Windows surface validation.

The baseline failures and the prepared 31-case native matrix are reconciled in
[the candidate validation plan](windows-context-candidate-validation.md).
