# Windows Basic referral pooling: evidence and production boundary

Current local implementation decision (2026-10-25): extend the reviewed Windows
synchronous Base FindOne / validated LDAPS / External subset to explicitly supplied
ASCII DNS names and canonical dotted IPv4 addresses, retaining token-isolated
keys and lifecycle checks. This is a source-backed generalization, not a remote-AD
native result. The diagnostic capability remains loopback-only. The host predicate
is not a target allowlist. Other Windows referral paths stay fresh. This remains
a limited operation subset, not general Windows Basic pooling across all APIs.
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


## Minimal path from loopback evidence to useful remote-host support

The literal loopback predicate was a fixture boundary, not a property consumed by
the pool/lifecycle algorithm. The pinned
[Protocols 9 Windows implementation](https://raw.githubusercontent.com/dotnet/runtime/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapConnection.Windows.cs)
passes the supplied hostname and port to WinLDAP and connects the resulting
handle. The library's factory, credentials, certificate validation, referral
configuration and scoped-key construction use the same paths for remote names.
The host string is included exactly in the HMAC key, without DNS canonicalization,
alias merging or credential rewriting. Native 31-case evidence validates context
isolation and lifecycle handling on that common path, while earlier negative TLS
and mixed-referral cases validate selected failure/identity behavior. Together
with source review, this supports broadening host eligibility; loopback success
alone would not establish that conclusion.

WinLDAP's [ldap_init documentation](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_initw)
explicitly allows domain names and describes discovery/reconnection. Even one
syntactically valid DNS name need not identify one physical server. We do not set
AREC_EXCLUSIVE/FullyQualifiedDnsHostName, pin DNS results, disable reconnect or
change referrals to obtain pooling. Reuse retains the native session's selected
connection until normal eviction, just as pooling normally retains a connection;
it does not promise a new DNS/DC choice on every operation. Basic does not enter
the SASL credential branch in the pinned
[bind implementation](https://raw.githubusercontent.com/dotnet/runtime/v9.0.0/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/ldap/LdapConnection.cs).

| Constraint | Why it remains or changes |
| --- | --- |
| Literal 127.0.0.1 primary | Evidence-only fence; replaced locally with one explicit ASCII DNS name or canonical IPv4 address. Diagnostic capability retains the literal fence. |
| Exact host/port/credentials/configuration key | Required isolation. Preserve original spelling, including case; never merge aliases or resolve before keying. |
| Internally owned synchronous request | Architectural boundary: can discard an unused lease after a token change and return/evict it without replay after send. No raw connection escapes. |
| Base scope | Evidence-only fence retained for this step. OneLevel/Subtree FindOne use the same single SendRequest boundary, but expanding scopes is distinct from host generalization. |
| Explicit Basic, validated LDAPS, External | Retain tested authentication/transport/referral semantics. StartTLS, plaintext and other masks are not inferred from LDAPS evidence. |
| Authenticated supported token and lifecycle checks | Required for reuse. Anonymous/unreadable/restricted/AppContainer contexts stay fresh, without substituting process identity. |
| Paging, controls, async/retained/streaming paths | Excluded from scoped reuse. Existing retained-handle behavior is unchanged; general Windows referral-provider leases remain fresh. Their mutable/multi-request lifetimes are not covered by the one-shot boundary. |
| Fresh schema reads and ordinary BindAuthority | Preserve audited materialization and existing root-policy semantics. |

The local host recognizer excludes null/empty strings, lists, URLs, embedded
ports, noncanonical numeric IP spellings, IPv6, non-ASCII names and trailing-dot
forms. Exclusion means the existing fresh path, not rejection of otherwise
supported public LDAP inputs. These are conservative eligibility choices, not
new WinLDAP resolution rules. Pure regressions cover accepted/rejected names,
exact case/host/credential/context key separation and the unchanged diagnostic
loopback fence.

No additional trusted fixture or live AD is necessary to establish these managed
routing/key changes. Required next verification is independent review and
ordinary exact-head Windows/Linux/Samba CI on the remote-host change; the green
CI at `2ff9a7f7` predates it and must not be presented as its validation. Remote
DNS/DC failover and certificate-name handling have not been executed here; they
remain native integration limits, not a reason to alter validation or request a
new trust change automatically.

This provides a useful remote-directory operation: repeated known-DN Base
FindOne reads with explicit Basic/LDAPS/External, using the same synchronous
operation ownership proved natively. It does not pool default Subtree FindOne,
FindAll/paging, DirectoryEntry's general reads/mutations or PrincipalContext.
Thus it advances the original Basic-with-referrals goal but does not complete
all Windows operation coverage. The next operation expansion should first audit
single-call OneLevel/Subtree FindOne and its partial-result/continuation handling;
that is smaller than redesigning general leases or commissioning a broad AD
matrix. A targeted native continuation test would be useful additional evidence,
but no such account/key/trust execution is prepared or requested in this step.

No new user security decision is required for the local host extension or ordinary
CI. No additional publication or trusted run was performed in this preparation
step. Existing PR-description publication denial remains untouched.

Local preparation validation: 13,549 full offline functional cases passed with
one existing skip per runtime. After adding explicit ordinary-route DNS and
non-loopback IPv4 cases, all 42 focused scoped-read cases passed on both runtimes.
Independent code/documentation review found no remaining blocker. The remote-host
change is local and not covered by the earlier hosted CI SHA.


## Local OneLevel/Subtree ownership audit and publication manifest

FindOne builds one SearchRequest, overrides SizeLimit to 1 and applies the
nonpaged time budget before selecting the send path. OneLevel/Subtree change
request data, not the synchronous ownership shape. The ordinary path accepts
SizeLimitExceeded partial responses; the scoped path preserves the same partial
response after evicting its lease, without resending. Materialization occurs
after the scoped lease has returned and uses a separate fresh schema lease.
The ordinary preliminary BindAuthority read is not removed.

New local regressions exercise the actual public FindOne request construction
and materialization through an existing delegate-backed ordinary connection:
OneLevel/Subtree, success/partial result, SizeLimit=1 despite a larger configured
limit, no paging controls, one object-resolution read and one search request.
These tests do not simulate native referral following. A separate scoped-lifetime
regression verifies that the original partial-response exception reaches the
outer caller only after eviction and with exactly one send. Eligibility tests
explicitly keep both non-Base scopes outside scoped pooling.

No specific ownership flaw emerged for non-Base synchronous FindOne. The untested
native distinction is a search that returns continuation references, potentially
alongside local entries and size-limited partial results, rather than the fixture's
single referral result. A minimal future native comparison would use that one
response shape with ordinary versus scoped FindOne, check identical first-result/
partial-result behavior, explicit identity, one managed send and pool cleanup on
both runtimes. It need not be a broad AD matrix or a new general lease design.
No fixture execution or scope activation is authorized/performed by this local
audit. The audit regressions were subsequently independently reviewed under the
parent's explicit local-review request; no external action was delegated or used
to bypass the publication denial.

The parent reported rejection of its CI/publication continuation request because
publication authorization and destination were not established. No GitHub write
or external CI was attempted in response. Read-only reconciliation confirmed:

- Public repository: `https://github.com/eliiran1231/active-directory-for-linux`.
- Proposed destination branch: `diagnostic/windows-authenticated-20261024-once`.
- Current branch head: `2ff9a7f7cbca077fc4a6eef09ada5e49be6c1b0b`.
- Existing workflow: `.github/workflows/windows-scoped-final-checks.yml`.
- PR235 source branch remains `codex/issue-15-connection-pooling` at `3b9565e5c467fba402dbfda7d6601260c85bcedc`; it is not the proposed publication destination.

Minimal future action, only after specific publication approval: create one
commit based on the verified destination head, containing the remote-host change,
local audit regressions and documentation, plus a descriptive workflow-name/comment
change to trigger its existing branch-and-path push rule. Advance only that branch
using an expected-head check. No dispatch, new branch, PR-description edit, merge
or trust/account workflow is needed. Recheck the head and pending runs immediately
before any approved write; do not overwrite intervening work.

The changed content relative to that head is these five tracked files:
`docs/connection-pooling.md`, `docs/windows-basic-pooling-boundary.md`,
`src/AdForLinux.DirectoryServices/Ldap/LdapConnectionProvider.ScopedRead.cs`,
`tests/AdForLinux.FunctionalTests/ConnectionPoolOperationTests.cs` and
`tests/AdForLinux.FunctionalTests/WindowsContextScopedReadTests.cs`. The deliberate
workflow trigger edit would be the sixth file. GitHub stores the resulting public
repository commit/tree; the runner checks out the tracked repository, not the
local workspace or its ignored files. No local credentials, keys, PFX, private
certificate material or user files are part of these changes.

The existing workflow uses GitHub-hosted `windows-2025` and `ubuntu-latest`, never
self-hosted runners. Four offline jobs cover both OSes/runtimes, with the offline
guard, builds, pure helper tests, and Windows surface/companion checks. Their
`artifacts/` TRX results are uploaded to this repository's GitHub Actions artifact
storage, named by OS/runtime/commit. GitHub also retains console/build/test logs.
The Linux job builds the repository's Docker image and runs both runtimes against
an isolated disposable Samba fixture using the repository's existing synthetic
test settings, then removes its containers/network; it has no artifact-upload
step. No authenticated Windows fixture, token/account creation, certificate import,
policy/ACL change or user-computer/live-AD access is invoked. The workflow requests
only `contents: read` for its run and disables checkout credential persistence.

Local audit validation: all 59 scoped-read and operation-lifetime tests passed on
.NET 8 and 10. No production scope predicate changed, and no external CI or
publication was attempted. Independent local review of the seven audit regression
cases found no blocker; the remote-host implementation had already passed its
separate independent review. The scoped partial-response test proves delivery to
the outer caller after eviction, not actual scoped FindOne materialization. The
time-limit assertion establishes an upper bound, not exact budget retention.


Minimal continuation evidence: four response scenarios (OneLevel/Subtree crossed
with success/SizeLimitExceeded) should emit SearchResultReference messages beside
a local entry. Compare the ordinary and scoped FindOne paths, including a second
operation to exercise warm reuse, on .NET 8 and 10. Keep returned entry/partial
result parity, exact explicit target identity, one managed send per operation,
strict duplicate-operation checks when no failure is injected, and zero final
pool delta. Schema materialization stays fresh. Any required diagnostic-only
scope capability must remain per invocation and separately guarded; production
Base-only eligibility must not be broadened just to run the experiment. This is
an evidence plan, not a prepared or authorized native/security run. No broad AD,
domain-delegation or credential matrix is required for this scope-specific gap.

### Local continuation comparison preparation (2026-10-25)

After the approved ordinary publication at `3da9a6e8027bccf2794ad70270de1841f3cfdd24`
(run `40217364239`, five jobs passed), subsequent continuation work is local only.
The production predicate still excludes OneLevel and Subtree. The new standalone
`WindowsContinuationDiagnostic.Run` is not wired into a worker mode, PowerShell
report parser or workflow; it cannot be selected by the existing diagnostic job.
No native/account/key/trust setup, external CI or publication was performed for
this preparation.

The minimal comparison has four scenarios: OneLevel and Subtree, each with a
successful or SizeLimitExceeded terminal response. Each scenario runs two real
FindOne calls through the ordinary path and two through the explicitly scoped
diagnostic path, under the original authenticated runner identity. It preserves
External referrals, normal LDAPS validation, explicit synthetic Basic identity,
SizeLimit=1 and no controls. A per-invocation internal capability permits only
the named non-Base scope on the guarded loopback diagnostic; it does not change
public eligibility. Both diagnostic paths reject invalid destination/options
before the preliminary binding-resolution read.

The source emits an application-19 SearchResultReference, a local entry and a
terminal SearchResultDone (0 or 4). This is distinct from the previously tested
SearchResultDone referral (10). RFC4511 sections 4.5.2 and 4.5.3 permit entries and
references before the terminal result, and require a base referral scope when
continuing a OneLevel search. See <https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2>
and <https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.3>.

Measurements preserve returned first-entry labels, result codes, two managed
sends, explicit identity, target search counts, binding/schema reads, scoped
reuse and zero final pool delta. Ordinary and scoped modes use separate endpoint
lifetimes. Both endpoints are stopped and awaited before final count/identity
assertions, so a late extra search cannot be attributed to the next mode or
escape the final counters. Cleanup failures remain separate from operation
failure codes; every owned endpoint and exact tracked pool key is attempted.
Expected source counts are 3 ordinary binds, 4 scoped-success binds or 5
scoped-partial binds; seven searches comprise one binding read, four schema reads
and two continuation reads. The partial path must evict rather than reuse its
scoped lease. These are explicit hypotheses to verify natively, not prior results.

Offline checks can establish BER structure, diagnostic configuration isolation,
pre-bind rejection, stage scheduling, strict final counts, parity comparisons and
existing public request/materialization behavior. They cannot establish whether
WinLDAP under External chasing follows this continuation, how it aggregates a
local entry plus a referred entry with SizeLimit=1, or whether it preserves code
4 and first-entry order. A native normalization, suppressed chase or differing
order must remain visible as a failed/insufficient comparison; do not silently
weaken the assertions. The original direct/referral gates control these original
identity cases independently of unrelated A/B or anonymous failures, while the
report still distinguishes aggregate supported controls and the adverse control.

A no-trust plaintext Windows experiment could investigate BER parsing/chasing
or result ordering with the current identity and synthetic credentials, but
cannot supply LDAPS explicit-referral-identity/context pooling evidence. This
Linux executor cannot provide WinLDAP evidence. No such experiment was executed.
Before proposing a security-changing run, the remaining **safe preparation gate**
is a reviewed opt-in worker/report-parser integration and pure serialization/
negative contract tests. Then the smallest native evidence gate is these four
comparisons on .NET 8 and 10 under the already established authenticated LDAPS
harness, with unchanged exact ownership/watchdog/cleanup safeguards and fresh
execution approval. Additional identities or a broad transport matrix are not
needed merely to resolve this continuation question; extending production scope
still requires evaluating the actual results. Streaming/retained paths and
Kerberos remain outside this preparation.

Local validation: 74 focused checks and 13,573 full offline functional checks
passed on each of .NET 8 and .NET 10 (one existing full-suite skip per runtime).
The offline-runner Python suite passed all five checks. Independent static review
confirmed both pre-bind validation and post-quiescence counter fixes, with no
remaining blocker for this local preparation. Native hypotheses remain untested.

### Completed local continuation integration (supersedes the integration gap above)

The opt-in `-ContinuationCandidate` supervisor switch now forwards
`--continuation-candidate` through the existing bounded worker transport. It is
mutually exclusive with context-candidate and fake E2E modes. The existing
read-only token-reader preflight runs for both runtimes before security setup.
The default worker mode, credential transport, ownership manifest, watchdogs,
normal TLS validation and production eligibility remain unchanged.

`ConvertTo-ContinuationCandidateResult` and the read-only result printer accept
exactly the four comparisons and fixed sanitized observation fields. Passing
rows require all counts, identity, result codes, reuse and cleanup assertions;
comparison verdicts additionally require identical first-entry/result sequences.
Valid operation failures and separate cleanup failures remain visible. Skipped
comparisons require failed original prerequisites and zero operation evidence.
The anonymous adverse outcome remains separate from supported-case verdicts.

The pure `--continuation-report-self-test` emits a marked synthetic report on
both runtimes. Contract tests cover the four-case inventory, 30 malformed-report
rejections, legitimate failed/skipped reports, mode conflicts, and the real
runtime orchestration's stop/dispose path after parser rejection with fake
transport. Eight cleanup combinations verify that key/source/target teardown is
attempted even when earlier teardown fails. No self-test calls native fixture
setup, certificate import or account/token creation.

The inert `tests/windows-referral-diagnostic/Continuation-Once.yml.template`
retains the previously exercised one-job workflow structure. It is outside
`.github/workflows`, contains invalid placeholder run IDs, and is not an active
trigger. Independent review covers it before any proposal to publish it.

One future bundled approval would cover publication to the public
`eliiran1231/active-directory-for-linux` repository's existing
`diagnostic/windows-authenticated-20261024-once` branch (last verified published
head `3da9a6e8027bccf2794ad70270de1841f3cfdd24`, recheck before writing), and exactly
one GitHub-hosted `windows-2025` job using the template copied to
`.github/workflows/windows-authenticated-once.yml` with two fresh manifest IDs.
The job runs .NET 8 then .NET 10 on the same disposable VM: four continuation
comparisons per runtime, each with two ordinary and two scoped FindOne calls
(16 comparison calls per runtime), plus the existing 12 raw controls (11
authenticated stages and the separate anonymous adverse control).

Security scope is unchanged: two unique standard local accounts, one interactive
logon each with token-handle copies, one uniquely owned non-exportable runner-user
CNG key, and one public certificate temporarily in LocalMachine Root. No new
identity, profile, membership, ACL, policy or validation changes are required.
Keep the 60-second setup watchdog and bounded runtime workers; terminate and
verify workers before cleanup. Existing finally and independent always cleanup
must verify exact owned account/certificate/provider-key absence and temporary
PFX/file/directory deletion, even after partial failure. No private key or
password enters logs, arguments or artifacts. The trigger is removed after the
single attempt; no automatic rerun. PR235 remains unchanged and no merge,
deployment or release is included.

Readiness means locally compiled, contract-tested and statically reviewed, not
native-proven. Only actual Windows execution can establish continuation chasing,
size-limit aggregation, ordering and counts under the unchanged LDAPS settings.
An unexpected native result must remain a failed comparison for investigation.
No expansion of OneLevel/Subtree eligibility follows automatically from a run.

Exact proposed publication content relative to that published tree (local only):

- `docs/windows-basic-pooling-boundary.md`
- `src/AdForLinux.DirectoryServices/DirectoryEntry.ScopedRead.cs`
- `src/AdForLinux.DirectoryServices/DirectorySearcher.cs`
- `src/AdForLinux.DirectoryServices/Ldap/ContextScopedReadDiagnostic.cs`
- `src/AdForLinux.DirectoryServices/Ldap/LdapConnectionProvider.ScopedRead.cs`
- `tests/AdForLinux.FunctionalTests/ConnectionPoolOperationTests.cs`
- `tests/AdForLinux.FunctionalTests/WindowsContinuationDiagnostic.cs`
- `tests/AdForLinux.FunctionalTests/WindowsContinuationTests.cs`
- `tests/AdForLinux.FunctionalTests/WindowsReferralEndpoint.cs`
- `tests/run-offline-tests.py`
- `tests/windows-referral-diagnostic/Authenticated-Fixture.ps1`
- `tests/windows-referral-diagnostic/Authenticated-Integration.ps1`
- `tests/windows-referral-diagnostic/Show-AuthenticatedResults.ps1`
- `tests/windows-referral-diagnostic/Test-PoolReportContract.ps1`
- `tests/windows-referral-diagnostic/worker/Program.cs`
- `tests/windows-referral-diagnostic/Continuation-Once.yml.template` (inert reviewed source)
- `.github/workflows/windows-authenticated-once.yml` (only after approval, from that template with fresh IDs; remove after consumption)

Final local integration validation: worker builds passed for both target runtimes;
13,581 full offline functional tests passed per runtime, with one existing skip.
Both runtime serialization contracts passed, including 30 continuation rejection
mutations, valid failure/skipped reports and fake runtime teardown on actual
parser rejection. Pure helper tests passed in direct-file and workflow-wrapper
invocation scopes; fake adapter tests passed. The inert YAML parsed as exactly one
hosted job, one supervisor invocation, attempt-one-only, independent always
cleanup and no artifact upload. Independent end-to-end static review found no
avoidable preparation blocker. No Windows security operation or external action
was performed during this integration.

### Executed continuation comparison: 40222146911

The specifically approved one-job publication ran at
`bc65fd1feb34cb9e59388a8a1ce6f17a5e17d835` (tree
`5bb569fa9a9a8bd244f12d17479b85bc7839e736`, exactly the reviewed preparation plus
fresh-ID trigger). Run: <https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40222146911>,
job `121255836043`, attempt 1. Both runtimes completed; overall failure. The
consumed trigger was removed and its absence verified at remote
`97acd93e162734e93b585c6c393bc5188d0d5d23`. This results note is local only.

All four comparisons failed on both .NET 8 and .NET 10, at the strict final
counts assertion: target binds/searches were zero for ordinary and scoped paths.
No verdict or expectation was relaxed. Each path made two managed sends and
returned `local,local`; successful terminal results were `0,0`, partial results
`4,4`. Source counts matched the prepared expectations (ordinary binds 3,
scoped-success 4, scoped-partial 5; searches 7, binding reads 1, schema reads 4,
continuation reads/references 2). Scoped success reused once; partial results did
not reuse. Every observation had Cleanup=true and PoolDelta=0. The identity
predicate checks observed binds; with no target binds it is NOT target-identity
proof. This establishes local/partial result parity and observed scoped lease
behavior, not continuation-target chasing or identity safety.

All 11 authenticated raw controls passed on both runtimes. The separate anonymous
direct control failed with LDAP81 before TLS/bind/search, as before. Pure
preflight, builds, contracts, fake complete-setup checks and their cleanup passed.

The primary and independent cleanup passes at 18:40:43 and 18:40:45 UTC verified
exact certificate `C6FFA3C4BCEE750F8E26EFDCA6C3C6254503D329`, owned provider key,
PFX and owned accounts absent. Final temporary file/directory absence was verified
at 18:40:46 UTC. Independent read-only review confirmed these results. No automatic
rerun, further security setup, production activation or PR235 update occurred.

Source investigation: Microsoft's WinLDAP Session Options distinguishes
`LDAP_CHASE_SUBORDINATE_REFERRALS` for search references from
`LDAP_CHASE_EXTERNAL_REFERRALS`:
<https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/session-options>.
This makes the fixture's External-only setting a credible explanation for not
following application-19 references. The current logs cannot exclude other
native conditions, including size-limit behavior, so do not claim causal proof.
Changing public policy to All/Subordinate merely to obtain target traffic would
change the tested semantics and is not a fix for External support.

The smallest useful next preparation is to separate two questions: preserve the
unchased continuation/local-result observations as such, and prepare OneLevel/
Subtree **external SearchResultDone referral (code 10)** comparisons under the
unchanged External policy to exercise the applicable referred-target path. Keep
strict managed-send/target identity/count/cleanup assertions on that external
referral test; do not relabel these failed continuation cases as passing target
coverage. Any additional native execution needs a fresh bounded approval. The
non-Base production guard and issue236 prerequisite remain unchanged.

### Corrected local test contract: external operation scope

The failure in run 40222146911 was a target-chasing assertion applied to the wrong
referral category, not evidence of an ordinary/scoped behavioral discrepancy.
Microsoft's WinLDAP `LDAP_OPT_REFERRALS` documentation explicitly separates
subordinate search references from external referrals (Session Options link
above). RFC4511 sections 4.1.10 and 4.5.2–4.5.3 distinguish a terminal referral result
from application 19 references returned during a search. Our Windows factory
passes the requested enum unchanged; External does not mean All. Neither the
documentation nor the ordinary baseline promises subordinate-reference chasing
under External. The run does not isolate whether policy, SizeLimit or another
native condition caused zero target traffic, so exact runtime causation remains
unproven. It would be incorrect to change policy to All to make this assertion
pass while claiming External evidence.

The existing run remains failed under its original strict contract. Its actual
observations still support narrower conclusions: ordinary/scoped local-entry
and partial-result parity, successful scoped reuse, partial-result eviction,
matching managed sends and exact cleanup. They do not establish target identity,
continuation chasing or all-scope pooling safety. No retrospective result edits
or weakening of the old four-case parser/count assertions were made.

A separate local `RunExternal` inventory now has exactly two cases:
`onelevel/external` and `subtree/external`. It emits a terminal external referral
result (10), without local source entries or application 19 references, under the
unchanged External policy. The referral URL retains the requested one/sub scope;
both source and target validate CN=target, that actual scope, SizeLimit=1 and
DereferenceAlias.Never. Only the source's exact binding-resolution/schema reads
are exempt. The target returns CN=referred,CN=target, a valid child for both
scopes. Existing four-case continuation behavior/reporting is unchanged.

Each case compares two actual ordinary FindOne calls and two diagnostic-scoped
FindOne calls. Strict expected observations: two managed sends and two target
searches per mode, nonempty explicit target bind identity without anonymous/SASL,
matching target entry labels and successful results, one scoped warm reuse,
source binds 3 ordinary/4 scoped, seven source searches including one binding
resolution and four schema reads, and zero pool delta after all endpoint/key
teardown. Wrong request scope or malformed traffic fails the fixture rather than
being silently accepted. Counts and WinLDAP referral rewriting still need native
verification; any unexpected assertion remains a failure.

The separate `-ExternalScopeCandidate` / `--external-scope-candidate` mode is
wired through the existing bounded supervisor, token-query preflight, worker and
read-only result printer. `ExternalScopes` has a separate strict two-case parser;
it cannot be parsed as the old `Continuations` inventory. Pure regressions cover
scope/limit rejection, missing/duplicate target traffic, historical continuation
failure preservation, inventory/dependencies, report type separation, 15 new
malformed-report mutations, preserved failure cleanup and all mode conflicts.
The inert `External-Scope-Once.yml.template` differs from the reviewed continuation
template only in its descriptive name and the two mode switches. No trigger was
created, published or executed.

Local validation: both worker builds passed; 13,586 full offline functional tests
passed per runtime (.NET 8 and .NET 10), with one existing skip each. All historical
and new report contracts passed on both runtimes, and pure preflight passed in
both actual invocation scopes. Independent static review found no blocker in
semantics, endpoint validation, cleanup, mode forwarding or report acceptance.
Production non-Base eligibility is unchanged.

The precise remaining question is whether real OneLevel/Subtree FindOne under
External follows a terminal external referral with the requested scope, returns
the same fully materialized result, and safely reuses its scoped primary across
two calls with exact cleanup. This two-case native comparison, combined with the
already observed local/partial parity, is the smallest useful next evidence gate;
it does not test subordinate/All modes, multi-hop, StartTLS, streaming or Kerberos.
A future explicitly approved single job could reuse the same two-account,
one-logon-each, owned non-exportable key/public LocalMachine Root certificate
setup on one hosted VM, .NET 8 followed by .NET 10, with all existing watchdog and
independent cleanup safeguards. It would run two comparisons (eight comparison
FindOne calls per runtime) plus the unchanged 12 raw controls. No such run or
publication is authorized by this local preparation, and none was attempted.
