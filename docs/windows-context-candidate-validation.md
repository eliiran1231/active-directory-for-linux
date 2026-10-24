# Context-scoped Windows candidate: next native validation

This is preparation, not a native result or production activation. Candidate
implementation baseline: `57fc6d2d860e330e54c826f564f0bb62224b4732`.
The [evidence boundary](windows-basic-pooling-boundary.md) still applies.
No workflow trigger, security setup, native token query or publication was run
while preparing this suite.

## Surface baseline reconciliation

An isolated detached checkout of unmodified parent `4538b30` used the same
Linux executor, SDK 10.0.100, .NET 8.0.22/10.0.0, NuGet cache and guarded runner:

```sh
python3 tests/run-offline-tests.py surface --framework net8.0 --dotnet /tmp/adfl-dotnet/dotnet --results-directory /tmp/adfl-baseline-net8.0
python3 tests/run-offline-tests.py surface --framework net10.0 --dotnet /tmp/adfl-dotnet/dotnet --results-directory /tmp/adfl-baseline-net10.0
```

Dependencies were restored first. Baseline and candidate each returned **34
passed, 12 failed** per runtime. Comparison of each failed test name and complete
TRX error message was identical on both runtimes; there were no introduced or
removed failures in `57fc6d2`.

Ten cases of `V1ServiceNameTrackingComparisonTests.Collection_change_tracking_matches_microsoft`
failed with Microsoft's `PlatformNotSupportedException`: `add`, `remove`,
`replace`, `duplicates`, `clear`, `clear-reinsert`, `insert-change`,
`change-remove`, `cancel-add`, `cancel-remove`. These execute the Microsoft
AccountManagement implementation, which is unavailable on Linux.

`PublicApiSurfaceComparisonTests.DirectoryServices_surface_matches_microsoft`
reported the `SerializableAttribute` on `DirectoryServicesCOMException`.
`AccountManagement_surface_matches_microsoft` reported the same attribute on
`MultipleMatchesException`, `NoMatchingPrincipalException`, `PasswordException`,
`PrincipalException`, `PrincipalExistsException`, `PrincipalOperationException`
and `PrincipalServerDownException`, plus `DebuggerDisplayAttribute("Name = {Name}")`
on `Principal`. These are unchanged comparisons against the loaded non-Windows
Microsoft package assemblies. They are existing baseline failures, not newly
introduced public API differences. The Windows reference surface check remains
required; this comparison does not turn the Linux suite green.

## Execution path and instrumentation

`WindowsContextCandidateDiagnostic` is standalone, not a discovered test.
The explicit worker argument `--context-candidate` selects it. The fixture's
opt-in `-ContextCandidate` switch forwards that argument through the existing
bounded supervisor/coordinator and selects a strict candidate report parser.
The default worker/fixture mode is unchanged. No workflow was created.

Every native case uses the real `WindowsLdapContextQuery.Capture`, context HMAC
key, shared pool and `ContextScopedRequest` lifecycle. It does not call the older
`AcquireWindowsReferralDiagnostic` eligibility bypass. `FindOne` cases enter a
guarded internal method sharing the public method's request construction,
authority validation, candidate selection, exception translation and result
materialization. Only permission to select the otherwise-disabled candidate is
different. Configuration exclusions still apply; failure to select the candidate
throws instead of silently testing a different path. Public production activation
remains false, with no global hook or runtime enable switch.

Invocation-local hooks expose only a stage name and synchronous one-shot action.
They cannot receive connections, credentials or responses. Continuations reject
repeat, deferred and cross-thread invocation. Existing A/B impersonation wrappers
wrap these actual lifecycle segments; no token adjustment or privilege mutation
is introduced:

| Stage | Exact location and scope |
| --- | --- |
| acquired | After selection/bind, before the post-acquisition capture; wraps preparation and send/completion, then unwinds before the separately checked return |
| send | After preparation, before pre-send capture; wraps mismatch fallback and send/completion, then unwinds before return |
| complete | In the native send's finally block, around post-send capture/invalidation |
| return | Around final capture/invalidation, before actual disposal; the hook fully unwinds before disposal so a post-continuation hook failure can still invalidate |

Hook failures are independently recorded. They evict and cannot replace a
completed native result/error during completion/return. Enclosing hooks cannot
reclassify a recorded post-send hook failure as a native failure. No send replay
is added. Pure regressions exercise these rules, including suppressed exceptions,
escaped continuations and nested-scope unwinding.

## Bounded matrix: 31 cases per runtime

| Cases | Count | Required evidence |
| --- | ---: | --- |
| original/A/B stable | 3 | Real readable stable fingerprint, three requests, one primary bind, exactly three target searches |
| original/A/B failed-bind | 3 | Actual LDAP 49, no searches before recovery, released reservation, succeeding fresh operation |
| original/A/B primary-failure and target-failure | 6 | Warm connection, classified native disconnect failure, eviction, recovery with another primary bind; exactly three managed attempts, no managed replay |
| original/A/B FindOne | 3 | Same FindOne core twice; root policy deliberately None versus searcher External; one pooled primary plus two fresh schema binds; six source searches including four synthetic rootDSE/schema reads, exactly two target searches; materialized description matches explicit Basic identity |
| A→B and B→A at acquired/send/complete/return | 8 | Real distinct fingerprints, one managed request and target search, stale selection never retained; pre-send fallback versus post-send eviction distinguished |
| Nested A→B→A | 1 | A scope remains active across B; exact return fingerprint, two primary binds and three target searches |
| original→anonymous at acquired/send/complete/return | 4 | Anonymous is unreadable/ineligible; pre-send outcome matches fresh anonymous native result, post-send success preserved, no idle lease retained |
| Anonymous fresh versus authenticated-warm: first referral, repeated referral, non-referring primary | 3 | Same native outcome code and bind/search deltas, no reuse for anonymous; the adverse direct control is reported separately |

Authenticated cases independently require that identity's normal native direct
TLS and referral baseline. A/B transitions require both identities. Anonymous
parity cases depend on original's direct/referral baseline, never on anonymous
TLS succeeding. Report status, counters, expected negative native error codes,
instrumentation failures, cleanup and pool delta are separate and strictly
validated. Case cleanup retires only tracked exact scoped keys through existing
freshness logic, using a factory that stops before connection allocation; no
cleanup LDAP bind or read is performed. Every endpoint cleanup is attempted even
if another cleanup fails. Final account/certificate/key/file cleanup remains the
independent supervisor/always-cleanup responsibility.

## Proposed one-job setup and limits

Use the established setup unchanged, only after fresh explicit execution approval:
one disposable GitHub-hosted Windows VM, two unique standard local accounts,
one interactive logon each, existing handle copies for sequential .NET 8/10,
one uniquely owned non-exportable runner-user CNG key and one ephemeral public
LocalMachine Root certificate. Retain the verified private path with unchanged
ACLs, 60-second setup watchdog, 180-second runtime worker bounds, 420-second
coordinator bound, durable exact ownership, terminate-before-cleanup ordering,
all-object cleanup and independent account/certificate/provider-key/file absence
verification. No profiles, administrator membership, token privilege adjustment,
policy/ACL changes, extra logons, secrets in argv/logs/artifacts, automatic rerun
or live AD. The new flags carry no secret. Cleanup needs no candidate-mode flag.

Scope remains explicit Basic, normal validation, LDAPS `127.0.0.1`, External
single-hop referrals and TLS 1.2 loopback endpoints. No StartTLS, plaintext/mixed
transport expansion, subordinate/All policy, hostname variants, domain/delegation
claims or production activation. Synthetic schema replies validate this
materialization path, not general AD schema interoperability. No actual token
ModifiedId mutation is attempted: pure key tests cover that field, while native
cases change existing token instances through existing scopes. Existing native
provider overlap evidence and pure candidate concurrency tests remain distinct;
this 31-case suite is not new native concurrent-operation stress. Arbitrary
external token mutation is not made atomic by these checks.

A passing run would validate this bounded candidate path, not by itself remove
the remaining transport/referral-graph or broader production eligibility limits.

## Safe preparation results

Independent static review completed after fixing three instrumentation defects:
sticky nested-hook failure propagation, deferred/cross-thread continuations,
and disposal preceding a return-hook failure. Negative native outcomes now have
specific classifications and typed parity; these fixes have pure regressions.

On the final local sources, both .NET 8 and 10 passed the full guarded functional
group (13,540 passed, one existing deferred skip) and companion group (113 passed,
15 platform skips). The 89 focused pool/context cases passed per runtime. Final
surface results were again 34 passed/12 failed, with exactly the same failed
names and complete messages as the unmodified baseline. Worker Release builds,
pure helper syntax/token-bridge compilation, both executable report contracts
(including malformed fields, counters, dependencies and typed outcomes), and five
offline-runner admission tests passed. These were pure/local checks; no native
identity/trust/account/key operations were performed.

Remaining unavoidable assumptions for an approved run are actual Windows token
query behavior, nested existing-identity scopes, WinLDAP's TLS/bind/referral
behavior at each lifecycle boundary, and native FindOne/schema requests. The
security setup and filesystem/ownership machinery are unchanged from the
previously validated harness. No claim is made that static/pure preflight proves
those native outcomes. The suite is prepared for one proposed bounded run;
production remains disabled regardless of preparation results.


## Executed candidate run: 40128116055

[The single approved run](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40128116055)
at `238dbbaedd7d10753108d71ad1385f00fb61fcfd` completed on 2026-10-24.
Both runtimes emitted all 31 cases: five passed, 26 failed. All 11 raw authenticated
controls passed; anonymous direct TLS remained LDAP 81 before TLS/bind/search.

The 23 zero-attempt failures occur at the initial readable-context assertion.
The token reader returned null for original, A and B; its then-unreported branch
cannot be attributed to Windows permissions, a particular native query or an ABI
check from this run. Partition used three fresh binds, not two pooled binds.
The five anonymous passes therefore do not establish authenticated warming or
reuse. Pre-send anonymous cases also failed parity; their warm outcome was a
fixture/result assertion rather than the fresh control's LDAP 81.

| Case | .NET 8 | .NET 10 | Attempts / source binds / target searches (both) |
| --- | --- | --- | --- |
| original/stable | failed | failed | 0 / 0 / 0 |
| original/failed-bind | failed | failed | 0 / 0 / 0 |
| original/primary-failure | failed | failed | 0 / 0 / 0 |
| original/target-failure | failed | failed | 0 / 0 / 0 |
| original/findone | failed | failed | 0 / 0 / 0 |
| a/stable | failed | failed | 0 / 0 / 0 |
| a/failed-bind | failed | failed | 0 / 0 / 0 |
| a/primary-failure | failed | failed | 0 / 0 / 0 |
| a/target-failure | failed | failed | 0 / 0 / 0 |
| a/findone | failed | failed | 0 / 0 / 0 |
| b/stable | failed | failed | 0 / 0 / 0 |
| b/failed-bind | failed | failed | 0 / 0 / 0 |
| b/primary-failure | failed | failed | 0 / 0 / 0 |
| b/target-failure | failed | failed | 0 / 0 / 0 |
| b/findone | failed | failed | 0 / 0 / 0 |
| a-to-b/acquired | failed | failed | 0 / 0 / 0 |
| a-to-b/send | failed | failed | 0 / 0 / 0 |
| a-to-b/complete | failed | failed | 0 / 0 / 0 |
| a-to-b/return | failed | failed | 0 / 0 / 0 |
| b-to-a/acquired | failed | failed | 0 / 0 / 0 |
| b-to-a/send | failed | failed | 0 / 0 / 0 |
| b-to-a/complete | failed | failed | 0 / 0 / 0 |
| b-to-a/return | failed | failed | 0 / 0 / 0 |
| anonymous/first | passed | passed | 3 / 1 / 0 |
| anonymous/repeated | passed | passed | 3 / 1 / 1 |
| anonymous/primary | passed | passed | 3 / 1 / 0 |
| partition/a-b-a | failed | failed | 3 / 3 / 3 |
| anonymous/acquired | failed | failed | 2 / 1 / 0 |
| anonymous/send | failed | failed | 2 / 1 / 0 |
| anonymous/complete | passed | passed | 1 / 1 / 1 |
| anonymous/return | passed | passed | 1 / 1 / 1 |

Every case reported Cleanup=true and PoolDelta=0. Both external cleanup passes
verified exact certificate `949D4D947C40DA65F31B28640E278358E8F7CBDE`, the owned CNG
key, PFX and all owned objects absent. Independent final deletion verified all
owned temporary files and the directory absent. Review independently confirmed
these results. Trigger removal is remote `9f0605644ea291d024aebd8db96ce96b872be3f2`
(local `a19f104`). No rerun occurred; production remains disabled.

Next diagnosis is a query-only probe of the existing hosted runner token, emitting
fixed stages and numeric errors without identifiers. It creates no accounts,
logons, tokens, certificates or keys, performs no impersonation or LDAP, and makes
no trust/policy changes. It cannot substitute for a later authenticated native
candidate run, which would require fresh security-setup approval.
