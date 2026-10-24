# Authenticated Windows referral investigation and diagnostic results

The latest approved real-provider diagnostic completed on 2026-10-24 in run
[40123894559](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40123894559):
37/37 comparison cases passed on each runtime. Both runtimes passed all 11
authenticated raw controls; anonymous TLS still failed. External security-object and
temporary-file cleanup passed independently. All pool fixture cleanup checks passed
in this run; earlier failed target-barrier diagnostics remain documented below. Windows Basic with referrals remains ineligible for
production pooling. Detailed results, local corrections and remaining limits appear
at the end. Earlier plan/approval sections are historical, not execution authorization.

## Evidence and limits

The last trusted run [39855984179](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39855984179)
passed original-identity normal native TLS, explicit Basic referral identity and
retained-primary reuse on .NET 8 and 10. All five referred searches opened fresh
target connections. This was not production pool-key or exclusive-lease proof.
Anonymous native TLS failed, so impersonation-dependent assertions did not run.
Both cleanup paths verified exact certificate removal and temporary PFX deletion.

The subsequent non-mutating native chain probe passed on both runtimes in
[39858341706](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39858341706):
original identity returned a chain with untrusted-root status; anonymous identity
returned FALSE and immediate error 5 (access denied). This does not identify the
denied resource, establish WinLDAP's precise failure cause, or predict a normally
authenticated user's behavior.

The new real-provider plaintext loopback tests exercise eligible Basic + None:
idle credential/password/configuration isolation, simultaneous exclusive leases,
generation boundaries, referral-policy transitions, full-key capacity cancellation,
existing anonymous-scope transitions and transport failure eviction. They do not
cover referral-child identity, TLS, StartTLS or authenticated Windows
identity transitions. Existing fake-resource tests remain useful scheduling tests,
but cannot supply missing native evidence.

## Exact proposed security-sensitive setup (not authorized yet)

One disposable GitHub-hosted Windows VM, one job, .NET 8 then 10 sequentially,
without automatic retries. Create exactly two uniquely named temporary standard
local users with random passwords kept in process memory, no administrator or
other privileged membership, and no changes to logon rights or security policy.
Record ownership and resulting SIDs before proceeding. Abort on existing names.
Acquire one `LogonUserW` token per account with `LOGON32_LOGON_INTERACTIVE` and
`LOGON32_PROVIDER_DEFAULT`; stop on denied logon rather than changing policy.
Use scoped `WindowsIdentity.RunImpersonated` and verify expected identity and
restoration without logging account passwords or token contents.

This proposal deliberately does not load/create user profiles: LogonUser alone
does not load them. If normal native TLS needs profile setup, report that boundary
and seek separate approval rather than adding profile/registry operations.
[LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
and [local profile behavior](https://learn.microsoft.com/en-us/windows/win32/shell/local-user-profiles)
document the token/profile distinction. NEW_CREDENTIALS is unsuitable because it
does not change the local identity being investigated.

Generate one unique short-lived loopback server certificate and temporarily
import only its public certificate into LocalMachine Root. No CurrentUser imports,
private keys in Root, custom roots, certificate callbacks or validation bypasses.
Retain the existing 60-second setup watchdog, stage logs, pre-import ownership
manifest, exact thumbprint and preexistence abort. Keep any server PFX local to the
fixture and exclude it and all credential material from logs and artifacts.

## Stages and interpretation

1. Under original identity and each authenticated identity independently, require
   actual normal native TLS, explicit synthetic Basic bind and search success.
   Managed chain diagnostics remain informational. Anonymous is a separate
   negative control; its failure must not erase authenticated results.
2. Under each passing identity, run callback-free native referral baselines with
   both synthetic LDAP credentials. Record target identity, TLS/bind/search and
   connection counts; reject unexpected anonymous/SASL/credential propagation.
3. Retain a primary handle across A-to-B and B-to-A impersonation scopes, with the
   LDAP credential unchanged, then repeat for the second LDAP credential. Observe
   target identities and new versus retained target connections explicitly.
   Failures block safety claims, without changing authentication semantics.
4. Keep the production guard in place during this diagnostic. If native evidence
   supports a proposal to change eligibility, separately review that proposal and
   prepare real production-provider tests for idle reuse, exact credentials and
   transport/referral configuration, concurrent exclusive leases, return across
   identity transitions, failed bind, source/target disconnect and failure eviction.
   Do not force eligibility in a test and describe it as production-pool evidence.
5. LDAPS results do not establish StartTLS behavior. StartTLS and mixed referral
   transports need explicit endpoint support and their own reviewed matrix before
   any broad Windows eligibility change. Local users do not represent domain
   identities, Kerberos, delegation or live multi-DC behavior.

## Cleanup and stopping rules

Stop and join any timed-out worker before cleanup. In finally and an independent
always step: remove only the manifest-owned exact certificate, verify absence and
PFX deletion, dispose token handles after leaving impersonation, remove only the
two manifest-owned accounts after checking name/SID agreement, and verify their
absence. Never delete a preexisting or mismatched object. Record sanitized stage
outcomes and cleanup checks, not keys, passwords, raw event payloads or tokens.
If cleanup cannot finish, report its exact state; disposable VM destruction is
the last isolation boundary, not a claim that explicit cleanup succeeded.

Required approval is for this one VM's two temporary local accounts, two logon
tokens and one temporary public LocalMachine Root certificate with the above
cleanup. No profile loading, trust-changing rerun, policy changes, live AD, user
computer, merge or release is included. Implementation and independent review of
the account/token helper must precede execution even after approval.

## Integrated preparation (2026-10-24; not executed)

The manual entry point is `tests/windows-referral-diagnostic/Authenticated-Fixture.ps1`.
Its default mode is **Preflight**, which performs no Windows operations. No workflow
was added and nothing was pushed or dispatched for this preparation. The explicit
Supervisor/Coordinator/Cleanup modes must not be invoked before fresh approval.

The supervisor checks both prebuilt runtime workers with `--self-test`, verifies
restrictive inherited directory permissions without changing ACLs, and assigns a
barrier-blocked coordinator to a named, non-inheritable kill-on-close job. A durable
owner record precedes release. The coordinator verifies actual job membership before
mutating anything. The setup deadline is 60 seconds from release, covering account
creation, two logons, certificate export/file writing/import and exact readback.
Stage logs contain fixed labels only.

Exactly two standard local accounts receive only standard Users membership. Created
SIDs are saved before the next mutation. Account passwords remain SecureStrings in
the coordinator; byte buffers are cleared and credentials disposed after logon.
`Authenticated-Token.cs` performs one interactive logon per account, checks expected
SID and absence of the Administrators SID, and keeps those two original tokens until
both runtime workers finish. No profiles or logon-right policies are changed.

Each runtime worker starts behind a bounded private stdin pipe. The coordinator
copies the two existing token handles into that exact process with only QUERY,
IMPERSONATE and DUPLICATE access, non-inheritable. Decimal-string handle values and
expected SIDs travel through the pipe; passwords never cross process boundaries.
Partial handoff kills the contained worker; the OS closes any unadopted handles.
Worker-owned copies are disposed after synchronous impersonation scopes. Restoration
failure hard-terminates the child without FailFast/crash-report invocation. Runtime
minidump/diagnostic collection is disabled per process; no global policy is changed.

Each runtime has a nested containment job. All its descendants must be verified gone
before the next runtime starts. Any infrastructure failure aborts to supervisor
job-wide termination. Cleanup cannot run until process shutdown is confirmed. Finally
and the independent Cleanup mode both remove exact owned accounts/certificate/PFX
and verify absence, attempting independently owned objects even when another object
or the account manifest fails validation. A missing or invalid SID never permits
name-only account deletion. If creation completed but SID persistence was interrupted,
report unresolved ownership; VM destruction remains the final isolation boundary.

`WindowsAuthenticatedDiagnostic` supplies actual native callbacks: normal TLS,
explicit Basic bind and search under original/A/B identity, then each identity's
referral and retained-primary stages independently. A-to-B and B-to-A stages require
both authenticated baselines. The existing anonymous-scope direct test is a separate
negative control. Managed chain results are recorded but never gate native attempts.
No certificate callback, auth fallback, custom trust or production eligibility override
is introduced. All reads are sequential; this does not test concurrent referral-pool
operations. Primary bind/search and target connection/TLS/bind/search/closed counters
are reported separately. Production Windows referral pooling remains disabled.

Output is capped and parsed against an exact schema; raw stdout/stderr and exception
messages are never forwarded. Only sanitized runtime result JSON may be uploaded.
Do not upload the fixture directory, owner/handle records, PFX, raw output, dumps,
compiled binaries or arbitrary logs. The independent Cleanup step must run with the
same run ID even if Supervisor fails. There is no automatic rerun.

### Safe preflight performed

- PowerShell pure tests exercise the actual lifecycle functions with fake Start,
  Assign, partial handle copies, broken release, timeout/cancellation, malformed
  result, stop and cleanup failures. They also cover manifest durability, SID-save
  failures, preexisting names, lookup errors, invalid manifests, failed absence
  verification, private-ACL classification and output field/gate validation.
- All PowerShell files parse. Token/process interop compiles without invocation.
- Both .NET 8 and 10 standalone workers compile. Their `--self-test` entry points
  exercise native-stage scheduling with injected observations, bounded framing and
  x64 interop layout sizes. No Windows security API or loopback fixture is invoked.

### Remaining assumptions requiring the approved Windows execution

Compilation and fake adapters cannot establish hosted Windows behavior. The future
run may stop before mutation if inherited directory ACLs or nested job assignment are
unsuitable. It must not repair them. It may stop during setup if standard Users lack
interactive logon rights, if token copying/querying fails, or if certificate operations
hang. It must not change policy, add privileges, load profiles or retry trust setup.
Native TLS under authenticated users without loaded profiles remains the question
being measured, not a promised result. Actual account/token lifecycle, Schannel results
and independent Windows cleanup are unexecuted assumptions until that one run.

### Exact proposed one-job execution scope

One disposable GitHub-hosted Windows x64 VM; two distinct temporary standard local
accounts with Users membership; exactly two interactive logons, plus non-inheritable
copies of those existing tokens for sequential .NET 8 and 10 workers; the existing
anonymous negative-control scope; one unique one-hour public certificate temporarily
in LocalMachine Root, with the private key confined to the loopback fixture/PFX.
Include the 60-second setup watchdog, contained process shutdown, finally and an
independent always cleanup/absence check. No administrator membership, profiles,
ACL edits, policy/registry changes, live AD, user computer, automatic reruns, merge
or release. All earlier individual trust approvals are consumed.

After fresh approval, a unique run ID must be fixed before Supervisor starts and
reused by the independent Cleanup step. These command shapes describe the proposed
manual job; they are not approval or an instruction to execute now:

```powershell
# Build and pure preflight happen before security-sensitive setup.
dotnet build tests/windows-referral-diagnostic/worker/AuthenticatedWorker.csproj -c Release
# Same preselected unique 32-character lowercase hex ID in both steps:
./tests/windows-referral-diagnostic/Authenticated-Fixture.ps1 -Mode Supervisor -RunId $runId
# Independent always step, even after Supervisor failure:
./tests/windows-referral-diagnostic/Authenticated-Fixture.ps1 -Mode Cleanup -RunId $runId
```

Primary API references: [job object containment](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
[RunImpersonated](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.runimpersonated),
and [standard local group membership](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember).

### Hosted preflight and corrected execution, 2026-10-24

Hosted pure preflight [40092190133](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40092190133)
at `8d1a4a79ea8fa3f263b580b8c22b3072dd754ec9` passed both exact-path invocation scopes on PowerShell 7.6.7,
both worker builds, and .NET 8/10 pure self-tests. The preceding invocation-scope defect was fixed in local
`014770a`: a `GetNewClosure()` callback now uses an inline assertion instead of looking up a script-local function.

The separately approved corrected full job [40092502811](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40092502811)
at `cc4d118076ec533e83656ed914a39cdcdb60df26` passed preflight/builds but stopped at
`Assert-DiagnosticDirectoryPrivate` before ownership records or coordinator execution. Its inherited directory
ACL did not satisfy the existing predicate. The logs do not identify the rejecting ACE or prove which alternate
location would work. No permissions were changed and no fallback was attempted.

Independent always cleanup verified owner/object manifests and PFX absent. No accounts, logons, token acquisition,
certificate imports, or native tests ran. Both runtimes have no native results. Independent review confirmed these
limits. The consumed full-workflow trigger was removed remotely in `391bf2ad21ca4bbb992eb7722a31de27b90f330d`.
No retry is authorized by that consumed single-job approval. A next ordinary diagnostic could classify existing
candidate directory ACLs read-only, without emitting unrelated machine data, changing the predicate, or editing ACLs.
Windows referral-enabled pooling remains guarded.

### Read-only permission evidence and prepared location change

Read-only job [40092919907](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40092919907)
at `276364e28027cd1054143ecdb03492331ed4cde4` found that RUNNER_TEMP and the workspace had
an approved owner but unapproved allow entries: CREATOR_OWNER (inherit-only) and three
standard-user entries, including inheritable read/execute and directory/file creation.
There were no deny entries in those inspected ACLs. This is not merely rejection of an
inherit-only creator placeholder: the standard-user grants present a real confidentiality
concern for normally inherited fixture files. It supports, but cannot reconstruct exactly,
the earlier failed child's rejection on a different destroyed VM.

The existing process-temp, LOCALAPPDATA, and LOCALAPPDATA/Temp directories each passed
the unchanged predicate: only runner/System/Administrators allow entries with full control,
approved owner, container/object inheritance, and no reparse point at the inspected directory.
The check is deliberately conservative, not an effective-access calculator. Windows evaluates
ordered ACEs against a token; denying an earlier right may constrain a later allow. An
inherit-only ACE affects descendants rather than the current object. We do not relax the
predicate based on those possibilities. See [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[ACE inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules), and
[null versus empty DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces).

That first probe contained an output defect: a collection-left PowerShell comparison serialized
raw ACL metadata, including machine SIDs, instead of the intended DaclPresent Boolean. No
credentials, private keys or file contents were output. The correction compares null on the
left and validates every emitted property type and allowed key before JSON serialization.
Pure tests reject nested metadata and exercise collection/null inputs.

The prepared fixture now uses only Get-DiagnosticRoot($env:LOCALAPPDATA, $runId), a fixed
LOCALAPPDATA/Temp/adfl-auth-<id> location, shared by Supervisor/Coordinator/Cleanup and matched
by worker envelope validation. It validates the existing parent and created child with the
unchanged private ACL predicate, rejects reparse components, and stops rather than editing ACLs
or choosing a fallback. Pure path tests cover absent/relative roots and wrong parent/nested paths.
No new fixture directory or security object is created by the read-only/pure validation jobs.

A future approved full workflow must use the same Get-DiagnosticRoot helper for its independent
always ownership check and result reading; it must not retain the previous RUNNER_TEMP expression:

```powershell
. ./tests/windows-referral-diagnostic/Authenticated-Integration.ps1
$root = Get-DiagnosticRoot $env:LOCALAPPDATA $runId
```

No full diagnostic trigger is present. Execution still requires approval for one disposable VM,
two unique standard local accounts and one interactive logon each, token handle copies for
sequential .NET 8/10, and one temporary public LocalMachine Root certificate. The 60-second setup
watchdog, per-worker bounds, worker shutdown before cleanup, exact ownership/absence checks,
and independent always cleanup/PFX deletion remain required. No ACL/policy/profile/admin changes,
automatic retries or pooling eligibility changes are authorized by permission inspection.

Corrected read-only/pure run [40093265557](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40093265557)
at `0b110643a8d6de96017c4bca626d36217f9972f8` passed. All six permission records had scalar Boolean
DaclPresent and no raw SIDs or SecurityIdentifier properties. LOCALAPPDATA/Temp again passed the unchanged
guard; RUNNER_TEMP again failed with four unapproved allow entries. Both invocation scopes, both worker
builds (zero errors, 16 warnings), and .NET 8/10 pure self-tests passed. No fixture child, account, logon,
token acquisition or certificate import occurred. Runtime parent/child/reparse checks and authenticated
native behavior remain unexecuted; the next full run requires fresh explicit approval.

### Ancestor-check defect and consumed private-path run

The single approved full run [40094277415](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40094277415)
at `39a5ceec536ca29385b763ae4fa7124b35e3e06b` passed pure preflight/builds but stopped in the ancestor
check before fixture-child creation, ownership records or security setup. Independent always cleanup verified
owner/object manifests and PFX absent. Neither runtime produced native results; no accounts, logons or
certificate imports occurred. Its approval is consumed; no full retry was made.

Local independent reproduction found a real defect consistent with that failure: Get-Item enriches its result
with PowerShell's PSIsContainer property, but DirectoryInfo.Parent returns ordinary CLR objects without it.
The prepared fix checks DirectoryInfo type, refreshed existence, Directory attribute and absence of ReparsePoint
for every ancestor instead. The private ACL predicate is unchanged. Tests traverse an actual ordinary parent
chain and reject files, missing paths and reparse attributes. Both invocation scopes pass locally. The hosted
failure log does not identify the exact rejecting ancestor, so it does not rule out additional Windows path issues.
The consumed full trigger is replaced only by pure/read-only checks that call the exact guards on the existing
private parent without creating a fixture child or any security objects.

Hosted pure/read-only follow-up [40094550396](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40094550396)
at `71401d373b0d250a1675d53bc569aa561a735727` passed both invocation scopes and the exact corrected
ancestor/private-ACL checks against the existing LOCALAPPDATA/Temp parent. It created no child or security
objects. The full workflow is absent at this head. Child creation/inheritance and authenticated native execution
remain unverified; no additional full execution approval is available.

### Complete non-security setup validation

The prepared E2ESupervisor/E2ECoordinator/E2ECleanup modes exercise this same fixture orchestrator with
explicit TestOnly manifests and envelopes. They never load the real account adapter or PowerShell token
bridge. Fake account/trust state is durable JSON and dummy marker files; no account, logon, token, trust-store,
LDAP or TLS operation runs. A harmless unnamed signaled event stands in for each identity handle: the real
DuplicateHandle/pipe/worker/CloseHandle path is exercised without acquiring tokens. Synthetic observations
have a TestOnly wrapper and separate filenames and must never be presented as authentication evidence.

Filesystem creation, inherited ACL and ancestor checks, atomic ownership writes, parent/child ACL stability,
nested process jobs, bounded frames/output, watchdog shutdown and independent cleanup remain real.
Eleven scenarios cover success, coordinator early exit, partial fake account creation, the actual 60-second
setup watchdog, runtime timeout with a live acknowledged descendant, partial handoff, malformed output,
output overflow, early worker exit, truncated input, and simultaneous fake account/certificate cleanup faults.
Each failure must prove its injection point and terminal stage; generic failure cannot count as a pass.
Cleanup confirms all fake objects absent, checks inherited ACLs on remaining dummy files, and removes only
allowlisted files plus the owned empty child. Batch ownership includes the GitHub run ID; cross-mode cleanup
and worker input are rejected. The full authenticated trigger remains absent.

Hosted results are required before calling this complete. The E2E suite cannot establish real local account/
group privileges, interactive-logon rights, token-specific copying/adoption/impersonation, certificate-store
operations, or native TLS/referral behavior. Those operations remain outside the ordinary test authorization.

Hosted E2E run [40096037926](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40096037926)
at `773e24fc62b79c57894ce2dd6c2c9a61c3c4d8e8` passed all eleven scenarios. The setup-timeout scenario
took approximately 62 seconds, exercising the unchanged 60-second watchdog. Independent cleanup verified
all owned dummy files and child directories absent. Both invocation scopes, fake-adapter unit checks and
worker builds passed (zero errors, 16 warnings). Independent result review confirmed the evidence.

Review identified two additional non-mutating prerequisites: LocalAccounts command/parameter metadata and
shared certificate-material generation/export. The prepared follow-up checks metadata without invoking any
account command. It extracts the fixture's exact material construction/export into a shared helper and checks
public-only DER plus PFX round trips in .NET 8/10 through a bounded pipe. Material is generated solely for this
test, stays in memory, and is decoded with EphemeralKeySet; no certificate store, chain build or private-key
file is used. Public and private key agreement is checked by signing/verifying a fixed dummy challenge, and
source/worker PFX byte buffers are explicitly cleared. See the documented
[EphemeralKeySet semantics](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keystorageflags?view=net-10.0).
The actual Root-store add/remove and native TLS paths remain outside these tests and are not enabled.

Final hosted validation [40096818996](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40096818996)
at `88c0cb0b8ab540f959987709c874406b2647d22c` passed the command/parameter metadata checks, both in-memory
material round trips, both invocation scopes, all eleven E2E scenarios and independent cleanup. All owned dummy
files and child directories were verified absent; builds had zero errors and 16 warnings. Independent review
confirmed the results. No real account/group mutations, interactive logons, identity-token transfers or
impersonation, certificate-store changes, or native TLS/referral operations ran. No further full-run approval
is requested or implied by this evidence. Windows referral-enabled pooling remains guarded.

The remaining approval-dependent tests concern actual account/group permissions and logons, token-specific
transfer/impersonation, Root-store operations and native TLS/referrals. The memory-only material prerequisite
is distinct from the unchanged real TLS fixture's DefaultKeySet loading: Windows may create temporary provider
key containers. CLR disposal normally manages their lifetime; forced termination does not prove explicit key
container deletion. Exact PFX-file deletion therefore must not be presented as proof of all provider-key cleanup;
disposable VM destruction remains the final isolation boundary. No private keys are logged or uploaded. See
[Microsoft's private-key lifetime documentation](https://learn.microsoft.com/en-us/dotnet/core/compatibility/cryptography/9.0/private-key-lifetime).
A future explicitly approved full workflow must retain the same non-security prechecks on its own VM before
account or trust operations; a prior passing VM is evidence, not permission to bypass those checks.

### Prepared explicit provider-key ownership (not executed)

The authenticated helper no longer imports private PFX material. Its former worker
thumbprint check and each TLS endpoint used `DefaultKeySet`, which can persist
provider keys under the executing identity; neither their exact provider nor their
post-termination absence was measured. Endpoint construction precedes impersonation,
so these loads ran as the original runner, not either test user. Ordinary legacy
native fixtures retain their default imports and are outside this change.

An ephemeral-only TLS replacement is not supported by the inspected Windows TLS
implementation in [.NET 8](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Net.Security/src/System/Net/Security/SslStreamPal.Windows.cs)
and [.NET 10](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Net.Security/src/System/Net/Security/SslStreamPal.Windows.cs).
Preparation therefore uses one explicitly named RSA-2048 user key in Microsoft
Software Key Storage Provider. Creation forbids overwrite and export, records the
original runner SID and unique run-derived name before creation, and durably records
ownership plus SHA-256 of the public SPKI before certificate preparation. No machine
key, key ACL change, or access grant to test accounts is requested.

The certificate is generated against that key. Only public DER is written or added
to Root; the authenticated path exports no PFX/private key. Both workers open the same
named key under the original identity, validate its recorded properties and public
hash, and attach it to the matching public certificate. Native TLS validation and
referral authentication are unchanged. Runtime's
[persisted CNG attachment path](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/X509Certificates/CertificatePal.Windows.PrivateKey.cs)
references the existing key before considering private export; this is source evidence,
not a successful Schannel test.

After workers are stopped, finally and independent cleanup each process the provider
key separately from accounts, Root certificate and PFX absence. Only an `owned`
manifest with matching SID/provider/name/properties/SPKI permits `CngKey.Delete`.
An interrupted `creating` record is unresolved and is never grounds for deletion.
Key-query/access errors are failures, not absence: runtime
[CngKey.Exists](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CngKey.Exists.cs)
returns false only for `NTE_BAD_KEYSET`. Successful deletion is followed by an absence
query and the distinct `CLEANUP verified owned provider key absent` line; failures
emit `CLEANUP failed ProviderKey` and do not suppress other cleanup categories.
PFX absence remains a separate check, never evidence of key deletion. An interruption
between key creation and durable ownership can still require VM destruction as final
isolation; it must be reported as unresolved cleanup rather than success.

Pure fake tests cover preexisting keys, creation failure, failed ownership save,
creating records, wrong SID/public hash, delete/query failures, a key remaining after
delete, and already-absent keys. They also verify certificate/key failures cannot
suppress PFX cleanup. The actual manifest-writer callback is exercised with dummy
JSON in both invocation scopes. No test calls native key creation/open/delete.
The existing memory-only material round trip remains ephemeral and does not validate
this named-key path.

Any future single full job needs explicit scope for this one persisted user-provider
key in addition to the two standard accounts, two logons and public LocalMachine Root
certificate. It must verify original-identity key creation/reopening, non-exportability,
normal Schannel TLS on both runtimes, identity-specific native stage dependencies,
and independent provider-key/account/certificate/PFX cleanup. No such job or trust
trigger is added here. This preparation does not establish referral pooling safety;
the production Windows referral guard remains unchanged.

Local preparation validation passed: both exact invocation modes (including the real
manifest-writer closure and fake ownership/cleanup regressions), fake-adapter tests,
in-memory material checks on .NET 8/10, worker self-tests on both runtimes, and worker
build (zero errors, 16 existing warnings). Independent static review found no remaining
preparation blocker after callback-scope and explicit key-property fixes. No hosted job
was launched for this change and no persistent key operation was executed. The earlier
hosted E2E run predates this key implementation and must not be described as validating it.


### Approved owned-key authenticated execution: 2026-10-24

Exactly one job ran: [40098419409](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40098419409),
job `120885412022`, exact source commit `efd12243f345bf2c341aa3795e16e66db6802648`.
Its tree `5c5cd2f6261ae16c477271ab89c4de03f0f7923d` matches local `84d7098`, which
contains reviewed key implementation `2203b55` plus the one-job workflow and sanitized
key-stage reporting. Trigger removal is public commit `c2ea545d83f559e40dbea39731afde5c2b127dff`
(local equivalent `a668d65`). No rerun was requested; PR #235's branch was not changed.

The same VM first passed both exact invocation scopes, fake adapter checks, builds
(zero errors, 18 warnings), command metadata checks, both ephemeral material checks,
all eleven complete safe E2E scenarios and independent dummy cleanup. Real setup then
completed two unique standard local accounts, one interactive logon each, the single
owned non-exportable user CNG key and public LocalMachine Root certificate. Stages
reached `net8`, `net10`, and `complete` without setup/watchdog failure.

Each runtime reported the same native observations:

| Stages | Result | Target connections / TLS / binds / searches | Primary binds / searches |
| --- | --- | --- | --- |
| Original, A, B direct (each) | Passed | 2 / 2 / 2 / 2 | 0 / 0 |
| Original, A, B referral (each) | Passed | 2 / 2 / 2 / 2 | 2 / 2 |
| Original, A, B retained primary (each) | Passed | 4 / 4 / 4 / 4 | 2 / 4 |
| A→B and B→A (each) | Passed | 4 / 4 / 4 / 4 | 2 / 4 |
| Anonymous direct | Failed, LDAP 81 at bind | 1 / 0 / 0 / 0 | 0 / 0 |

Every successful search checked the returned explicit synthetic LDAP identity; zero
anonymous or SASL binds were observed. Target closed counts matched connections.
Each runtime therefore had 11 passing authenticated stages and one failed anonymous
negative control. The coordinator returned exit 1 and the job correctly reports
failure; it did not fail during setup. Anonymous failure still does not prove its
precise WinLDAP/Schannel cause, and it is not evidence of credential substitution.

Finally and the independent cleanup step each verified certificate thumbprint
`CB74EA4C04213A67AF0E80D4BF354BD01D1CC1F2` absent, owned provider key absent, PFX absent,
and all owned objects absent. Account absence is established by the two-entry
name/SID ownership checks and aggregate successful cleanup, not individual account
log lines. Independent cleanup then deleted only allowlisted owned files and verified
the temporary directory absent. No PFX/private-key file was generated by this new
path. Named-key creation, reopening, Schannel use, explicit deletion and independent
absence verification are now observed in this fixture, not inferred from PFX deletion.
Independent review confirmed the logs and these limits.

These are sequential native-connection tests. Retained **primary** connections were
reused; every referred search opened a fresh target connection. The production pool
was never invoked for referral-enabled connections. Remaining evidence includes real
production pool-key/credential isolation, exclusive concurrent leases, referral failure
cleanup/eviction and transport distinctions (particularly StartTLS versus LDAPS), with
appropriate ambient-identity transitions. Existing plaintext Basic+None provider tests
do not fill those gaps. Production eligibility remains unchanged and Kerberos #236
has not been started. All individual execution approvals are consumed; no automatic
security-changing rerun or full trigger remains.

### Prepared production-pool integration candidate (not executed)

`WindowsReferralPoolDiagnostic` now prepares 34 actual-provider cases per runtime,
separate from the 12 raw native observations above. No new account, logon, token,
persisted-key or trust operation has run for this preparation, and no full workflow
has been added. Production `CanReuse` is unchanged.

The narrowly internal friend-test entry `AcquireWindowsReferralDiagnostic` calls the
same private acquisition core, static production pool, exact `ConnectionKey`, native
factory, `Session`, and failure tracking as ordinary callers. There is no global
eligibility override and no public switch. Its diagnostic configuration is fixed to
Windows hosted CI, IPv4 loopback, explicit Basic, normal-validation LDAPS, External
referrals, and no StartTLS/signing/sealing/certificate-skip flags. The worker must also
supply its owned-key directory. These environment checks prevent accidental invocation;
they are not an adversarial security boundary. Only the standalone fixture calls this
entry. Normal application acquisition still follows the existing guard.

For each of original, A and B, the prepared cases cover:

- Idle original-key reuse while different explicit identity, timeout, endpoint port
  and None referral policy acquire distinct native primary handles. A separate
  wrong-password case must perform a fresh rejected bind while leaving the valid idle
  key reusable. Existing pure tests cover exact key separation for all other settings;
  rejected candidate transports/settings are not called native-tested.
- Two distinct simultaneous leases, with both target operations reaching a bounded
  rendezvous before either response is released. Tasks inherit the surrounding
  impersonation context, verify their actual SID without logging it, and are all
  joined before leaving the existing synchronous token scope. This exercises concurrent
  operations rather than sequential reads. The token/logon API is unchanged. See
  [RunImpersonated async-context documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.runimpersonated).
- Eight held leases, cancelled ninth acquisition, no additional bind, and admission
  of the exact returned lease afterward.
- Generation boundaries, fresh checkout while an old lease is held, late return,
  and rejection of the old native handle.
- Primary disconnect and referred-target disconnect separately. The operation delegate
  must run once; an actual native LDAP/protocol failure must be classified by production
  code and evict the lease before reacquisition. Response/identity assertions occur
  outside the tracked operation, so manufactured fixture exceptions cannot prove native
  eviction. An unresolved Referral response is reported distinctly and fails this case
  if production does not classify it as connection failure. Native reconnects are not
  mislabeled as managed replay.
- Referred-target bind rejection without anonymous/SASL fallback; an untrusted target
  certificate without bind/search; and a mixed LDAPS-primary/plaintext-referral control
  comparing raw native behavior against two pooled acquisitions. The untrusted public
  certificate uses the same owned named key, a distinct self-signed subject, and no
  store import or extra private-key container. Negative resolution alone does not
  identify the precise TLS failure cause. Mixed behavior reports explicit/anonymous
  bind observations without adding callbacks or changing authentication. Its per-read
  bind-presence comparison may conservatively fail if WinLDAP reuses an already-bound
  target; such a result needs interpretation, not a claim of changed semantics.

Four further cases acquire/return/reacquire across A→B→A and B→A→B for both explicit
LDAP identities. Two discover the first referral only after the identity switch.
They require the same primary handle and unchanged primary bind count across leases.
Each fixture invalidates active leases, retires every exact successful idle key using
existing freshness semantics, disposes endpoints, and requires the production pool's
total to return to its initial value. Cleanup binds are explicit and included in
primary counters; they never replay searches. Failure cleanup remains observable.

The worker report has separate `Native`, `Pool`, `Supported`, `Adverse`, and `AllPassed`
fields. `Supported` requires the authenticated raw stages and every dependent pool
case; `Adverse` independently reports anonymous direct behavior. Anonymous failure
still keeps `AllPassed=false` and the worker/job failing. Schema validation rejects
missing/extra fields, inconsistent verdicts, dependency bypasses and incomplete
passing evidence. `Show-AuthenticatedResults.ps1` reads and emits only this sanitized
schema. Fake E2E results retain their separate TestOnly format. A new pure worker
serialization contract exercises the real .NET 8/10 JSON through the PowerShell
validator with an explicit synthetic discriminator.

### Next single-job proposal and remaining evidence

The next proposed job is one disposable hosted Windows VM using two unique standard
accounts, one interactive logon each, copies of those tokens for sequential .NET 8/10,
one uniquely owned non-exportable user CNG key, and one public LocalMachine Root test
certificate. It additionally uses concurrent scoped operations on the same tokens and
an untrusted **public-only** certificate backed by the same key; no additional logon,
key container, trust import or policy change is needed. All complete safe prechecks,
including `Test-PoolReportContract.ps1`, must pass on that VM first. Existing private
path guards, setup/runtime watchdogs, stop-before-cleanup, ownership manifests and
finally plus independent account/certificate/provider-key/file absence checks remain
required. Use the new report reader before allowlisted temporary-file deletion. There
is no automatic rerun and no approval for this job yet.

Even all 34 cases passing would cover only this fixture's TLS 1.2, IPv4 loopback,
External-referral scenarios and the two local authenticated identities. StartTLS,
other primary transports, hostname variants, Subordinate/All policy, multihop/cycles
and domain delegation remain unvalidated. Crucially, a primary LDAPS configuration
does not constrain native referral target URLs; a production LDAPS-only eligibility
check cannot silently assume every target is also trusted LDAPS. Mixed and negative
controls are necessary but do not establish every referral graph. No broad guard
removal is proposed. Actual production eligibility must wait for the candidate results
and a defensible supported scope or additional evidence. Kerberos #236 remains deferred.

Preparation validation (local Linux, no native Windows/security operations): both
runtime builds and worker self-tests passed; both exact PowerShell invocation scopes
passed; the synthetic C#→PowerShell report contract passed on .NET 8 and 10; 45 focused
pool/policy/scheduler tests passed per runtime; the full allowlisted functional offline
runner passed **13,496 tests + 1 existing cross-DC skip per runtime**, with zero failures.
`tests/test_offline_runner.py` passed all five runner-safety checks. Independent review
found no remaining static preparation blocker after correcting failure attribution
and per-case schema checks. These results are not hosted Windows execution or native
pool safety evidence. Changes remain preparation-only, with no full trigger installed.

### Actual production-pool diagnostic: 2026-10-24

Exactly one approved job ran: [40113617612](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40113617612),
job `120930254286`, source `8bee2ea3c55e93df1e6175934ef56aa357c621c3` (tree
`1dd8c87bb5a6b430e6d081449ab1ca63370bbd10`, local equivalent `07118e6`). This contains
candidate `915294a` and the reviewed single-job workflow. The publication's create-tree
call initially remained pending; its confirmed result was reconciled before commit/ref
updates, with no duplicate launch. The consumed trigger was removed at public commit
`c096f7e02af08cadb7f87ab84af6ad9bf4f75dc3` (local `7ca090f`). PR #235 remains unchanged.
GitHub's job-step endpoint returned empty/stale step data while running; the completed
job log supplied the actual stage results.

Safe invocation checks, builds, metadata/material checks, both report contracts, all
11 complete fake-security E2E scenarios and dummy cleanup passed before real setup.
Both real runtimes reached `complete` and emitted all 34 pool cases. Their raw native
controls again passed all 11 authenticated stages; anonymous direct failed with LDAP
81 before TLS/bind/search. Both Supported and Adverse verdicts were failed, and the job
correctly returned failure. No retry was requested.

Every pool case is accounted for below; O/A/B are original runner, local account A,
and local account B. Four transition cases are listed separately.

| Case | .NET 8 O / A / B | .NET 10 O / A / B |
| --- | --- | --- |
| isolation | pass / fail / fail | pass / fail / fail |
| concurrent | pass / pass / pass | pass / fail / pass |
| capacity | pass / pass / pass | pass / pass / pass |
| generation | pass / pass / pass | pass / pass / pass |
| failed-bind | pass / pass / pass | pass / pass / pass |
| primary-disconnect | pass / pass / pass | pass / pass / pass |
| target-disconnect | fail / fail / fail | fail / fail / fail |
| target-bind-rejection | pass / pass / pass | pass / pass / pass |
| untrusted-target | pass / pass / pass | pass / pass / pass |
| mixed-referral | fail / fail / fail | fail / fail / fail |
| A→B→A idle reacquisition | pass | pass |
| B→A→B idle reacquisition | pass | pass |
| First referral after A→B, then A | pass | pass |
| First referral after B→A, then B | pass | pass |

Totals: .NET 8 **26 passed / 8 failed**; .NET 10 **25 passed / 9 failed**. Positive
candidate cases used actual production pool leases. They do not enable ordinary
production eligibility or validate broader transports/referral graphs.

Finally and independent cleanup both verified exact certificate thumbprint
`45E77954588F98B9637DBB25CC284016B525A511`, owned provider key and PFX absent, plus aggregate
owned-object/account absence. Independent temporary-file cleanup verified all owned
files and the directory absent. These successful external cleanup checks must not be
confused with individual pool rows' `Cleanup=false` (in-process lease/key-retirement,
endpoint teardown or pool-count verification).

### Failure interpretation and local corrections

Independent review confirmed the A/B isolation fixture design defect: after two
successful assertions and three reads, it constructed the alternate TLS endpoint
inside impersonation. The owned-certificate loader then needed the runner's private
manifest/key. Both failures reported `0x80070005`, consistent with that boundary.
All endpoints, including the alternate source, are now prepared before entering any
identity scope. No ACL or key permission changes were made. The alternate endpoint
is readonly after construction; a pure lifecycle regression checks preparation order
and prevents entering the scope after setup failure. Windows execution of this fix
is still unverified.

All six target-disconnect rows recorded four assertions, three managed invocations,
and observed directory error 52; replacement acquisition was reached. Cleanup then
failed. The old report overwrote any operation exception with generic cleanup
`0x80131509`, so neither a completely successful recovery nor the cause of cleanup
failure can be claimed. All mixed-referral rows completed 14 comparison assertions,
observed unresolved Referral response 10 and three target TCP connections, but zero
binds/searches. Their cleanup also failed. The old fixture did not classify first
bytes on plaintext targets, so these observations do not establish which transport
WinLDAP attempted there. .NET 10 A-concurrent reported three target searches, two
binds and three TLS connections for two managed invocations, with four completed
assertions and failed cleanup. Its cause remains unresolved; it is not evidence of
managed replay or a proven pool defect.

Local instrumentation now preserves original operation errors when disposal also
fails, including during partial construction. Cleanup attempts every category and
reports fixed mask bits and numeric HResults: 1 active-lease disposal, 2 exact-key
retirement, 4 alternate endpoint, 8 primary endpoint, 16 target endpoint, 32 pool
count mismatch; PoolDelta is reported separately. Fixed failure-point labels distinguish
setup, ambient-identity checks, concurrent-count assertions, response shape/identity,
native response/exception, and cleanup. No messages, payloads, paths or secrets enter
these reports. First-byte protocol classifications now also cover plaintext targets;
only TLS/BER category counts are emitted, not bytes.

Source review and pure tests also reproduce a separate parser defect: the fixture
assumed every non-Unbind operation was constructed, while
[RFC 4511 section 4.11](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.11)
encodes Abandon as a primitive application-tagged message ID. It now consumes that
primitive and emits no response, recording only a count. This is parsing support,
not full cancellation of an in-flight search. Malformed encodings still fail. The
completed job did not record Abandon operations, so this correction is **not** claimed
to explain its cleanup failures. Unexpected protocol/teardown failures remain visible;
no success assertion was weakened.

Local validation passed: both runtime builds, 49 focused pool/preparation tests per
runtime, both invocation-scope regressions and .NET 8/10 synthetic report serialization
contracts. Four added pure tests cover preparation-before-impersonation, preserving
original errors while attempting all cleanup, separate cleanup attribution and Abandon
encoding. Independent static review found no remaining blocker. No new account,
logon/token, key, store, policy or ACL operation was executed during correction.

The next proposed test is one separately approved disposable job using the same two
standard accounts/one logon each, one owned non-exportable user key and one public
LocalMachine Root certificate, with complete safe prechecks and exact independent
cleanup. It would rerun the 34 cases on both runtimes to verify isolation setup and
identify the remaining native/cleanup failures through the new fields. No such job
is authorized or triggered here. Production Windows referral pooling remains guarded;
Kerberos #236 remains deferred until actual Windows completion.


## Corrected diagnostic completed; remaining fixture preparation

Run [40115032176](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40115032176)
executed source c293e013744cad84a5cc91f842111d841c077e98 once. The dedicated
trigger was removed at 05c511c81007014168deeedcf37138bf1d42649e. This consumed
the approval described in the preceding historical proposal.

Both runtimes passed all 11 authenticated raw stages. Anonymous direct TLS
still failed (LDAP 81; no TLS, bind or search). Pool results were:

| Runtime | Passed | Failed cases |
| --- | --- | --- |
| .NET 8 | 31/34 | original/A/B mixed-referral |
| .NET 10 | 29/34 | original/A/B mixed-referral; original/B concurrent |

All other cases passed, including all A/B credential-isolation and
target-disconnect cases. This verifies the previous fixture lifetime correction
under these test conditions, not general Windows referral eligibility.

Every mixed-referral failure had three TLS prefixes on the plaintext target,
zero BER prefixes, TLS handshakes, binds and searches, PoolDelta=0 and target-only
cleanup mask 16. The target cleanup code was -2146233087 (InvalidDataException);
the observed native result was response 10. The plaintext endpoint tried to parse
a TLS hello as BER. The new local fixture explicitly closes TLS-prefixed
connections only on this designated plaintext negative control and counts those
rejections. This preserves the failed-protocol behavior without manufacturing a
fixture parser error. All other malformed protocol errors still fail. Raw versus
pooled outcome/credential comparisons remain required. These new changes have
not been executed against WinLDAP.

The .NET 10 original/B concurrent failures had three target searches for two
managed operation callbacks, three TLS connections but two binds, PoolDelta=0,
and target-only cleanup mask 16 with -2146233083 (TimeoutException). Their original
failure point was concurrent-counts. The fixture's three-second overlap wait
timed out. Native reconnect/replay versus scheduling effects is unresolved;
there is no evidence yet permitting the extra search to be accepted.

Local preparation replaces ThreadPool client tasks with two dedicated workers,
waits until both are ready, releases them together, verifies the actual Windows
SID in each operation, and joins every started worker before leaving impersonation
or disposing leases. The external watchdog remains the bound for hung native
calls. Report fields now include worker readiness, operation starts, overlap
arrivals/timeouts and intentional TLS rejections. Passing concurrent cases still
require exactly two starts, two overlap arrivals, zero overlap timeouts, two
managed callbacks and two target searches. No count assertion was relaxed.
Pure tests cover context flow, dedicated-thread overlap, joining after failure,
narrow TLS rejection and strict report rejection of duplicate/timeout evidence.

Finally and independent cleanup both verified absence of the exact public
certificate 9BA9A74B67ED3FD16612972771232BFC3BE6DE39, owned CNG key, accounts and
PFX; independent cleanup also verified temporary files and directory absence.
These security-object cleanup results are separate from the endpoint cleanup
failures above.

Independent static review found no blocker in the local preparation. No further
security-changing job is authorized or started. The next evidence-producing
proposal is one separately approved disposable job running the same 34 cases on
both runtimes with the unchanged two standard accounts/one logon each, owned
non-exportable runner-user key, public LocalMachine Root certificate, watchdogs
and independent exact cleanup. It must resolve the remaining concurrent duplicate
search evidence, not reinterpret it as success. Production Windows referral
pooling remains guarded; LDAPS IPv4 loopback External referral evidence does not
cover StartTLS, broader referral policies or domain delegation. Issue #236 remains
deferred until Windows pooling is actually completed and validated.

Local validation of this preparation: both runtime builds passed (zero errors),
52 focused pool/preparation tests passed per runtime, both PowerShell invocation
scopes passed, and both runtime pure worker and synthetic report contract checks
passed. These checks perform no native account, token, trust or key setup and
cannot validate the remaining WinLDAP behavior.


## Synchronized diagnostic executed once: remaining concurrent search failure

The freshly approved run
[40116076575](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40116076575)
executed candidate 2f7d3ef plus its dedicated workflow at remote source
ce45cb7bc65cb56163ab067351a9df9cfdf8e52c (local equivalent f1b547c;
tree bd9563be6327c7322902fad4f001466df73dfcaa). No duplicate or pending run
was present before publication. The trigger was removed at remote
c1c6681d16bc33ed4322bd50cc3f4943d7b8921c (local equivalent f41513f).
No automatic rerun occurred. This approval is consumed.

Both runtime builds, pure invocation-scope/report checks and all eleven complete
fake-adapter setup/containment scenarios passed on hosted Windows before real
setup. Both runtime workers completed and emitted all 34 pool cases.

| Runtime | Pool result | Failed cases |
| --- | --- | --- |
| .NET 8 | 32/34 | A-concurrent, B-concurrent |
| .NET 10 | 32/34 | original-concurrent, B-concurrent |

All other cases passed. In particular, all six mixed-referral cases now passed
with three deliberately rejected TLS prefixes, zero BER, binds or searches,
matching raw/pooled response 10, and clean fixture disposal. This verifies the
narrow negative-control correction on this run; it does not establish general
mixed-referral transport safety.

Each of the four concurrent failures recorded:
- WorkersReady=2, OperationStarts=2, ManagedAttempts=2;
- OverlapArrivals=3, OverlapTimeouts=1, TargetSearches=3;
- TargetConnections=3, TargetTls=3, TargetBinds=2, Closed=3;
- Anonymous=0, Sasl=0, SourceAbandons=0, TargetAbandons=0;
- FailurePoint=concurrent-counts; target-only cleanup mask=16,
  TargetCleanupCode=-2146233083 (TimeoutException), PoolDelta=0.

The endpoint increments its search counter once per decoded application-tag-3
LDAP request and invokes the overlap callback once at that same point. Thus the
three arrivals are three parsed requests, not a counter increment at both send
and completion. The provider operation delegate ran exactly twice; no third
managed callback was observed. This distinguishes the wire-observed extra search
from managed replay, but does not identify which request was retried or why.
Two worker starts do not establish when each native request entered WinLDAP or
reached the target. A native reconnect/retry following the fixture's overlap
timeout is plausible, not proved. Dedicated client workers did not eliminate the
failure, and neither thread scheduling nor native serialization can be ruled in
from aggregate counters. The passing concurrent cases had exactly two starts,
callbacks, overlap arrivals and target searches, with no overlap timeout.

All 11 authenticated raw stages passed on both runtimes. Anonymous direct TLS
still failed with LDAP 81 before TLS/bind/search; both Supported and Adverse
verdicts correctly remained failed.

Finally and independent cleanup each verified the exact public certificate
5E799F26C7117A59672892400A795D75E29667FE absent, owned provider key absent,
PFX absent and all owned objects/accounts absent. The final independent step
verified temporary files and directory absent. This is distinct from the target
endpoint timeout failures. Independent read-only review confirms the results.

The next useful preparation is a sanitized, bounded event timeline correlating
synthetic operation IDs with managed entry/exit, source referral requests, target
connection/bind/search, overlap timeout and close. A raw unpooled concurrent
baseline using the same endpoint and scheduling would distinguish pool-specific
behavior from native/fixture behavior. Preserve the strict two-operation/search
gate and compare timing evidence before proposing a fix or extending timeouts.
These additions are only a next-step proposal, not executed in this run. Any
further account/key/trust setup requires a new approval. Production eligibility
remains guarded, and no merge, release or Kerberos implementation occurred.


## Correlated timelines and independent unpooled controls prepared locally

The remaining concurrency failure now has a prepared comparison, without any
additional native or security setup. The fixture's source confirms the original
three-second overlap timeout escapes the search handler, reaches its finally
block and closes that target connection. This provides a concrete possible
trigger for native reconnect/retry. It does not prove that WinLDAP retried, which
operation it retried, or whether the pool contributed.

The prepared suite has 37 cases per runtime: the existing 34 plus an
unpooled-concurrent case for original/A/B. Each unpooled case uses two explicit
connections from the same production connection factory, options, External
referral policy, synthetic LDAP identity, target/source endpoints, dedicated
workers and three-second overlap barrier. It calls no provider acquisition,
session execution, key or generation path. Both raw connections become owned
before configure/bind so partial setup failures still dispose every created
connection. Pooled and unpooled cases are independently gated on that identity's
actual native direct/referral controls; failure in one comparison does not skip
the other. The six comparisons retain exact two-worker, two-managed-operation,
two-overlap-arrival and two-target-search requirements and actual SID checks.

Only these six cases record timelines. Each operation uses a fixed synthetic
base DN (CN=operation-1 or CN=operation-2), carried through the fixture-generated
referral's base DN. The endpoint rejects unknown correlation DNs rather than
logging them. It records fixed event labels and numeric IDs only; no credentials,
raw LDAP bytes, host/user names, certificate material or exception text enters
the timeline.

Timeline encoding is:
sequence:elapsedMicroseconds:role:connectionId:messageId:operationId:event
with semicolon-separated events. Sequence and monotonic elapsed time are captured
under one lock shared by client/source/target within the case. Connection IDs
are endpoint-local; operation IDs 1/2 join source and target requests even when
native LDAP message IDs change. Zero denotes no operation/message association.
The events include accept, TLS completion, bind receipt, search receipt,
referral-send, response-send, overlap arrival/release/timeout, fault/close, and
native-enter/native-exit/native-error. Send events mark write attempts, not
completed writes. Native-enter marks the managed SendRequest call boundary,
not proof that WinLDAP internally began processing then.

Each timeline is capped at 64 events; truncation is counted and cannot pass.
The existing 65,536-byte whole-report cap is unchanged. Both local report-contract
checks passed with all six 64-event timelines at maximum schema numeric widths
and long labels: 52,437 bytes including the synthetic wrapper. Strict schema
validation rejects unknown fields/labels, non-monotonic order, invalid IDs,
missing or duplicate operation correlations, timeout/fault events in passing
cases and dropped events. Successful comparisons require exactly one source
search and one target search for each operation, not merely an aggregate of two.
After endpoint teardown joins server tasks, the result is checked again so late
duplicates become explicit case failures. Original operation failures and
separate cleanup errors remain preserved.

Local validation: both runtime builds, 57 focused pool/preparation tests per
runtime, both PowerShell invocation scopes, both pure worker self-tests and both
maximum-capacity synthetic report contracts passed. New pure regressions cover
timeline bounds/allowlists, exact operation IDs, retained timeout evidence after
later arrivals, simultaneous barrier release and independent unpooled scheduling.
Independent static review found no remaining blocker. No security operation,
native Windows run, permission change or trigger publication occurred.

The smallest useful next native comparison is pooled versus unpooled concurrency
under original/A/B on both runtimes, after each identity's native control gates.
The prepared full harness reports those six comparisons within its 37-case suite;
it does not yet provide a separate six-case-only execution mode. A future single
approved job could use this existing harness with the unchanged two standard
accounts, one logon each, one owned non-exportable runner-user key and one public
LocalMachine Root certificate, watchdogs and exact independent cleanup. Use the
timeline to determine whether timeout/close precedes a repeated operation ID and
whether the same pattern occurs without pooling. Do not accept extra searches,
extend timeouts to manufacture a pass, or enable production eligibility on this
preparation alone. No further trusted job is authorized.


## Pooled/unpooled comparison completed; primary-overlap correction prepared

One approved job ran candidate 8aa2682 at remote source
b347607bb6279aeccea4de23d0508eb4c8538a59 (local equivalent 3dc54be,
tree 5205639a7801addecf461b7fb5552a3073a9583d):
[40117275357](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40117275357).
All prior runs were completed before publication; no duplicate or rerun occurred.
The consumed trigger was removed at remote
5bb6fbe793d29f8c36f9b182ce2d23baa97172ba (local equivalent dd8b2a3).

.NET 8 passed all 37 cases. .NET 10 passed 35/37; the failures were
original-unpooled-concurrent and pooled B-concurrent. All authenticated raw stages
passed, while anonymous direct TLS remained LDAP 81. No production eligibility
changed.

The failing .NET 10 timelines establish the following order. Times are milliseconds
from each fixture's local monotonic origin, not synchronized wall-clock times.

| Event | Original unpooled | B pooled |
| --- | ---: | ---: |
| Both managed calls entered | 13.178 | 12.118 |
| First target request arrived | op 2 at 18.273 | op 1 at 17.136 |
| Other TLS target connection closed without a bind | 18.725 | 17.327 |
| Target overlap timeout | 3019.003 | 3025.145 |
| Faulted target connection closed | 3019.068 | 3025.179 |
| New target connection accepted | 3019.939 | 3026.134 |
| Previously unseen operation searched on new connection | op 1 at 3024.091 | op 2 at 3031.548 |
| Timed-out operation repeated on same new connection | op 2 at 3024.167 | op 1 at 3031.625 |

Each trace had two managed calls, three parsed target searches, one overlap
timeout, zero anonymous/SASL binds, target-only cleanup timeout mask 16 and
PoolDelta=0. The repeated request retained its operation correlation ID and LDAP
message ID. There was no third managed provider callback. The unpooled path has
no provider session or retry loop, so this pattern is not specific to pool
acquisition/reuse. The sequence places repetition after fixture-induced
connection failure within the native calls; it does not prove why WinLDAP closed
the unused connection or that every referral is shared/serialized.

Source review exposes a test-design problem: the endpoint reads a connection's
next LDAP request only after awaiting the current response callback. A target
barrier waiting for a second request can therefore obstruct progress if native
referral operations use that same target connection. The observed new connection
indeed handled both operation IDs. Earlier target-barrier failures remain recorded
as failed diagnostics, but they do not establish a provider defect or inability
to overlap primary operations.

The locally prepared correction explicitly tests overlapping operations on
exclusive PRIMARY leases:
- Both managed calls must enter before either returns.
- Each operation must reach a distinct, nonzero source connection ID.
- Both source requests must arrive before either source referral is released.
- Source IDs must remain stable through each operation's search/arrival/release/
  referral events; the full per-operation event order is validated.
- The target immediately processes/replies to each search, with no barrier waiting
  for another target request.
- Exactly two managed calls and exactly one target search per operation remain
  required, as do explicit LDAP identity and actual Windows SID checks.
- Source timeout records a permanent failure, then permits a valid referral
  response; it no longer throws to intentionally close a connection. Zero source
  timeouts is mandatory for a pass.
- All workers are joined and endpoints disposed before final duplicate checks;
  operation errors and cleanup failures remain separately preserved.

Both pooled and unpooled controls use this identical revised instrumentation.
Report fields are explicitly renamed SourceOverlapArrivals/SourceOverlapTimeouts.
This measures overlapping primary operations, not simultaneous target processing
or independent referral-child connections. Shared target processing is permitted;
duplicate requests, missing IDs, shared primary connections, sequential primary
arrival/release, timeout, identity mismatch or truncated traces cannot pass.

Finally and independent cleanup both verified public certificate
6AA0904CBC93CD44F5DEB839AA1358155F0F063F, owned provider key, PFX and all owned
accounts/objects absent. The independent final step verified temporary files and
directory absent. Independent read-only review confirmed the run and cleanup.

The revised source-barrier code passed both runtime builds, 57 focused tests per
runtime, both invocation scopes, both pure worker self-tests and both full-size
synthetic report contracts. Regressions permit shared target connections but
reject shared/serial primary operations and duplicate correlation IDs; a timed-out
barrier releases a response without erasing its failure or requesting connection
closure. Independent static review found no blocker. The correction has not run
against WinLDAP. No new security action or trigger publication occurred.

The smallest useful next comparison remains the six pooled/unpooled concurrency
cases under original/A/B, within the prepared 37-case harness on both runtimes,
with actual identity-specific native control gates. A future single approved
disposable job would retain the same two standard accounts/one logon each, owned
non-exportable runner-user key, public LocalMachine Root certificate, watchdogs
and exact cleanup. No such run is authorized now. Production remains guarded and
Kerberos work remains deferred.


## Primary-lease overlap verification completed successfully within fixture scope

Exactly one approved disposable Windows job executed candidate
dd4972e34778d0916adc30a3d71110ef50f51b31:
[40123894559](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40123894559).
Its remote source is 0615f46c2482b8939afc03ef6ebcc31012e3de67, local equivalent
9ed2499, tree 1ce4e030b642cce2d60f38fbbfb925f8fc9eb487. The existing executor,
clean candidate and absence of pending prior runs were checked first. The one-job
trigger was removed at remote e0402036e8bca24486f1832519c8c094be6a4ccf, local
equivalent 5541d7f. No duplicate job or automatic rerun occurred.

Both runtimes passed all 37 comparison cases and all 11 authenticated raw stages.
This includes every pooled/unpooled concurrency case and all credential/settings
isolation, capacity/cancellation, generation, failed-bind, primary/target failure,
negative certificate/credential controls, mixed-referral comparison and ambient
A/B transition cases. All per-case cleanup checks passed with PoolDelta=0.

All twelve concurrency traces (six per runtime) independently satisfy:
- Two managed calls and distinct primary connection IDs for operations 1 and 2.
- Both source arrivals before the first source release.
- Each operation's managed entry, source search/arrival/release/referral-send,
  target search/response-send and managed exit in the required order.
- Exactly one target search for each synthetic operation ID, no duplicate request.
- SourceOverlapArrivals=2, SourceOverlapTimeouts=0, TimelineDropped=0.
- Actual Windows SID checks, returned LDAP identity checks, exclusive lease checks
  and joined worker/endpoint cleanup all pass.

The .NET 10 original-unpooled case is particularly informative: two target
TCP/TLS connections were observed but only one bind; target connection 1 handled
both operation IDs, while connection 2 closed before a bind. There were still
exactly two searches and no retry/timeout. Thus overlapping primary operations
can legitimately use one bound target connection. This is direct fixture
evidence of shared target connection use in that case, not proof of simultaneous
target execution, independent target sessions, or an internal WinLDAP algorithm.

With target responses no longer artificially withheld, the repeated-search
pattern was absent in this run. Together with the earlier unpooled failure and
timeout-before-repetition traces, this supports the target-barrier design flaw
as the explanation for those diagnostic failures. It does not establish that
native reconnect/retry can never occur after a real transport failure, nor
guarantee identical timing in every environment.

Both report Supported verdicts passed. Anonymous direct TLS still failed with
LDAP 81 before TLS/bind/search on both runtimes; Adverse failed and AllPassed
remained false. Consequently the overall Actions job correctly concluded failure.
No adverse result was hidden or reclassified.

Finally and independent cleanup each verified exact certificate
3C5BB4B1ADCF49647F56A9B0716AB98F6433E333 absent, owned non-exportable runner-user
CNG key absent, PFX absent and all owned accounts/objects absent. The final
independent step verified all temporary files and directory absent. Independent
read-only review confirmed all twelve concurrency traces, case results and
cleanup.

This validates the diagnostic candidate only within the tested LDAPS IPv4
loopback, External-referral, TLS 1.2 endpoint scope with synthetic explicit Basic
credentials and these local authenticated identities. It does not justify
StartTLS, broader referral policies, hostname variants, multihop/cycles or domain
delegation behavior. Production Windows referral eligibility remains unchanged
and guarded as instructed. Windows pooling is not declared complete; Kerberos
#236 remains deferred. The one approval is consumed and no further security run,
merge or release is authorized by it.
