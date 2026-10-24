# Authenticated Windows referral investigation and diagnostic results

The approved authenticated diagnostic completed on 2026-10-24 in run
[40098419409](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/40098419409).
Both runtimes passed all 11 authenticated stages; anonymous direct TLS still failed.
Independent cleanup verified the owned security objects and temporary files absent.
Windows Basic with referrals remains ineligible for production pooling. Detailed
results and remaining limits appear at the end of this document. Earlier plan and
approval sections below are historical, not current execution authorization.

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
