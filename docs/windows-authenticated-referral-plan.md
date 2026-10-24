# Authenticated Windows referral investigation: proposed next diagnostic

This is an unexecuted plan requiring fresh approval. Windows Basic with referrals
remains ineligible for production pooling. No account, token, trust or policy setup
is performed by the ordinary tests added alongside this document.

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
