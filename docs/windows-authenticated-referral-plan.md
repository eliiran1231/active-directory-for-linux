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
