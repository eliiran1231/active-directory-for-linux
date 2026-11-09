# Contained read-only AccountManagement probe candidate

## Current status

The read comparison, opt-in containment policy and supervisor are implemented,
but **live execution remains unconditionally blocked** in `ProbeReadiness`.
No CLI option or environment setting can remove that gate. With valid nonsecret
configuration the executable exits `2` with `BLOCKED containment-review-pending`,
before READY, credential input, context creation or LDAP activity.

This candidate has not contacted AD, performed a native bind or consumed real
credentials. The unconditional gate stays until the separate security review,
cross-runtime checks, trusted runtime/TLS prerequisites and precise operator
scope have been accepted. Building or checking this project does not authorize
any AD connection. Do not edit the gate merely to bypass a failed prerequisite.

The project is outside the solution and live/Samba runners. Pure configuration
and comparison source is linked into the guarded functional tests; those tests
use isolated recording Protocols connections, not a neutral substitute backend.
The controlled callbacks on `ProbeReads.Run` are internal test seams only. The
executable supplies none of them and uses the stock Protocols/facade paths.

## Design and scope

An internal immutable endpoint/scope policy accompanies the selected context's
options, entry/result copies and deferred attachments. Ordinary public contexts
and Basic/SSL referral defaults remain unchanged. The diagnostic uses Basic over
LDAPS with an explicit fully qualified DNS host, port636, no StartTLS, no anonymous
or ambient identity, no certificate bypass, and referrals None **before bind**.
Windows auto-reconnect is disabled for selected connections. Policy-selected
sessions are fresh and have isolated pool keys/caches; raw retained handles,
credential validation, GC, foreign contexts and cross-context paths refuse.

Searches can read only the following locations:

| Location | Scope and permitted operations |
| --- | --- |
| Independently supplied user DN | Base search only; size cap2, exactly one returned fixture row |
| RootDSE empty DN | Base search for `schemaNamingContext` only; exactly one empty-DN row, value must equal the preapproved schema DN |
| Independently supplied schema DN | One-level attributeSchema lookup only, exact generated name filter and three syntax fields; at most256 rows, complete unique requested names and direct-child DNs |

LDAP alias dereferencing is disabled. Async/streaming searches, paging, ASQ,
DirSync, VLV, unsupported controls and all writes refuse. Response references,
referrals, non-success results, unexpected controls/rows/identities and missing/duplicate/noncanonical
schema evidence latch a failure. Later admission/send and final PASS check that
latch. Schema fallback cannot convert rejected evidence into a successful probe.
Policy sends use the original Protocols request and a shrinking total deadline;
requested bind/send limits are at most10seconds. The policy is not a public configuration
feature and does not grant authority to new endpoints or credentials.

The DNS name and TLS identity are constrained, **not a pinned socket IP**. DNS
resolution remains an OS service. Later approval must verify that this is a
specific controller name, not a domain discovery alias, and restrict egress to
its approved addresses. A trusted host/runtime/network is part of the boundary;
this is not a sandbox against a malicious operator or compromised native library.

## Actual read phases and expanded authorization scope

1. Direct stock Protocols baseline: base read of objectGUID, objectSid,
   sAMAccountName, description and displayName. Require the independently known
   nonzero GUID and exact SAM before another phase. Validate exact SID length.
2. Public DirectoryEntry: refresh the same five attributes and compare.
3. Public PrincipalSearcher/UserPrincipal: base, buffered FindAll with no paging
   or async; enumerate and access deferred Current; compare type, GUID, SID, DN,
   SAM and nullable description/displayName. Fully dispose before final checks.

**The entire procedure is not limited to five attributes.** Stock principal
attachment reads GUID and enumerates the target entry via `*` plus
`nTSecurityDescriptor`, requesting Owner, Group and DACL. The normal user query
projection also includes these ordinary/account attributes (duplicates omitted):

```text
displayname description samaccountname userprincipalname objectguid objectsid
objectclass name distinguishedname useraccountcontrol usercertificate
badpasswordtime accountexpires lastlogon lastlogontimestamp lockouttime badpwdcount
pwdlastset givenname middlename sn mail telephonenumber employeeid
userworkstations logonhours homedirectory homedrive scriptpath
```

`ADsPath` is a facade projection value. Syntax resolution reads rootDSE/schema
metadata for returned target attributes. No schema-wide/subtree traversal is
permitted. No group/foreign membership traversal, Save/Add/Modify/Delete/Move,
password operation, fixture provisioning, or cleanup write exists in the probe.
Read-only binds/reads can still create server audit records and affect password
failure counters. No zero-server-effects claim is made.

## Offline validation

Restore/build with an installed .NET10SDK and both .NET8/10 runtimes:

```sh
dotnet restore tests/account-management-read-probe/AccountManagement.ReadProbe.csproj
dotnet build tests/account-management-read-probe/AccountManagement.ReadProbe.csproj --no-restore -c Release
python tests/account-management-read-probe/check-blocked.py --dotnet dotnet
python tests/account-management-read-probe/check-admission.py --dotnet dotnet
python tests/account-management-read-probe/test_launcher.py
dotnet restore tests/account-management-read-probe/termination-check/TerminationCheck.csproj
dotnet build tests/account-management-read-probe/termination-check/TerminationCheck.csproj --no-restore -c Release
python tests/account-management-read-probe/check-termination.py --dotnet dotnet
python tests/test_offline_runner.py
python tests/test_samba_runner.py
python tests/run-offline-tests.py functional --framework net8.0 --results-directory TestResults/read-probe-net8
python tests/run-offline-tests.py functional --framework net10.0 --results-directory TestResults/read-probe-net10
```

The six `check-blocked.py` invocations verify only the earliest immutable offline
guard, with values1/0/false on each runtime. They do not verify deeper admission.
`check-admission.py` separately checks nonsecret refusals using sealed empty stdin
and synthetic .invalid scope. It carries no credentials. An inherited offline
guard makes it refuse rather than remove that guard; use a separately scoped
nonsecret admission-check process, not an unguarded live test. Missing builds or
unexpected outcomes fail. None of these PASS records is AD integration success.

Launcher tests cover sanitized child environment, no secret input before READY,
framing/encoded-size bounds, CRLF, duplicate keys, timeouts, cleanup and a real
local Python child killed/reaped by the deadline. That child uses no LDAP/native
library and only synthetic input. Functional tests exercise the actual policy
send helpers, stock facade materialization and full comparison with recording
Protocols connections. Four separately guarded self-termination drills invoke only the emergency
method, under blocked-stderr and blocked-exit-handler conditions on both runtimes;
they do not enter admission or LDAP code. Native TLS/bind behavior, Windows supervisor execution and
actual AD permissions are not established by these offline observations.

## Supervision and secret handling

The proposed live entrypoint is `run-probe.py`. It sanitizes child environment,
disables managed diagnostic attach/minidumps, and on Unix disables ordinary core
dumps. No password/identity is accepted in CLI arguments, environment or a file.
After all nonsecret gates pass, the child emits READY with a fresh nonce; the
launcher then reads one redirected JSON line containing exactly `bindDn` and
`password`, adds the nonce, writes a bounded frame, and retains the pipe.
Credential values remain in process memory; no memory-zeroization guarantee is
made. They are never printed, logged or written by this implementation. A later
operator must also disable privileged OS dump/telemetry capture that could retain
process memory. The launcher is not an identity proof against an operator who
controls its code, pipes and credentials.

A launcher timer covers the whole operation, including pipe writes. At55seconds
it kills the scoped child/process group and reserves at most5seconds for reaping.
The child also has a55-second timer, an elapsed-time success gate and a pipe-EOF
monitor. Emergency abort hard-kills only its own process without pipe I/O or
managed exit-handler dependence; ordinary outcomes retain disposal. Deadline, launcher death or malformed framing cannot be accepted as PASS.
As with any process supervisor, this assumes a responsive OS; uninterruptible
kernel stalls are outside an absolute user-space timing guarantee. Killing the
process does not prove server-side cancellation of a previously submitted read.

Output contains only fixed status/stage records. No exception messages, server
diagnostics, returned attributes, environment dumps or credential values appear.
Missing prerequisites are BLOCKED/exit2; input/supervision/read failures exit1;
exit0/PASS requires all comparisons, disposal and final healthy deadline checks.
The launcher never automatically retries or changes endpoint/backend.

## Exact later live-run prerequisites — not authorization now

Before activating the source gate or supplying credentials, obtain approval for:

- One trusted cloud/owned test machine with Python3, .NET8/10, and this reviewed
  build. No laptop dependency. On Linux install a trusted compatible OpenLDAP
  runtime that supports strict certificate and SAN enforcement. Confirm platform
  TLS behavior and trust configuration separately; the environment strings alone
  are not proof that an arbitrary native library honors them. Windows uses its
  normal trusted certificate store. Install trust/dependencies outside the probe.
- Exact ASCII controller FQDN and approved DNS-resolved egress addresses, TCP636
  only, with no alternate DC, domain discovery, plaintext or StartTLS fallback.
- Trusted server certificate chain with SAN matching that FQDN. On Unix require
  `LDAPTLS_REQCERT=demand` and `LDAPTLS_REQSAN=demand` at process startup. Audit
  native/system LDAP configuration for unwanted client keys or alternate trust.
- Independently obtained fixture DN, sAMAccountName and nonzero object GUID, plus
  the exact schemaNamingContext DN. Identify a stable, already-existing user;
  the probe will never search for a replacement fixture.
- A verified dedicated read account and a one-time private redirected input
  channel. Grant Read Property for the fixture's readable ordinary attributes
  and READ_CONTROL for Owner/Group/DACL, rootDSE schemaNamingContext read, and
  list/read lDAPDisplayName/attributeSyntax/oMSyntax under the schema container.
  No administrative, password-reset, write or SACL privilege is required.
- Explicit permission for the one chosen controller, account, expanded read
  scope, both desired runtimes, bounded duration and bind/audit side effects.
  Confirm valid credentials independently to avoid bad-password experiments.

After separate review/activation and live authorization, the nonsecret command
shape would be:

```text
python run-probe.py --dotnet <approved-dotnet> --framework net8.0
  --allow-live-read --host <approved-controller-fqdn> --port 636
  --fixture-dn <approved-user-dn> --schema-dn <approved-schema-dn>
  --sam <known-sam> --guid <known-guid>
```

Set `ADFL_ACCOUNT_READ_PROBE=1` and the Unix
TLS requirements in the explicitly approved live process. A private input helper
must send the credential JSON through stdin without echo or persistence; no
credential-bearing command/file example is provided. Do not unset an offline
guard to repurpose an existing guarded process. Current builds remain blocked,
so do not supply credentials now.

The comparison is direct LDAP versus this project's facades on one known AD
fixture. It is not a Microsoft AccountManagement runtime oracle, Kerberos worker
validation, mutation test, throughput measurement, or proof of complete AD
compatibility. No publication, AD connection or credential use is authorized by
this document.
