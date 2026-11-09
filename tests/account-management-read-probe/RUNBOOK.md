# AccountManagement read probe: preparation and later activation

## 1. Current stopping point

Live admission is hard-disabled in `ProbeReadiness.LiveEnabled`. Keep it disabled.
There is no credential or command-line override. Even a correctly configured
invocation must stop before READY, secret input or LDAP activity.

The candidate and this runbook are local cloud work, not part of the published
PR head. Inspect the commit being used before building. The held containment
candidate is `389e4f38758b43117d4aff2076afda4237aad42d`; later preparation commits
must be reviewed with it. Do not treat a different checkout as equivalent.

Linux does not need to be booted to supply credentials now. A chosen Linux
machine becomes necessary for its nonsecret runtime/TLS preflight. An actual AD
run is a later, separately authorized step after the prerequisites below pass.
No runner or AWS VM is confirmed. Historical laptop success does not establish
the new machine's readiness. Old disabled test accounts and destroyed tickets
are not available fixtures or authorization.

## 2. Build and verify the blocked candidate without AD

Use a trusted test checkout, Python 3, a .NET 10 SDK and both .NET 8/10 runtimes.
Run from the repository root. Restore needs package-source access; the tests
below need no directory credentials. Do not set live opt-ins or supply stdin
credentials. Retain the functional runner's immutable offline guard.

```sh
git status --short
git rev-parse HEAD
dotnet --info
python3 --version
dotnet restore tests/account-management-read-probe/AccountManagement.ReadProbe.csproj
dotnet build tests/account-management-read-probe/AccountManagement.ReadProbe.csproj --no-restore -c Release
dotnet restore tests/account-management-read-probe/termination-check/TerminationCheck.csproj
dotnet build tests/account-management-read-probe/termination-check/TerminationCheck.csproj --no-restore -c Release
python3 tests/account-management-read-probe/check-blocked.py --dotnet dotnet
python3 tests/account-management-read-probe/check-admission.py --dotnet dotnet
python3 tests/account-management-read-probe/test_launcher.py
python3 tests/account-management-read-probe/check-termination.py --dotnet dotnet
python3 tests/test_offline_runner.py
python3 tests/test_samba_runner.py
dotnet restore tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj
python3 tests/run-offline-tests.py functional --framework net8.0 --results-directory TestResults/read-probe-net8
python3 tests/run-offline-tests.py functional --framework net10.0 --results-directory TestResults/read-probe-net10
```

Stop on an unexpected result. `check-blocked.py` checks six early guard cases;
`check-admission.py` checks 22 nonsecret refusal cases and the hard live gate.
The latter must run in a separately scoped nonsecret process: if an offline guard
is inherited it refuses rather than clearing that guard. Do not repurpose an
existing guarded process for live work. Launcher tests use synthetic frames and
a local Python child; termination checks kill only their own guarded helper.
`test_samba_runner.py` tests the runner with mocks; it does not run Samba or AD.

These commands do not select the four opt-in reentrant Save contract diagnostics.
The held candidate's default functional result is 14,193 total / 14,191 passed /
0 failed / 2 existing skips on each runtime. That is offline evidence, not AD
compatibility or Microsoft AccountManagement parity.

## 3. Optional owned-loopback native experiment

This separate SDK-only project references neither the probe nor production
facades. It accepts no external host. The Python fixture owns both IPv4 and IPv6
loopback listeners and creates/removes a temporary test CA and synthetic LDAP
server. The only bind values are fixed synthetic constants.

Prerequisites: Linux, Python with SSL/IPv6, OpenSSL CLI, both runtimes, and the
native dependencies required by the pinned Protocols package. The test refuses
an inherited offline guard. Run in a separate nonsecret test process, not by
removing a guard from a production or functional-test process.

```sh
dotnet restore tests/account-management-read-probe/loopback-tls/LoopbackTls.csproj
dotnet build tests/account-management-read-probe/loopback-tls/LoopbackTls.csproj --no-restore -c Release
python3 tests/account-management-read-probe/loopback-tls/run-fixtures.py --dotnet dotnet --report /tmp/adfl-loopback-results.json
```

The pinned Protocols 9 Linux binary expects `libldap-2.5.so.0`. The cloud host's
ordinary library is 2.6 and failed the initial positive control before connection.
For this experiment only, a Debian 2.5 package was verified against a signed
archive index and extracted privately without installation. The fixture's
optional `--native-directory <verified-private-directory>` sets only the isolated
child's library path and records library hashes. This is not an installation
recipe for a live runner. Do not make an ABI symlink or install an old package
across distributions to silence the loader. Provision supported, trusted native
dependencies for the chosen machine separately.

The matrix brackets strict TLS negatives with successful bind/search controls,
checks wrong SAN, CN-only, expiration and untrusted CA, and tests referral/result
reference responses against owned LDAP/LDAPS traps. It includes a deliberately
insecure control confined to the synthetic loopback child, never the production
probe. OpenLDAP's localhost canonicalization requires the generated valid SAN to
cover the machine's local name too; the socket target remains fixed localhost.
Bind-referral evidence is narrower than search-referral evidence: the server
emitted the referral, Bind failed with no response code, and neither trap was
contacted. Do not claim a decoded Bind referral result from that exception alone.

Stalled handshake, stalled search and partial response cases distinguish native
failure from the six-second independent process timeout in the JSON report.
An outer timeout is not proof that the SDK honored its two-second timeout.
In the cloud validation, all six stall cases (three per runtime) required the
outer six-second termination. The 32 passing cases include that supervision
evidence; they do not establish a native two-second deadline guarantee.
Temporary test keys are removed; no global trust or system LDAP settings change.

**This matrix uses explicit process-local native TLS options with LDAPNOINIT=1.**
It does not verify the production launcher's environment-based TLS configuration,
the exact controller FQDN/port636 path, AD permissions, or Microsoft behavior.
Success cannot activate the live probe.

## 4. Collect nonsecret choices, then review the exact machine

Provide/review these values before any activation or secret input:

| Required input | Verification |
| --- | --- |
| Chosen trusted machine, OS/architecture and runtime versions | Cloud or explicitly chosen owned runner; no assumption of laptop availability |
| Exact controller ASCII FQDN, TCP636 | A specific DC, not a domain discovery alias; no alternate controller/GC/StartTLS fallback |
| Approved controller addresses and direct runner egress | Owner/network confirmation; proxy-derived HTTPS IPs do not identify LDAP egress |
| Trusted certificate chain and matching SAN | Independently verify on the actual runtime; no callback bypass or relaxed trust |
| Existing fixture DN, exact SAM, nonzero GUID | Independently obtained and stable; no discovery or fixture creation |
| Exact schemaNamingContext DN | Independently approved metadata location |
| Dedicated account identity and permissions | Verify account availability privately; do not send a password during planning |

On that machine, first inspect runtime/native-library compatibility without an
AD connection. Audit trusted system/native LDAP configuration for client keys,
alternate trust or weaker verification. The launcher drops inherited library,
startup-hook and arbitrary LDAP environment overrides; its actual environment
and native initialization must be tested with negative certificate controls in
an audited isolated setup. The loopback experiment above intentionally does not
establish that property. Do not copy its private library-path workaround or
insecure control into the production launcher.

No direct egress IP, connectivity, TLS chain or credentials have been established
for the user's eventual runner. Do not probe the controller to fill these gaps
before the exact connection is authorized.

## 5. Approve the complete read scope and activation

Review the full attribute list in [README.md](README.md), not just the five-field
comparison. Approve these operations against the one controller:

1. Basic authentication over verified LDAPS with one already-valid dedicated
   read account. A failed bind may affect account counters; do not experiment
   with guessed/disabled credentials.
2. Repeated Base reads of the one existing user: comparison attributes, normal
   user projection, `*`, and `nTSecurityDescriptor` Owner/Group/DACL. No SACL.
3. RootDSE Base read of schemaNamingContext and bounded OneLevel schema lookups
   for attribute syntax metadata, as described in README.
4. The selected runtime(s), bounded duration and ordinary bind/read audit effects.

The account needs applicable Read Property and READ_CONTROL for that fixture,
rootDSE metadata read and list/read syntax attributes under the approved schema
container. No administration, password reset, writes or fixture provisioning is
part of the probe. If permissions are insufficient, stop; do not expand scope or
grant privileges automatically.

Only after machine/TLS checks, scope approval and independent containment review
should a separately reviewed change activate the source gate. Rebuild/retest the
exact activation commit. The current candidate must still remain blocked.

## 6. Later live execution and cleanup — unavailable in current build

After that separate activation and authorization, select one runtime. The
nonsecret invocation shape is documented in README. It requires both live
opt-ins, strict Unix certificate/SAN settings and the supervisor; there is no
direct executable shortcut. Choose and review a private, non-echoing redirected
input helper before the run. It must produce exactly one JSON frame with bindDn
and password in memory, without putting secrets in commands, environment, files,
shell history, transcripts or logs. No helper or credential is assumed ready.

Do not supply secret input now. Current runs must stop before READY.

Expect only fixed statuses: BLOCKED/exit2 for prerequisites, FAIL/exit1 for read,
input or supervision failure, and exit0 only for the exact final comparison PASS
after disposal and deadline checks. Preserve nonsecret status/runtime/commit and
timing only. A timeout, late success, partial comparison or missing prerequisite
cannot pass. Stop on failure; there is no automatic retry, endpoint fallback or
backend switch.

The supervisor kills/reaps its own child at the deadline. Process death does not
prove server cancellation of a submitted read. Cleanup closes owned processes,
connections and pipes and discards private in-memory input; it performs no AD
deletes or credential/account changes. There are no fixtures to remove in AD.
Disable privileged dump/telemetry capture separately on the approved runner.
Keep audit records only under the agreed retention policy.
