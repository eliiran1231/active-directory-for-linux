# Read-only AccountManagement fixture specification

**No live path is shipped.** This directory contains an admission-only scaffold
and a future integration specification. Even with every opt-in and valid fixture
argument, the executable exits `2` with
`BLOCKED referral-containment-unavailable`. It contains no LDAP types, connections,
contexts, entries, native calls, credential reads or PASS path. There is no
fixture creation, mutation, password operation, membership edit or cleanup.

The executable is outside the solution, offline allowlist, CI workflows and
Samba runner. Building it is not authorization for a later AD bind. Tonight's
only executions are the six offline-guarded refusal checks below.

## Why tomorrow also stays blocked

The specification requires referral chasing **None on every operation**, including
base-object validation, schema reads and deferred principal attachment. Setting
the public PrincipalSearcher's underlying DirectorySearcher to None controls its
query. Basic/SSL principal materialization can then reopen a DirectoryEntry whose
configuration defaults to External before the caller can configure that entry.
The public API provides no containment hook at that point.

Therefore dual opt-ins, known fixture arguments and trusted TLS cannot currently
make this scaffold live. A separately reviewed way to enforce the complete
endpoint/referral boundary is required before implementing any read phases.
There is no force option or environment override for this final block. This is a
limitation of the proposed probe contract, not a claim that External is a defect
in the general public API.

## Build and blocked checks

From the repository root, with the existing cloud SDK configuration:

```sh
export XDG_RUNTIME_DIR=/workspace/directory-runtime
export DOTNET_CLI_HOME=/workspace/dotnet-cli
export NUGET_PACKAGES=/workspace/nuget
export DOTNET_NOLOGO=1
/workspace/dotnet/dotnet restore tests/account-management-read-probe/AccountManagement.ReadProbe.csproj
/workspace/dotnet/dotnet build tests/account-management-read-probe/AccountManagement.ReadProbe.csproj --no-restore -c Release
python tests/account-management-read-probe/check-blocked.py --dotnet /workspace/dotnet/dotnet
```

Expected: both `net8.0` and `net10.0` build with exit `0`. The Python command
prints `PASS 6 guarded invocations blocked before credential access` and exits
`0`; this is PASS for refusal checks, **not AD integration success**. Each child
exits `2`, prints `BLOCKED offline-guard` on stderr and prints nothing on stdout.
The checker tries guard strings `1`, `0` and `false` on each runtime, including
apparently opted-in CLI arguments. It copies only a small runtime-environment
allowlist and never looks up credential variables. Missing built DLLs make the
checker exit nonzero, never silently pass.

## Ordered admission gates

The scaffold only validates non-secret admission data:

1. Any nonempty `ADFL_OFFLINE_TESTS` refuses, including `0` and `false`. The
   program never removes the guard or accepts a CLI override.
2. CLI `--allow-live-read` must be present.
3. `ADFL_ACCOUNT_READ_PROBE` must equal `1` exactly.
4. On Unix, `LDAPTLS_REQCERT=demand` and `LDAPTLS_REQSAN=demand` are required.
5. All explicit configuration pairs must be valid: `--host`, `--port 636`,
   `--fixture-dn`, `--sam`, `--guid`. Unknown/duplicate options are refused.
6. The unconditional referral-containment block refuses. **No credentials are
   read**, even if every preceding gate passes.

All scaffold invocations exit `2`; stderr identifies the first block. No live
invocation or unguarded gate experiment was performed overnight. An illustrative
future CLI shape is below; **today it still blocks** and no credentials should
be supplied to it:

```text
AccountManagement.ReadProbe.dll --allow-live-read
  --host <controller-dns-host> --port 636
  --fixture-dn <known-user-distinguished-name>
  --sam <known-sAMAccountName> --guid <known-object-GUID>
```

Do not unset an offline guard to try this template. Future integration must use
a separate, explicitly authorized environment with a reviewed implementation.

## Future existing-fixture prerequisites

An authorized operator must identify one stable, already-existing AD user and
obtain the following values independently of the probe:

- One exact DNS controller host on port **636**. No alternate host, automatic
  controller discovery, plaintext LDAP, StartTLS or fallback endpoint.
- Exact distinguished name, `sAMAccountName` and nonzero object GUID. The first
  search may verify these values but must never select a replacement fixture.
- A readable binary `objectSid`. Description and display name may be absent;
  otherwise each must be a single string. The user must match the public
  AccountManagement user filter and remain unchanged during the observation.
- Verified credentials for a dedicated least-privilege read account authorized
  for the fixture's ordinary attributes, required security sections and
  rootDSE/schema metadata. No ambient identity or credential-file discovery.
- A trusted server certificate whose SAN covers the explicit host, using the
  platform trust store and host-name checks. No verification callback or bypass.
  Unix libldap must support strict certificate/SAN policy. Install required trust
  and native dependencies separately, outside the probe.

Only a future reviewed implementation could read explicit bind DN/password from
an operator-approved mechanism after all admission gates pass. No secret values
belong in CLI arguments, shell history, test settings, output or this directory.
LDAP binds/reads can produce server audit entries and affect bad-password
counters; valid credentials and separately scoped live authorization are required.

## Future read phases and bounded contract

No phase below is implemented in the scaffold.

1. **Direct Protocols baseline:** TLS Basic, protocol version 3, exact host636,
   referral chasing None, base scope at the known fixture DN, size limit `2`,
   10-second client and server limits. Read only objectGUID, objectSid,
   sAMAccountName, description and displayName. Require exactly one row, no
   referrals/references, and independently known GUID/SAM before proceeding.
2. **Public DirectoryEntry:** same endpoint, credentials, strict TLS and referral
   policy; refresh those exact attributes at the same DN. Compare GUID/SID binary
   identity and nullable scalar values against the direct baseline.
3. **Public AccountManagement:** SimpleBind over SSL and the fixture DN as context
   container; UserPrincipal SAM filter, base scope, no paging, referral chasing
   None, size limit `2`, 10-second client/server query limits. Exercise FindAll
   and deferred attachment and compare type, GUID, DN, SID and nullable scalars.
   The future containment seam must also cover **all** internal rootDSE/schema
   and attachment reads. No subtree/group traversal or implicit referral target.

Use a 60-second total wall bound, including provider-internal reads. Do not retry
automatically or switch endpoints/backends. Dispose all resources on ordinary
success/failure; define hard-deadline termination explicitly. No Save, Add,
Modify, Delete, ModifyDN, password, membership, provisioning or cleanup calls.

Future outcome rules:

| Exit | Meaning |
| --- | --- |
| `2` | Missing admission/prerequisite: BLOCKED, no bind attempted. |
| `1` | Admitted read failed or exceeded its time bound; server effects may exist. |
| `0` | Only after all three phases verify the known fixture; one explicit PASS record. |

Missing fixtures/credentials, TLS failure, read denial, malformed identity,
referrals, unexpected row counts and mismatches must fail/block, never skip or
silently PASS. Capture runtime, phase, status and non-secret error type; do not
dump credentials, environment, exception messages or returned attribute values.

This future check would compare **direct LDAP with this project's facades on one
real AD fixture**. It would not be a Microsoft AccountManagement oracle, mutation
test, performance benchmark, or proof of complete AD/schema compatibility.
