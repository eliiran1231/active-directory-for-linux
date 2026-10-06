# Offline entry ownership and identity resolver model probe

Research only; supports the [built-in resolver design](../../design/context-bound-identity-resolution.md).
No production resolver or lifecycle hook is implemented. The project is outside the solution
and is non-packable. No directory connection, bind, search, permission write or workflow is run.

Research date: 2026-10-06. Source inspected at PR225 head
`930d0f55d4e0a297c70b7caa2441f16d0a68dbc0`; ambient-auth correction inspected at
`8fc21cedeef7d2709d901ee88546ee5d4acb4ad8`; cross-entry copy policy added atop
`74c927a75c0783c789341ad525b3f48ded35f242`. SDK **10.0.100**, Linux x64 execution
runtimes **8.0.0** and **10.0.0**. The real projects reference Protocols **9.0.0**;
that package version is distinct from the runtime version. The Microsoft DirectoryServices
9.0.0 Windows behavioral oracle remains outstanding.

## Results and boundaries

Both [net8 output](results/linux-net8.txt) and [net10 output](results/linux-net10.txt) passed:

- **Actual repository:** lazy option acquisition, configured endpoint/identity/timeout,
  credential changes resetting Options in place, old option snapshots and independently
  created entries retaining their settings, Close reuse, disposal checks, and entries remaining
  independently configured after their creating PrincipalContext is disposed.
- **Actual ambient configuration:** default entry maps Secure to Negotiate, is not anonymous,
  and returns no explicit credential. A separate **model policy** refuses automatic lookup
  without a proven pinned authority before any fake query. It does not change OS credentials,
  bind, or prove effective identity continuity across connections.
- **Existing helpers:** source-linked, unmodified SidCodec and LdapFilter produce the exact
  escaped binary SID assertion and escape text metacharacters for the fixtures.
- **Model only:** explicit fake epoch rotation rejects stale lookup, invalidation after a fake
  query prevents edit publication, explicit reacquisition succeeds, detached SID data remains
  usable and disposed owners reject lookup.

The executable uses synthetic credentials and reserved `.invalid` hosts; it never prints
passwords or connection options. Reflection invokes only configuration methods (`BuildOptions`,
`CreateEntryForDn`, `CreateDirectoryEntry`) and reads the disposal flag. The ambient fixture also invokes
the public internal-options ToCredential helper, which only constructs a credential or returns null. These methods were
inspected for lazy behavior. No GetConnection, Bind, Search, ObjectSecurity or Save is called.
Private reflection here inspects this repository, not a bypass of platform runtime constructors.

The model explicitly calls Rotate around chosen mutations; **production setters do not yet
emit these epochs**. FakeLookup returns fixed data and cannot demonstrate LDAP, domain discovery,
authentication isolation, real descriptor attachment, races or atomic publication. The model's
final check and EditCount increment are not a coordinated concurrency guard. Retained actual
ObjectSecurity state across credential changes is source evidence, not exercised on Linux's
BCL stub. Full SID validation and ill-formed UTF-16 handling need separate fixtures.

## Cross-entry copy policy fixture

The approved policy is independent descriptor-data copying with no source authority transfer.
The separate CopyDescriptor fixture exports only cloned bytes and a synthetic intent bit;
Assign receives destination authority separately. It checks bidirectional data isolation,
source/destination authority expiry independently, refusal for missing or unpinned ambient
authority, and failure before replacing the destination for validation/unpermitted-intent cases.
Call counters check that assignment performs no hidden fake lookup or source fallback.

The two-byte fixture is **not a security descriptor**. A boolean stands in for destination,
provenance and partial-section validation; the synthetic bit is not a decided intent allowlist.
This tests the proposed transfer boundary only, not actual ObjectSecurity assignment,
production parser/validation, races, authentication or OS identity continuity. No source
credentials or real leases are involved, and no live connection is opened.

## Reproduce

From the repository root with SDK 10.0.100 and both runtimes installed:

```bash
dotnet build docs/research/identity-context-probe/IdentityContextProbe.csproj -c Release
/path/to/net8/dotnet docs/research/identity-context-probe/bin/Release/net8.0/IdentityContextProbe.dll
/path/to/net10/dotnet docs/research/identity-context-probe/bin/Release/net10.0/IdentityContextProbe.dll
```

Build restores the referenced projects' NuGet packages if needed. The executed environment used
`/tmp/acl-interop/dotnet8/dotnet` for runtime 8 and `/tmp/acl-interop/dotnet/dotnet` for SDK/runtime
10. Normal builds completed with zero warnings/errors. Outputs record exact runtime versions.
No Windows execution or live AD success is implied; next request-capture, lifecycle integration,
concurrency, Windows-oracle and separately authorized read-only AD cases are in the design.
