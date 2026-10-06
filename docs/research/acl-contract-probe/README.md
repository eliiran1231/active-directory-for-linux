# Existing ACL contract: Linux feasibility evidence

Result: **an internal managed core cannot make the existing BCL-derived public contract
execute unchanged on stock Linux .NET 8/10**. Two independent constructor chains fail:
`ActiveDirectorySecurity → DirectoryObjectSecurity → ObjectSecurity` and callers'
`SecurityIdentifier → IdentityReference`. Rule construction independently fails through
`AuthorizationRule`. These are runtime failures, not merely analyzer warnings.

The user rejected a parallel portable public API. This probe does not introduce one or choose
re-rooting. It is an isolated research executable, outside the solution and production
projects; its project reference builds the actual library. No LDAP, AD, Samba, OS ACL change,
workflow dispatch, patched framework, private constructor invocation or unsafe allocation is
used. See [the revised design](../../design/portable-acl-core.md) for decisions and next gates.

Subsequent authorized investigation of replacement dependencies is recorded in the
[same-name candidate](../../design/same-name-portable-acl-api.md). It does not invalidate these
original-contract failures.

## Recorded execution

Research date: 2026-10-05. Input PR head: `e33c444ef4960e49a6f77ce2c0141716aa4213af`;
production source remains unchanged. Host: Debian GNU/Linux 13, Linux x64.
Build SDK: **10.0.100**, compiling both `net8.0` and `net10.0`.
Execution hosts: **Microsoft.NETCore.App 8.0.0 and 10.0.0**, installed in isolated `/tmp`
directories from Microsoft's official dotnet-install distribution. SDK 8.0.100 supplied the
8.0.0 runtime; it was not used to build the multi-target project.

| Check | net8.0 / runtime 8.0.0 | net10.0 / runtime 10.0.0 |
|---|---|---|
| Normal build, including BCL-typed consumer method | Pass | Pass |
| `ActiveDirectorySecurity()` | PNSE at `ObjectSecurity..ctor` | Same |
| Nine existing rule classes, representative constructors with null identity | PNSE at `AuthorizationRule..ctor` | Same |
| BCL SID from string and bytes, NTAccount | PNSE at `IdentityReference..ctor` | Same |
| Real caller expression: BCL SID passed to existing rule | Fails while creating SID | Same |
| RawAcl / RawSecurityDescriptor | PNSE at GenericAcl / GenericSecurityDescriptor | Same |
| Reflection: IdentityReference constructor | `Assembly` (internal) | Same |
| Reflection: SecurityIdentifier | Sealed | Same |
| External IdentityReference subclass compile | Expected CS1729 | Same |
| Unexpected probe outcomes | 0 | 0 |

Full outputs: [Linux net8](results/linux-net8.txt), [Linux net10](results/linux-net10.txt),
[negative compile net8](results/identity8.txt), [negative compile net10](results/identity10.txt).
Compile diagnostics replace only the machine-specific repository prefix with a relative path.
Constructor IL is emitted as raw hex for independent inspection; the exception stack and
source configuration establish the behavior, not a guessed interpretation of IL tokens.

The null-identity probes deliberately isolate the base-constructor failure. They are **not**
valid identity examples, complete overload coverage, or Microsoft behavioral-parity tests.
The compile-only consumer checks real `ObjectSecurity`, `AccessRule`, `IdentityReference` and
`SecurityIdentifier` assignments/member calls, illustrating contract obligations beyond names.
Reflection also records nonvirtual inherited owner/group, protection and binary/SDDL setters;
a same-named method on a derived class cannot intercept base-typed calls.

Existing offline helper tests were also run on net10.0 with the exact filter below:
**36 passed, 0 failed, 0 skipped**. Existing xUnit analyzer warnings in unrelated test files
were emitted during build. This supports reuse of the current helpers, not a complete ACL
implementation. No Windows oracle execution or live-directory parity evidence was obtained.

## Reproduce

Install a .NET 10 SDK plus the .NET 8 and 10 runtimes through your normal trusted tooling.
From the repository root (this project is intentionally not added to `AdForLinux.sln`):

```bash
dotnet build docs/research/acl-contract-probe/AclContractProbe.csproj
dotnet run --project docs/research/acl-contract-probe/AclContractProbe.csproj -f net8.0 --no-build
dotnet run --project docs/research/acl-contract-probe/AclContractProbe.csproj -f net10.0 --no-build
```

If hosts are installed separately, execute the corresponding host directly:

```bash
/path/to/dotnet8/dotnet docs/research/acl-contract-probe/bin/Debug/net8.0/AclContractProbe.dll
/path/to/dotnet10/dotnet docs/research/acl-contract-probe/bin/Debug/net10.0/AclContractProbe.dll
```

The executable expects Linux PNSE results and exits 1 on a different outcome. A Windows run
is intentionally not a passing test. Normal build suppresses CA1416 only to allow this
platform probe; it does not suppress runtime exceptions. Normal build produced no warnings.

Negative compilation is expected to exit nonzero with **CS1729**, not a restore/SDK error:

```bash
dotnet build docs/research/acl-contract-probe/AclContractProbe.csproj -f net8.0 -p:DefineConstants=PROBE_DERIVED_IDENTITY
dotnet build docs/research/acl-contract-probe/AclContractProbe.csproj -f net10.0 -p:DefineConstants=PROBE_DERIVED_IDENTITY
```

Diagnostic: `'IdentityReference' does not contain a constructor that takes 0 arguments`.
Reflection/source explain why: its parameterless constructor exists but is inaccessible to
third-party code. Build normally again after the negative probe when reusing build outputs.

Offline helper regression command (do not remove the filter on a configured directory host):

```bash
dotnet test tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj -f net10.0 --filter 'FullyQualifiedName~SidCodecTests|FullyQualifiedName~ChangePasswordAclTests'
```

## Official source cross-check

The checked runtime project files generate unsupported non-Windows assemblies. The presence
of managed implementations in the source tree does not mean those implementations ship as
supported Linux BCL APIs.

| Evidence | Official source |
|---|---|
| Non-Windows principal assembly generation | [v8.0.0 project](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Principal.Windows/src/System.Security.Principal.Windows.csproj), [v10.0.0 project](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Principal.Windows/src/System.Security.Principal.Windows.csproj) |
| Non-Windows ACL assembly generation | [v8.0.0 project](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.AccessControl/src/System.Security.AccessControl.csproj), [v10.0.0 project](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.AccessControl/src/System.Security.AccessControl.csproj) |
| IdentityReference internal constructor | [v10.0.0 IdentityReference.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IdentityReference.cs) |
| Public inherited setters and protected section flags | [v10.0.0 ObjectSecurity.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ObjectSecurity.cs) |
| Merge algorithm can combine differing inheritance/audit flags | [v9.0.0 ACL.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs), `MergeAces` and `MergeInheritanceBits` |
| SD-flags ignored on LDAP Add | [MS-ADTS §6.1.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499) |

`ObjectSecurity` source confirms protected section flags can convey that an inherited setter
was invoked; they do not retain an operation log or the caller's raw binary payload. That is
useful for intent tracking, but does not prove that a changed BCL projection can safely be
reconciled with opaque bytes discarded during import. The design requires preserve-or-refuse
within changed sections and leaves full adapter feasibility open.

Microsoft **System.DirectoryServices 9.0.0** is the project's pinned Windows comparison
package. It must be tested on net8/net10 Windows hosts with loaded ACL dependency versions
recorded separately. The v9 ACL source link corrects the old merge claim, but does not stand
in for either runtime's executed Windows oracle. This research tests initial 8/10 releases,
not every patch, architecture or future framework. Any servicing-runtime recheck should
record exact versions and rerun these probes rather than infer platform support from an SDK
version or an assembly's availability in the reference pack.
