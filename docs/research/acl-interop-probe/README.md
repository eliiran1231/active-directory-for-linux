# Microsoft snapshot conversion and protected-hook feasibility probe

**Research only.** This executable is outside the production solution, non-packable, and
performs no directory access, actual permission writes or privilege enabling. It extends the
[same-name construction probe](../same-name-acl-probe/README.md) and supports the
[interop/override design](../../design/acl-microsoft-interop-and-overrides.md).
No final method names, package design or shipping replacement implementation are approved.

## Result and limits

Research date: 2026-10-06; source PR head `eb2a4383c64ff5a7516ec21356b68d657076c4fb`.
Host: Debian Linux x64. Build SDK 10.0.100, targets net8.0/net10.0. Execution runtimes:
Microsoft.NETCore.App **8.0.0 / 10.0.0**. Microsoft System.DirectoryServices package **9.0.0**
is pinned separately; actual loaded ACL/identity/directory-base assembly identities are logged.
No Windows host was available. Build success is not Windows runtime evidence.

| Case | Executed result on both Linux runtimes |
|---|---|
| Portable consumer subclass: base-typed ModifyAccess/ModifyAudit | Pass, protected overrides called |
| Recursive lock acquisition, modified flag reads/writes, exception cleanup | Pass, correct accesses work and unlocked accesses reject |
| Constructor shapes `ObjectSecurity()`, `(bool,bool)`, `(portable descriptor)` and both DirectoryObjectSecurity shapes | Compile/run with limited fixtures; general descriptor behavior not implemented |
| Custom DirectoryObjectSecurity factory override | Pass |
| Concrete ActiveDirectorySecurity sealed factory override | Expected **CS0239** on each target |
| Name / SafeHandle / bool Persist overrides | Pass, only counters change; no resource I/O |
| False-valued base Persist forwarding to name override | Pass |
| True-valued research-base ownership path | Intentional PNSE, no privilege call |
| Typed AddAccessRule helper bypasses protected ModifyAccess | Probe confirms intended path distinction; actual Microsoft behavior verified on Windows (see below) |
| SID, NTAccount, access rule, audit rule, descriptor, collection exports into real Microsoft targets | Six expected **PlatformNotSupportedException** results on each runtime |
| Reverse conversions and real Microsoft subclass execution | Compiled only on Linux; Windows branch executed separately (see below) |

Recorded outputs: [Linux net8](results/linux-net8.txt), [Linux net10](results/linux-net10.txt),
[sealed override net8](results/sealed-factory-net8.txt), [sealed override net10](results/sealed-factory-net10.txt).
Only machine-specific repository prefixes are removed from compile diagnostics.

### Windows execution (added 2026-10-06)

The unchanged probe source (PR head `d7214a7`) was run on Windows 11 Pro 10.0.26200
(build 26200.9457), x64, built with SDK 10.0.302. Execution runtimes were the installed
**servicing** releases, not 8.0.0/10.0.0: Microsoft.NETCore.App **8.0.29** (net8.0) and
**10.0.10** (net10.0). Loaded assemblies: System.DirectoryServices 9.0.0.0, with the ACL,
directory-base and identity assemblies at 8.0.0.0 and 10.0.0.0 respectively.

| Case | Executed result on both Windows runtimes |
|---|---|
| Portable hook checks (same as Linux table above) | Pass, same messages |
| Real Microsoft subclass: base-typed ModifyAccessRule/ModifyAuditRule reach protected overrides | Pass |
| Real Microsoft typed `AddAccessRule` helper does **not** dispatch to protected `ModifyAccess` | Pass (verified, no longer only source-backed) |
| Real Microsoft Persist name / SafeHandle / bool overrides, and base `Persist(false)` forwarding | Pass; base `Persist(true)` not called |
| SID, NTAccount, access/audit rule (inherited, both GUIDs), collection: export and import | Pass for this fixture set |
| Empty-DACL descriptor snapshot export/import; later Microsoft `SetOwner` not reflected in source | Pass |

Outputs: [Windows net8](results/windows-net8.txt), [Windows net10](results/windows-net10.txt).
Exit code 0 on both. This is the limited fixture set described below. It is not a general
conversion, data-loss or parity suite; for Microsoft's broader in-memory behavior see the
[Windows oracle](../acl-windows-oracle/README.md).

## How the scaffold is bounded

The project source-links unmodified production wrapper and SidCodec files, plus aliases and
rule-value scaffolding from the prior probe. `EXTENSION_PROBE` excludes that older probe's
throwing descriptor bases and substitutes `ExtensionScaffolding.cs`. Ordinary use of the older
project has no such define and retains its earlier behavior. Neither project modifies the
shipping library. The new bases implement managed dispatch/locks/flags for tests, not an ACL
algorithm or complete public/protected contract.

The public portable CommonSecurityDescriptor **fixture adapter** accepts only the fixed
28-byte empty-DACL fixture with revision 2 or 4. It copies bytes and exposes directory/container
flags. Other input is rejected. It is evidence that descriptor-typed constructors/properties
can be provided, not implementation of the descriptor/ACL member closure or a final public
facade. General edits still throw. The research binary setter is a fixture loader and does
not implement mutation intent, dirty tracking or concurrent access guarantees.

`Conversions.cs` binds to real Microsoft SID/account/rule/descriptor/collection types. SID and
name converters copy values; rule converters use factories to retain inherited state/GUIDs.
The descriptor import requires explicit complete-section provenance and the fixture adapter
rejects non-fixture bytes. Collection import/export creates new collections. The examples do
not implement general unknown-ACE handling, arbitrary consumer-subtype rejection, validation
parity, protected-facade mutation notification or a raw-preserving edit-back session. They must
not be used on real permissions.

`MicrosoftConsumer.cs` compiles a subclass against the **actual Microsoft** protected types,
proving those override signatures are accessible on both targets. Its runtime checks are
inside the Windows branch: base-typed dispatch, typed-helper bypass and three Persist hooks.
Its only base Persist call passes `false`; **no actual base true-ownership/native privilege
path is called on any platform**. The portable scaffold's true path is a deliberate refusal,
not an assertion that Microsoft's default has that exact exception behavior.

## Reproduce

Requires .NET 10 SDK, .NET 8/10 runtimes and restore access for Microsoft package 9.0.0:

```bash
dotnet build docs/research/acl-interop-probe/AclInteropProbe.csproj
dotnet run --project docs/research/acl-interop-probe/AclInteropProbe.csproj -f net8.0 --no-build
dotnet run --project docs/research/acl-interop-probe/AclInteropProbe.csproj -f net10.0 --no-build
```

With separate installations, run the matching host on
`docs/research/acl-interop-probe/bin/Debug/net8.0/AclInteropProbe.dll` or the net10.0 path.
The executable selects Linux rejection probes or Windows offline conversions by OS. A future
Windows run may expose fixture normalization/field mismatches; record those as findings, not
as an already passed oracle. Neither branch connects to a directory.

Negative compile probes must fail specifically with CS0239, not missing-SDK/restore errors:

```bash
dotnet build docs/research/acl-interop-probe/AclInteropProbe.csproj -f net8.0 -p:ProbeSealedFactory=true
dotnet build docs/research/acl-interop-probe/AclInteropProbe.csproj -f net10.0 -p:ProbeSealedFactory=true
```

Build normally after negative probes. CA1416 is suppressed solely in this research executable
to make explicit platform-failure calls; the converter methods carry Windows annotations and
the proposed production boundary requires appropriate runtime checks. The existing same-name
probe should still build/run with its original 46-constructor results. No full solution or
live integration test is necessary to reproduce these local experiments.
