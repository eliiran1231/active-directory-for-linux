# Same-name portable dependency feasibility probe

This is **research scaffolding, not a security implementation**. It tests the user-approved
direction of preserving the ten existing class names/member patterns while replacing their
Windows-only base and identity types. See [the candidate design](../../design/same-name-portable-acl-api.md).
The original [unchanged-contract failure probe](../acl-contract-probe/README.md) remains valid.
No production source is edited and no parallel shipping ACL API is introduced.

## What it actually tests

The csproj source-links the complete, unchanged production `ActiveDirectorySecurity.cs`
(containing all ten wrappers) and `SidCodec.cs`. Compiler aliases bind rule/security/identity
dependencies to new `AdForLinux.Security.*` scaffold types. This is a different **runtime type
identity**, not a way to retain BCL compatibility. The only copied production enum is the
small `SecurityMasks` fixture; no DirectoryEntry, directory client, credentials or live I/O
are present. The scaffold's descriptor constructor, mutations, locks and dirty-state access
fail deliberately with `NotSupportedException` or have placeholder state. Do not use it to
handle actual permissions, serialization, concurrency or user data.

Scaffolding implements just enough portable SID construction and rule value storage to bind
the real wrapper declarations. Descriptor bases are shape stubs; the public
`CommonSecurityDescriptor` stub exists only for the production file's internal constructor
reference and is **not proposed as a shipping dependency**. The design proposes replacing
that private loading path with internal core state in a later implementation.

Executed 2026-10-05, Debian GNU/Linux 13 x64, input PR head
`575ff805ee484370a172de6933717fd28570308b`. SDK 10.0.100 built both targets; hosts were
Microsoft.NETCore.App **8.0.0** and **10.0.0**. The normal build succeeded without warnings.
These are initial runtime releases, not tests of every servicing version.

| Check | net8.0 / 8.0.0 | net10.0 / 10.0.0 |
|---|---|---|
| All ten wrappers / 46 public constructor shapes | Pass | Pass |
| SID binary offset round-trip and defensive copy | Pass | Pass |
| Virtual factory dispatch to ActiveDirectoryAccessRule | Pass | Pass |
| Generic collection of portable base rules | Compiles/runs | Compiles/runs |
| Actual BCL AccessControlType retained as property type | Pass | Pass |
| DACL LDAP mask differs from BCL AccessControlSections.Access | Pass | Pass |
| BCL ObjectSecurity and IdentityReference assignability | Correctly false | Correctly false |
| Descriptor mutation | Expected explicit scaffold refusal | Same |
| Unmigrated BCL SID argument / base assignment / generic collection | Expected CS1503, CS0029, CS1950 | Same |

Outputs: [runtime net8](results/linux-net8.txt), [runtime net10](results/linux-net10.txt),
[negative compilation net8](results/bcl-client-net8.txt),
[negative compilation net10](results/bcl-client-net10.txt).
The negative compiler logs remove only the machine-specific repository-path prefix.
One valid parameter set is invoked per constructor; passing 46 shapes is **not** validation
of every argument combination, null behavior, enum range, GUID eligibility or error order.

## Public/protected dependency inventory

`--inventory` reflects the **actual BCL types**, without constructing them. The expanded
metadata inventory was regenerated during review of PR head `60e8522e35f85aab31438f6fc5ef9220789c36e4`;
both constructor transcripts were re-executed and remained byte-identical. Results are
[net8](results/bcl-surface-net8.txt) and [net10](results/bcl-surface-net10.txt). These 11 type
inventories identify base/interface relationships, constructors, method/accessor signatures,
static/abstract/virtual/final method flags, abstract/sealed type status and visible fields.
Member access is emitted as exact metadata: `Public`, `Family` (protected), `FamORAssem`
(protected-internal) or `FamANDAssem` (private-protected). Field static/readonly/literal flags
are also recorded. This corrects the first inventory's collapsed "protected" label. Generic interface strings include runtime assembly
versions; apart from that version difference the recorded inventories matched on these hosts.
The scaffold does not implement this inventory; see the design's explicit protected-member
manifest. The inventory is not a full attribute/nullability/default-value API snapshot and does not
assert Windows implementations behave like Linux stubs. Reference-source checks also confirm
the collection constructor/AddRule shape and the protected descriptor dependency:
[AccessControl reference declarations](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.AccessControl/ref/System.Security.AccessControl.cs),
[DirectoryObjectSecurity reference declarations](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.IO.FileSystem.AccessControl/ref/System.IO.FileSystem.AccessControl.cs).

## Reproduce

Requires .NET 10 SDK and .NET 8/10 runtimes. From repository root:

```bash
dotnet build docs/research/same-name-acl-probe/SameNameAclProbe.csproj
dotnet run --project docs/research/same-name-acl-probe/SameNameAclProbe.csproj -f net8.0 --no-build
dotnet run --project docs/research/same-name-acl-probe/SameNameAclProbe.csproj -f net10.0 --no-build
dotnet run --project docs/research/same-name-acl-probe/SameNameAclProbe.csproj -f net10.0 --no-build -- --inventory
```

With separate hosts, run `/path/to/dotnet8/dotnet` or `/path/to/dotnet10/dotnet` directly on
`docs/research/same-name-acl-probe/bin/Debug/net8.0/SameNameAclProbe.dll` or its net10.0 path.
For the expected compilation failures (nonzero exit must be a listed C# diagnostic, not a
missing SDK/package error):

```bash
dotnet build docs/research/same-name-acl-probe/SameNameAclProbe.csproj -f net8.0 -p:DefineConstants=BCL_CLIENT
dotnet build docs/research/same-name-acl-probe/SameNameAclProbe.csproj -f net10.0 -p:DefineConstants=BCL_CLIENT
```

Build normally again afterward. No NuGet package dependency or production project reference
is required for this executable; the shared repository build props supply language/nullable
settings. It is excluded from the solution and marked non-packable. No Windows runtime,
Microsoft DirectoryServices 9.0.0 oracle, LDAP, AD, Samba or workflow was executed. Those remain
separate validation gates, as do full SID semantics, SDDL, translation, ACL edits and transport.
