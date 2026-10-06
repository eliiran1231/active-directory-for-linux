# Offline Windows oracle: Microsoft in-memory descriptor behavior

**Research only.** This executable records how Microsoft `System.DirectoryServices` **9.0.0**
`ActiveDirectorySecurity` behaves on detached, in-memory objects built from handcrafted
descriptor bytes. It uses no `DirectoryEntry`, LDAP, AD or Samba. It makes no permission
writes, `Persist` calls, token or privilege changes. It is outside the solution and
non-packable. The outputs are **observations of Microsoft behavior**, not parity verdicts for
any portable implementation; none exists yet.

[`Fixtures.cs`](Fixtures.cs) builds descriptor, ACL, ACE and SID bytes independently of the BCL
serializer, and decodes output bytes for review. [`Program.cs`](Program.cs) runs the scenarios.

## Recorded execution

Research date: 2026-10-06. Host: Windows 11 Pro 10.0.26200 (build 26200.9457), x64.
SDK 10.0.302 built both targets.

| | net8.0 | net10.0 |
|---|---|---|
| Runtime | Microsoft.NETCore.App **8.0.29** | Microsoft.NETCore.App **10.0.10** |
| System.DirectoryServices | 9.0.0.0 | 9.0.0.0 |
| System.Security.AccessControl | 8.0.0.0 | 10.0.0.0 |
| System.IO.FileSystem.AccessControl | 8.0.0.0 | 10.0.0.0 |
| System.Security.Principal.Windows | 8.0.0.0 | 10.0.0.0 |
| Exit code | 0 | 0 |

These are **servicing** runtimes, not the 8.0.0/10.0.0 releases used by the Linux probes.
Apart from the six header lines, the two transcripts are **byte-identical**. Outputs:
[net8](results/windows-net8.txt), [net10](results/windows-net10.txt). Each case records:
- decoded output bytes and hex;
- whether the input bytes were preserved, and whether re-importing the output is stable;
- `AreAccessRulesCanonical`/`AreAuditRulesCanonical` and `AreAccessRulesProtected`;
- the protected modified flags, read under `ReadLock`;
- the SDDL form;
- the enumerated access and audit rules.

## Observed behavior (verified on both runtimes above)

Case IDs refer to the transcript.

### Initial state and import

- **A1** `new ActiveDirectorySecurity()` serializes as 28 bytes: no owner/group, absent SACL,
  **present empty DACL** (revision 4). All modified flags are false.
- **B1–B5, J3** `SetSecurityDescriptorBinaryForm` sets **all four** modified flags to true,
  including with `AccessControlSections.Access` (J1). Even a read-only import looks
  "modified", so these flags cannot serve as mutation intent.
- **J1** `SetSecurityDescriptorBinaryForm(bytes, Access)` replaced only the DACL. An owner set
  earlier stayed. **J2** an `All` import from bytes without owner/group leaves them absent.

### Null, absent and empty ACLs

- **B1** An **absent** DACL and a **NULL** DACL both enumerate as one explicit
  `Allow Everyone rights=0xFFFFFFFF CI|OI` rule. Both export as **absent** (control 0x8000,
  DACL offset 0). The NULL-DACL input is **not preserved**: DACL_PRESENT is dropped.
- **B2/B4** Any mutation of an absent or NULL DACL, including `AddAccessRule` and
  `SetAccessRuleProtection`, **materializes that Everyone full-control ACE as a real ACE**
  (flags 0x03, mask 0xFFFFFFFF) alongside the change. The original breadth is kept, now in
  explicit form.
- **B3** `RemoveAccess(Everyone, Allow)` on an absent or NULL DACL yields an **empty** DACL.
- Empty and populated DACLs round-trip byte-exactly. **B5** `AddAuditRule` on an absent SACL
  creates a present SACL (revision 4).

### Merging (C1–C3)

| Second rule added to first | Result |
|---|---|
| Same SID/type/scope, RP then WP | One ACE, mask OR'd (0x30) |
| Identical rule twice | Unchanged bytes; `ModifyAccessRule` still returns `modified=true` |
| RP None + RP All | One ACE, scope All (CI) |
| RP None + RP Descendents (complementary scopes) | **Merged** into one ACE, scope All |
| RP Children + RP SelfAndChildren | One ACE, SelfAndChildren |
| Non-object RP + object RP G1 | Not merged (two ACEs) |
| Object RP G1 + object WP G1 | Merged, mask 0x30 |
| Object G1 + object G2 | Not merged |
| Same ObjectType, InheritedObjectType G2 vs none | Not merged |
| Allow + Deny | Not merged; deny placed first |
| Audit Success + Failure, same mask | Merged into one ACE, flags 0xC0 |
| Audit Success RP + Success WP | Merged, mask 0x30 |

### Ordering

- **D1/D2/F1/H2** Explicit deny precedes explicit allow, and explicit ACEs precede inherited
  ones. **Within** each group, non-object ACEs precede object ACEs. This also moved a callback
  object ACE (0x0B) behind a newly added non-object allow.
- **F1 import** An input with an allow-object ACE ahead of non-object allows was reported
  canonical, but was **re-emitted in a different order**: object ACEs moved after the
  non-object ones. Import plus export normalizes order even without a mutation.
- **J4** The component order DACL, owner, group is re-emitted as owner, group, (SACL), DACL.

### Non-canonical input (G1–G3, H1/H2 unknown type)

- Explicit-allow-before-explicit-deny, inherited-before-explicit, and an unknown ACE type
  0x20 each give `AreAccessRulesCanonical == false`. Their bytes are **preserved exactly** on
  import and export.
- `AddAccessRule` and `PurgeAccessRules` on such a DACL throw
  `System.InvalidOperationException`: "This access control list is not in canonical form and
  therefore cannot be modified." Bytes are unchanged afterwards.

### Removal and splitting (E1–E2)

| Start | Operation | Returned | Result |
|---|---|---|---|
| Allow RP\|WP All | Remove WP (self only) | true | **Split**: `Allow CI RP` + `Allow CI\|IO WP` |
| Allow RP\|WP All | Remove RP Children | **false** | Unchanged |
| Allow RP\|WP All | Remove RP\|WP Descendents | true | Self-only `Allow RP\|WP` |
| Non-object Allow RP | Remove object RP G1 | **false** | Unchanged |
| Object Allow RP G1 | Remove non-object RP | true | Object ACE removed |
| Allow WP | Remove RP (no such bits) | **true** | Unchanged |
| Audit Success\|Failure All | Remove Failure (self only) | true | Split: `Success CI` + `Failure CI\|IO` |

`RemoveAccessRule` returns `true` even when nothing matched (E1 last row, J3).
`RemoveAccessRuleSpecific` with an inexact rule changes nothing and does not throw.

### Set / Reset / Purge / RemoveAccess scope (F1)

The fixture has, for U1: an explicit object deny XR G2, an object allow RP G1, a non-object
allow WP, and an inherited allow RP. It also has an explicit allow for U2.

- `SetAccessRule(allow U1 …)` removes **every explicit allow for U1, regardless of object
  GUID**. The explicit deny, inherited ACEs and other SIDs stay. Then it adds the rule.
- `ResetAccessRule` removes explicit allow **and** deny for U1, then adds.
- `PurgeAccessRules(U1)` removes every explicit ACE for U1. Inherited ACEs stay.
- `RemoveAccess(U1, type)` removes every explicit ACE of that type for U1, regardless of GUID.

### Unusual payloads (H1 import, H2 unrelated add)

| Payload | Import | After unrelated `AddAccessRule` |
|---|---|---|
| Callback allow ACE 0x09 with application data | Preserved byte-exact; not enumerated as a rule | Allowed; preserved |
| Callback allow object ACE 0x0B with application data | Preserved byte-exact; not enumerated | Allowed; preserved, reordered after non-object allow |
| Unknown ACE type 0x20 | Preserved; ACL non-canonical | **Refused** (InvalidOperationException) |
| Allow ACE with 4 trailing bytes | Preserved | Preserved |
| ACL revision 2 holding an object ACE | Preserved | Preserved, still revision 2 |
| Object ACE with object flags 0 | Preserved (type 0x05) | Preserved |
| Object ACE, ObjectType present but all-zero | Bytes preserved; **rule reports `ObjectFlags=None`** | Preserved |
| Object ACE with unknown object flag 0x4 | Bytes preserved (flags 5); rule reports only `ObjectAceTypePresent` | Preserved |
| Unknown ACE flag 0x20 | Preserved | Preserved |
| Generic bit 0x80000000 in mask | Preserved, not mapped | Preserved |
| Control bits 0x0500 | **0x0100 (DACL_AUTO_INHERIT_REQ) dropped**; 0x0400 kept | — |
| Mandatory-label ACE 0x11 in SACL | **Dropped silently** (SACL becomes empty) | — |
| Audit ACE inside the DACL | **Dropped silently** | — |
| ACE flags IO only (no CI/OI) | **ACE dropped** | — |
| ACE flags NP only | **NP flag cleared** | — |

Callback ACEs are therefore **not** universally unsupported by Microsoft's in-memory path:
those cases were preserved and edits beside them worked.

### InheritanceType getter (I1)

OI only → `None` (no exception). OI|CI → `All`. CI|NP → `SelfAndChildren`.
CI|IO|NP → `Children`.

## What this does not establish

- Behavior on 8.0.0/10.0.0, other servicing releases, other architectures or other Windows builds.
- Behavior of the `DirectoryEntry` commit path, the wire SD-flags mask, server reordering, or
  inheritance recomputation (O-4 remains open; that needs a directory).
- SDDL parsing of arbitrary strings, alias resolution, constructor argument validation for
  all 46 overloads, or exception ordering beyond the recorded cases.
- Whether a given normalization is "harmless". The transcript shows what changed. Classifying
  each change as acceptable normalization versus data loss is a design decision that has not
  been made.

## Reproduce

On Windows with the .NET 10 SDK and .NET 8/10 runtimes, from the repository root:

```bash
dotnet build docs/research/acl-windows-oracle/AclWindowsOracle.csproj
dotnet run --project docs/research/acl-windows-oracle/AclWindowsOracle.csproj -f net8.0 --no-build
dotnet run --project docs/research/acl-windows-oracle/AclWindowsOracle.csproj -f net10.0 --no-build
```

On any other OS the executable prints a notice and exits 2 without running a case.
