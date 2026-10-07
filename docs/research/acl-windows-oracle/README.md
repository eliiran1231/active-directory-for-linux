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
- **J5** Flag effects measured in isolation, from a fresh object (all flags false) and from a
  loaded object whose flags were reset under the write lock:

  | Setter call | Flags set (owner/group/access/audit) |
  |---|---|
  | `SetSecurityDescriptorBinaryForm(bytes)` (one-argument, all sections) | 1111 |
  | `…(bytes, Access)` | 0010 |
  | `…(bytes, Audit)` | 0001 |
  | `…(bytes, Owner)` | 1000 |
  | `…(bytes, Group)` | 0100 |

  `GetSecurityDescriptorBinaryForm` and `GetAccessRules` afterwards did not change the flags.
  The flags therefore track **which sections a setter was called for**, not whether bytes
  changed. A read-only load through the one-argument overload marks all four sections as
  modified, so these flags cannot serve as mutation intent for a read-derived descriptor.
- **J1** `SetSecurityDescriptorBinaryForm(bytes, Access)` replaced only the DACL. An owner set
  earlier stayed. With flags reset immediately before the call, only the access flag became
  true. **J2** an `All` import from bytes without owner/group leaves them absent.
- **J3** With flags reset first: a `RemoveAccessRule` that matched nothing (bytes unchanged,
  returned `true`) set the access flag. So did a `ModifyAccessRule(Add)` of an already
  present rule (bytes unchanged, returned `modified=true`).

  *Correction (2026-10-06):* an earlier version of this report claimed the Access-only
  overload sets all four flags. That test never reset the flags left by the preceding load and
  `SetOwner`, so it could not support the claim. J1 and J3 now reset the flags first, and J5
  was added.

### Null, absent and empty ACLs

- **B1** An **absent** DACL and a **NULL** DACL both enumerate as one explicit
  `Allow Everyone rights=0xFFFFFFFF CI|OI` rule. Both export as **absent** (control 0x8000,
  DACL offset 0). The NULL-DACL input is **not preserved**: DACL_PRESENT is dropped.
- **B2/B4** Any mutation of an absent or NULL DACL, including `AddAccessRule` and
  `SetAccessRuleProtection`, **materializes that Everyone full-control ACE as a real ACE**
  (flags 0x03, mask 0xFFFFFFFF) alongside the change. This does **not** newly grant access:
  a NULL DACL already allowed everything, and the explicit ACE keeps that existing breadth. The
  change is to the **representation**: the absent/NULL state becomes a populated DACL. That
  matters for raw-byte preservation and for how the result reads, not as a permission increase.
- **B3** `RemoveAccess(Everyone, Allow)` on an absent or NULL DACL yields an **empty** DACL.
- Empty and populated DACLs round-trip byte-exactly. **B5** `AddAuditRule` on an absent SACL
  creates a present SACL (revision 4).

#### Per-operation matrix (B6)

Each operation ran on a freshly loaded object with its modified flags reset first, for each
of absent, NULL and empty DACL inputs. "Everyone" below means the explicit
`Allow Everyone 0xFFFFFFFF CI|OI` ACE.

| Operation | Absent or NULL DACL result | Empty DACL result | Flags set |
|---|---|---|---|
| Getters only (binary form, rules, SDDL, canonical) | Unchanged representation (NULL still exports as absent, as in B1) | Unchanged | none |
| `SetOwner` / `SetGroup` | DACL stays absent | Unchanged DACL | owner / group only |
| `AddAuditRule` (SACL only) | DACL stays absent; SACL created | DACL unchanged; SACL created | audit only |
| `SetAccessRuleProtection(false, true)` on an unprotected DACL | **Everyone materialized** | Bytes unchanged | access |
| `SetAccessRuleProtection(true, false)` | Everyone materialized, protected | Empty, protected | access |
| `AddAccessRule` of a rule identical to the implied Everyone rule | Everyone materialized (one ACE) | One Everyone ACE added | access |
| `AddAccessRule(deny U1 RP)` | Deny U1 + Everyone | Deny U1 | access |
| `SetAccessRule` / `ResetAccessRule(allow U1 RP)` | Everyone + Allow U1 | Allow U1 | access |
| `RemoveAccessRule` / `RemoveAccessRuleSpecific` / `RemoveAccess` / `PurgeAccessRules`, **no match** | **Everyone materialized** (`RemoveAccessRule` returned true) | Bytes unchanged | access |
| `PurgeAccessRules(Everyone)` | **Empty DACL** | Unchanged | access |
| `RemoveAccessRuleSpecific(exact Everyone rule)` | **Empty DACL** | Unchanged | access |
| `RemoveAccessRule(allow Everyone RP)`, partial | Split: `Everyone 0xFFFFFFEF CI\|OI` + `Everyone RP CI\|IO` | Unchanged, returned true | access |
| `AddAccessRule(null)` / `ModifyAccessRule(Add, null)` | `ArgumentNullException(rule)`; unchanged | Same | none |

Reading of this matrix (observations, not design decisions):
- Materialization is triggered by **any DACL-targeted call that gets past argument
  validation**, including calls that change nothing semantically.
- Owner, group and SACL changes, getters and failed calls do not materialize anything.
- Removing the Everyone entry, fully or partly, is the path from unrestricted to restricted.
  Full removal yields an empty, deny-all DACL.
- For the empty DACL, no-op calls leave the bytes unchanged but still set the access flag.

### Shared component storage (J6)

Added for PR #227 review finding 4. Each case points two offset fields at the same bytes (or
reads a SID from inside an ACE). Both `RawSecurityDescriptor` and `ActiveDirectorySecurity`:

| Layout | Microsoft result |
|---|---|
| Owner offset == group offset (one SID stored once) | **Accepted**; re-emitted with separate owner and group copies |
| SACL offset == DACL offset, shared empty ACL | **Accepted**; re-emitted as two separate empty ACLs |
| SACL offset == DACL offset, shared ACL with one audit ACE | **Accepted**. `RawSecurityDescriptor` re-emits two copies. `ActiveDirectorySecurity` keeps the SACL audit ACE and drops the audit ACE from the DACL copy (consistent with H1 "audit ACE inside DACL") |
| Group SID read from inside the DACL's ACE (partial overlap) | **Accepted**; group = that SID, re-emitted as a separate copy |
| Owner SID read from inside the DACL's ACE (partial overlap) | **Accepted**; same |

None of the outputs equal the input bytes: Microsoft always un-shares the storage. A parser
that rejects overlapping components therefore rejects descriptors Microsoft treats as valid.
Offsets pointing into the 20-byte header were not tested.

### Merging (C1–C3)

| Second rule added to first | Result |
|---|---|
| Same SID/type/scope, RP then WP | One ACE, mask OR'd (0x30) |
| Identical rule twice | Unchanged bytes; `ModifyAccessRule` still returns `modified=true` (flag effect: see J3) |
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

Callback ACEs are therefore **not** universally unsupported by Microsoft's in-memory path. The
evidence is narrow, though:
- each callback case used one ACE with a fixed 4-byte payload (`artx` marker only, not a
  well-formed conditional expression);
- it was preserved on import/export, and one unrelated add beside it worked.

This does **not** show full conditional-ACE support: real conditional expressions, larger
payloads, callback audit/deny types, enumeration or editing of the callback ACE itself, and
SDDL round-trips are all untested. It also says nothing about **safe edit-back** through a
conversion bridge, which has not been built.

### InheritanceType getter (I1)

OI only → `None` (no exception). OI|CI → `All`. CI|NP → `SelfAndChildren`.
CI|IO|NP → `Children`.

### Inactive InheritOnly matrix (I2)

"Inactive" means InheritOnly (0x08) set with neither ContainerInherit nor ObjectInherit. Each
target ACE was placed between two neighbor ACEs for U2: deny then allow in the DACL, or two audits
in the SACL. Microsoft then imported it, and an unrelated rule for a distinct SID (Everyone) was
added. Verdicts come from parsing the output ACL:
- **PRESERVED** means a byte-identical ACE exists.
- **MODIFIED** means the same mask and SID exist with changed bytes.
- **DROPPED** means neither exists.
- **Rejected** means an exception was thrown.

The summary block `== I2 SUMMARY` in the transcript lists every row.

| ACE kind | Flag / GUID variants tested | Import | After unrelated add |
|---|---|---|---|
| Allow (0x00) | IO; IO\|NP; IO\|INHERITED | DROPPED | DROPPED |
| Deny (0x01) | IO; IO\|INHERITED | DROPPED | DROPPED |
| Allow object (0x05) | IO with object flags 0, 1 (ot=G1), 2 (it=G2), 3 (both); IO\|INHERITED with flags 1 | DROPPED | DROPPED |
| Deny object (0x06) | IO with object flags 1, 2, 3 | DROPPED | DROPPED |
| Audit (0x02, in SACL) | IO\|S; IO\|F; IO\|S\|F; IO with no audit flags; IO\|S\|INHERITED | DROPPED | DROPPED |
| Audit object (0x07, in SACL) | IO\|S with object flags 1, 2; IO\|S\|F with flags 3 | DROPPED | DROPPED |
| **Controls** (IO\|CI): Allow, Deny, Allow object (flags 2), Audit | — | **PRESERVED** | PRESERVED |
| *Excluded, recorded only:* Allow IO with unknown ACE flag 0x20 | — | DROPPED | DROPPED |
| *Excluded:* Allow object IO with unknown object flag 0x4 | — | DROPPED | DROPPED |
| *Excluded:* Allow IO with 4 trailing bytes | — | DROPPED | DROPPED |
| *Excluded:* Callback allow (0x09) IO with application data | — | DROPPED | DROPPED |
| *Excluded:* Callback allow object (0x0B) IO with application data | — | DROPPED | DROPPED |
| *Excluded:* Unknown type 0x20 with IO | — | DROPPED | DROPPED |

No case was rejected. In every case both neighbors survived byte-exact. No row produced
MODIFIED: Microsoft never cleared only InheritOnly or otherwise activated the entry.

Observations (not allowlist decisions):
- Microsoft drops **every** inactive-IO ACE tested, regardless of ACE type, object flags,
  GUIDs, audit flags, the INHERITED flag, unknown flag bits, trailing bytes or callback payload.
- An unknown ACE type 0x20 **with** IO is dropped, and the ACL stays canonical. Without IO, the
  same type is preserved and makes the ACL non-canonical (H1/H2). So an IO-only flag changes
  whether Microsoft keeps an unknown ACE at all.
- Dropping is unconditional on Microsoft's side, so Microsoft's behavior cannot tell
  "understood" from "unknown" entries. Any narrower allowlist is a policy choice on our side.

**Separate finding, SACL ordering:** after `AddAuditRule` (Everyone XR Success), Microsoft
re-emitted the SACL as `[new Everyone audit; U2 Failure 0x04; U2 Success 0x20]`. The two existing
U2 audits swapped relative order, and the IO|CI control behaved the same way. This is
independent of the InheritOnly drop, but it means an unrelated audit edit can reorder existing
explicit audit ACEs. This was initially unapproved; the later 2026-10-07 ordering/projection
slice below records and implements the subsequently approved known-ACE policy. In the DACL, the added
Everyone allow was inserted between the deny and the existing allow; existing order was kept.

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

## Issue 226 seeded recording and replay

`SeededSequences.cs` supplements the original report with 919 bounded observations (seed 226).
The committed `results/seeded-windows-net8.json` and `seeded-windows-net10.json` were downloaded
unchanged from [GitHub-hosted Windows run 37658872363](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37658872363),
head `7ba9afbcdea4f58c57deacad1a9b943c7606588f`. Microsoft DirectoryServices remains pinned at
9.0.0; the hosted runtimes were .NET 8.0.31 and 10.0.12. Observation bodies are identical.
The functional replay embeds both exact files and asserts output bytes, returns, modified
flags, exceptions, original immutability and section intent on Linux and Windows.

The generator records the **effective constructed Microsoft rule**, as well as its requested
shape. This distinction matters: a requested object GUID on `ListChildren` is removed by the
Microsoft rule constructor. Earlier exploratory runs logged only the requested shape; those
outputs are retained in their Actions artifacts and are not used as replay expectations.

New measured findings:

- The bounded common/object access/audit sequences successfully execute Add, Set, Reset,
  Remove, RemoveSpecific, RemoveAll, Purge, protection and owner/group changes.
- Combined audit mask, audit qualifier and scope subtraction produces three ACEs in the
  recorded order (four common/object, success/failure cases).
- Detached `SetAccessRuleProtection(true, true)` preserves inherited flags and order. It does
  **not** convert those ACEs into explicit ACEs in these recordings, correcting the earlier
  design assumption. Protection with `preserveInheritance=false` removes them.
- One sequence temporarily contains two audit ACEs for one SID (common ListChildren plus
  object-qualified Self). Replacing all of those entries with Set succeeds without adopting
  any existing-entry sort policy.

These findings do not resolve the I2 SACL sorting decision. Unsupported movement/loss is
still refused by the portable implementation, and no directory-write behavior is claimed.

Further review probes in the same committed recording establish:

- Across distinct ObjectType GUIDs, mixed masks still remove global rights. Only
  0x1/0x2/0x8/0x10/0x20/0x100 are object-qualified. Split object ACEs keep their ACE
  family but drop ObjectType/InheritedObjectType fields when the residual mask or
  propagation no longer uses them. Twelve DACL/SACL observations assert this.
- Add/Set/Reset of an object rule upgrades a revision-2 empty/common DACL to revision 4.
  A common-rule Add next to an existing revision-2 object ACE retains revision 2.
- Remove/RemoveAll/RemoveSpecific on absent or NULL SACL return true with modified=false.
- Split-then-restore retains two same-scope ACEs in the measured sequence; the engine
  must not invent an additional compaction pass.
- Admins/domain SID insertion compares subauthority count before subauthority values.

The operation observations also replay end to end by sequence, retaining the original raw
origin and accumulating only real section changes. This is bounded script evidence, not
an assertion of arbitrary conditional/object-inheritance/SACL sorting coverage.

Twelve earlier observations isolate GUID-removal precedence in DACL/SACL: disjoint
self/descendant scopes skip GUID narrowing, inherited-object GUID conflicts apply only
when both ACEs have CI, and audit disjointness does not bypass GUID narrowing.

A 96-observation extension establishes bounded distinct-IOT and common-ACE OI coverage:

- Sixteen distinct-IOT cases cover All/Descendents requests against All, SelfAndChildren,
  Descendents and Children existing scopes, with mixed masks and both audit outcomes.
  Differing child GUIDs permit only self subtraction; descendant-only requests are no-ops.
- Eight cases combine distinct ObjectType and InheritedObjectType GUIDs. Disjoint qualified
  rights are no-ops; overlapping global rights can still be subtracted from self.
- Eight cases confirm that a missing existing ObjectType GUID conflict is deferred until
  inherited-GUID filtering establishes shared scope: six successful no-ops and two false
  unchanged removals. This distinction changes return/modified values, not descriptor bytes.
- Sixty-four common-ACE OI cases cover flags 1/3/5/7/9/11/13/15 with three Remove scopes
  and same-mask Add, for DACL and SACL. Import preserves every input. DS propagation math
  ignores OI, while permission/audit splits retain it. NP/IO without CI yields invalid
  propagation and false/no-change removal unless scopes are already disjoint.

Against that 96-case extension, the earlier engine reproduced 86 individual failures
and one stateful replay failure before its inherited-GUID/common-OI fix.

A 216-observation extension establishes object-ACE OI and combined-sequence behavior:

- A 192-case matrix combines OT-only, IOT-only and both-GUID object ACEs with every odd
  low flag combination, Remove(None/All/Descendents), same-mask Add(All), and both ACL kinds.
- Three eight-step sequences combine object OI, different inherited GUIDs, global-right
  splits, no-ops, protection/unprotection, inherited-entry removal and specific removal.
  The SACL sequence uses Set to replace all explicit splits for one SID; it does not adopt
  a multi-entry SACL sorting policy. Owner edits during the split state stay independent.
- There are 141 descriptor changes, 39 successful no-ops and 36 failed unchanged removals;
  no exceptions and no raw import differences. Inheritance merging retains original GUID
  fields; removal cleans GUID applicability per residual. Invalid propagation stays atomic.

The previous object-OI refusal gate caused 172 individual replay failures and one
stateful failure against those 216 observations. Removing that gate lets the existing
recorded DS algorithms handle the matrix without changes to merge/split logic. Late-failure
safety tests cover invalid common and object OI propagation after staging an earlier edit.

A 42-observation extension isolate asymmetric object-mask Add. Seven existing/incoming
mask pairs run forward and reverse, for DACL and matching/different audit flags. The
forward existing ACE has only IOT=G2; the incoming rule adds OT=G1 with the same IOT.
Eight cases merge into the existing object ACE: four absorbed no-ops and four mask changes
that add global rights. Reverse direction, uncovered qualified rights and different audit
flags retain two ACEs in the other 34 cases. All return/modified values are true. There are
no exceptions or raw import differences. The issue concerns byte shape, no-op and intent
parity; these recordings do not establish an effective-access escalation.

The earlier run 37539461545 intentionally failed freshness comparison because it added
those 42 cases to the committed 624; the first 624 are unchanged. Both portable test steps
passed. The old SameShape gate caused eight individual replay failures and one stateful
failure. The fix relaxes only Stage 1 mask merging for identical type/SID/flags and inherited
GUID, an absent existing ObjectType flag, and coverage of every incoming 0x13B-qualified
bit. It retains the existing GUID shape. A present Guid.Empty is not an absent field.
That change left later merge stages, unknown/trailing checks, SACL sorting, import compaction
and descriptor relocation policy unchanged. Other asymmetric GUID/scope or constructor parity
is not established by this bounded matrix.


An eight-observation extension (`later-merge-*`) close two concrete source-supported leads:

- Stage 3 forward: same-OT self with absent IOT plus descendants with IOT becomes All,
  retaining absent IOT. Reverse retains two ACEs. Repeated Add is byte-identical in both.
- Stage 2 forward: success with present-empty OT plus failure with absent OT (same mask,
  IOT and CI) combines audit flags, retaining the existing present-empty field. Reverse
  requested-empty OT is normalized to absent by the rule constructor; actual RuleHex
  records this and the existing same-shape merge retains absent OT. Repeats are unchanged.
- All eight return true/modified=true; all requested descriptor bytes survive import.
  This demonstrates mutation behavior without new import or SACL sorting policy.

Run 37542059850 intentionally failed freshness because the new 674 observations differed
from the committed 666; both portable steps passed. The first 666 observations are exactly
unchanged, and .NET 8/10 agree on all 674. The previous engine failed four new individual
steps plus stateful replay. Narrow Stage 2/3 predicates fix those cases, with exact GUID
shape preservation, prior-intent/no-op tests and negative mask/OT/IOT boundary coverage.
The implementation acceptance matrix documents predicate scope and remaining policy gaps.


The latest 101 observations consolidate the three native Add stages instead of retaining
qualifier-specific exceptions. `scope-qualifier-*` supplies 13 Deny/audit forward/reverse
and repeat calls; reverse audit stops before editing its resulting multi-entry SACL.
`empty-ot-mask-*` supplies four forward/reverse/repeat mask calls. `merge-value-stage*`
adds 84 directed cases: 12 OT/IOT value/presence pairs across Stage 1 Allow/Deny/Audit,
Stage 2 Audit and Stage 3 Allow/Deny/Audit. The matrix covers absent, present-empty,
matching and different nonempty GUID values and asymmetric absence controls.

All 101 return true/modified=true, with unchanged raw imports: 44 changed one-ACE outputs,
50 changed two-ACE outputs, six one-ACE no-ops and one two-ACE no-op. Both runtimes agree
and the prior 674 are unchanged. Run 37543448512 intentionally failed freshness against
674 committed observations while both portable steps passed. The old narrow predicates
failed 25 individual new observations plus stateful replay. The coherent three-stage
algorithm matches all 775, preserves existing raw GUID layout and uses GUID value equality
only during Add. Presence bits remain essential to asymmetric absorption. Six added
safety cases cover metadata, opaque sections, prior intent, repeats and specific-removal
identity. No SACL sorting/import/gap policy was expanded; this is bounded evidence, not
proof of parity for every accepted descriptor/rule combination.


The ordering/projection slice adds 144 observations from `OrderingSequences.cs`: 88 isolated
mutation calls, 24 stateful calls and 32 import projections. Windows run 37658872363 at
7ba9afbcdea4f58c57deacad1a9b943c7606588f reproduced identical observations on both runtimes;
the previous 775 are unchanged. Its freshness failure was expected against the older
committed baseline, while both portable test steps passed.

The cases cover I2 forward/reverse ties, three equal-key audits, common/object families,
SID order, inherited suffixes, DACL controls and all operation families. Import cases cover
duplicates, masks, scopes, audit flags, three/four-entry chains, object masks and present-empty
GUIDs in both directions and ACL kinds. Compaction is a single adjacent pass: three entries
can become two. All new calls/imports succeeded; recorded Microsoft output is not itself
permission to discard original write data.

The approved policy is in `docs/implementation/issue-226-ordering-policy.md`. Raw/live edits
sort but never blanket-compact. Observable imports compact only known entries. Narrow edits
selected from compacted identities refuse at the explicit reconciliation boundary; unrelated
original entries are preserved. Existing payload, gap and unknown-data protections remain.

## Projected-to-raw reconciliation extension

`ReconciliationSequences.cs` adds 258 actual Windows observations from probe commit
`91df3c9ea36d2fe500b6571ad485c5a2d2c06206`, [run 37670943012](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37670943012).
Both .NET runtimes produced identical observations; the earlier 919 are unchanged, bringing
the total to 1,177. This probe intentionally fails freshness against the previous baseline.
Each case imports detached original bytes, selects an actual Microsoft projected rule, and
records its effective binary form plus actual return/modified/output. No AD or Persist call
is used. Tests separately replay native live outcomes and reconcile the raw originals;
all 258 outcomes now match through retained projected state: 140 changes, 114 true no-ops
and four unchanged false/modified=false removals. See the [preservation policy](../../implementation/issue-226-ordering-policy.md)
for contributor provenance and explicit raw/re-import boundaries.

## Retained live projected sequences

`ProjectedLiveSequences.cs` records 208 steps from eight detached objects that are retained
across successive operations, including repeated getters. Probe commit
`45c95cc9b2524e5606bda94fc67e9c86c93d6640`, [run 37674000374](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37674000374),
produced identical .NET 8/10 observations; all earlier 1,177 remain unchanged, total 1,385.
The 208 steps comprise 96 true/modified=true rule returns, eight false/modified=false
conflicting-GUID removals, and 104 getter/identity/protection/purge steps with no boolean
return contract recorded. No exceptions occurred. Probe freshness deliberately failed
against the preceding recording baseline while portable tests passed.

Both raw/native replay and retained projected sequences assert actual outputs. Retained
replay begins from RequestedDescriptorHex and never re-imports raw storage between steps.
Getter checkpoints use Operation=Get and preserve live bytes; separate safety tests exercise
explicit new-engine import and prove that it may regroup raw contributors.

## Descriptor layout extension

`LayoutSequences.cs` adds 107 observations from probe commit
`6840525d3bd92fa9316524dd183344dc89bf6029`, [run 37678217815](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37678217815).
Both runtimes agree on all 1,492 observations; the preceding 1,385 are unchanged. All 107
layout observations completed without exceptions. The probe intentionally failed freshness
against the preceding baseline while both portable test steps passed.

Twelve layouts each record Import/Owner/Group/Set/Add/RemoveSpecific/RemoveAll/Protect.
Eleven additional imports use independently constructed fixed-offset, terminal-resize and
alias-unsharing candidates. Portable tests compare those raw candidates byte-for-byte,
separately from Microsoft observable outputs. The [layout policy](../../implementation/issue-226-layout-policy.md)
explains preservation guarantees and the precise remaining trailer/interior-resize boundaries.
Microsoft repacking is observable evidence, not permission to persist omitted raw bytes.

The embedded-SID/shrinking-ACL follow-up is recorded in probe commit
`6a5c1710c01fd4de16953c28fd755738ff0fc8ac`, [run 37682045103](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37682045103).
Microsoft directly imports the independently constructed candidate after the DACL shrinks
and its two embedded SIDs are copied into independent storage. Both runtimes accept it;
all earlier 1,492 observations remain unchanged. Replay compares the exact portable raw
output with that candidate. Total: 1,493 observations and 12 candidate-layout imports.

## Detached public foundation and complete surface inventory

The [foundation status](../../implementation/issue-226-foundation-status.md) records source heads,
probe run URLs, scope, runtime differences and explicit remaining dependencies. `--foundation-json`
records 2,684 actual detached identity/rule/ACE cases per runtime; `--surface-json` records 39 roots,
55 types and 702 declaration records. The checked-in foundation/surface JSON files are downloaded
Windows artifacts. The final workflow requires both baselines and compares observations and
structured surface separately from runtime provenance. Eight null-domain-comparison rows differ
between runtimes; target-specific replay retains that distinction and asserts all other rows agree.
The original mutation recording remains separate and unchanged. No name lookup or live directory
operation is involved.
