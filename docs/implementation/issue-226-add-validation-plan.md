# Explicit LDAP Add: transport evidence and opt-in server validation

Status: offline implementation and source research only. No live AD run, credentials,
network settings, schema, privileges or directory ACLs were changed. This document does
not authorize those operations. MicrosoftInterop public exposure was separately approved after this Add slice; that
approval does not authorize live AD. The four approved persistence contracts are not reopened here.

## What is established locally

`RawSecurityWritePreparation.PrepareAdd` accepts an explicit descriptor only if the
raw parser accepts it, all four sections are explicitly known, owner and group exist,
both ACL PRESENT bits are set with nonzero ACL offsets, and both ACLs are protected.
Empty and populated ACLs qualify. Physical ACL storage with PRESENT clear does not:
the existing Add guard checks semantic ACL state, not just a stored component reference.
It refuses before changing a request or replacing an already assigned descriptor.

For accepted inputs, preparation and AppendAdd copy the complete original image.
They do not serialize the observable projection or discard inactive/zero-mask ACEs,
callback/opaque bytes, ACL reserved fields/trailers, descriptor gaps/tails, RM control,
shared component offsets or original component order. Tests pin these properties and
input/output isolation. This is a **local request-byte guarantee**, not proof that
AD accepts or retains unusual storage. Unknown bytes are never silently repaired.

No explicit descriptor means omit `nTSecurityDescriptor`; it does not mean send an
empty descriptor. An existing untracked descriptor attribute or SD-flags control
causes atomic refusal. No new accepted form is introduced by this work. The existing
complete protected subset is already wired to creation; its server behavior remains
unvalidated. Broader public Add support must not be inferred from the internal tests.

## Source evidence and server-dependent behavior

Microsoft's managed DirectoryEntry implementation writes a modified ObjectSecurity's
binary form to the ADSI property cache, then calls SetInfo for a newly created entry.
This occurs in both pinned [.NET 8 source](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs)
and [.NET 10 source](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs)
(`CommitChanges`, `SetObjectSecurityInCache`). It establishes the managed-to-ADSI
boundary, not ADSI's exact wire bytes or server results. A public Microsoft comparison
must record bytes after the Microsoft descriptor serializer as well as its original
input. Raw protocol tests are a separate arm, not a substitute for that comparison.

| Input or operation | Protocol evidence / remaining dependency |
| --- | --- |
| No descriptor attribute | The most specific structural class's `defaultSecurityDescriptor` supplies the initial SD with domain/root-domain SID context; parent inheritance and requester context still participate. [SD defaulting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5ba06266-a8ef-4d34-9c29-411676249bcd) |
| Explicit absent DACL / NULL DACL | Explicit absent DACL fails Add; NULL DACLs are disallowed. These are not requests for the schema default. [Processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e42f988c-72a0-4f8d-a705-7235eac175d9), [requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a) |
| Explicit absent SACL | Server writes NULL in place of the absent SACL. Local broader support remains gated. [Processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e42f988c-72a0-4f8d-a705-7235eac175d9) |
| Empty vs populated ACL, protected vs unprotected | Protection blocks parent inheritance; unprotected ACLs depend on parent and effective object class. Standardization can reorder ACEs. Protection alone does not promise a byte-identical server result. [Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a) |
| Supplied inherited ACEs / RM control | Inherited ACEs are recomputed rather than authoritative; supplied RM control is reset as specified. Exact retained raw bytes and returned bytes must be reported separately. [Processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e42f988c-72a0-4f8d-a705-7235eac175d9) |
| Missing owner/group | Requester token, default administrators group and DC level affect defaulting. Do not derive ownership from the client machine or copied resolver. [Owner/group defaults](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3ac403a6-4e8e-488d-8ef6-c7fa1aa785b6) |
| Explicit owner and SACL | Add has owner constraints; Modify's WRITE_DAC/WRITE_OWNER/SeSecurityPrivilege checks must not simply be transplanted into Add. SACL readback privileges are a separate prerequisite. [Security considerations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6) |
| Computer class / server hardening | Per-attribute Add authorization can depend on server settings, caller and computed default SD. Record those conditions; do not change them to make a test pass. [Add authorization](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ff004f3e-8920-4ba4-aaa7-346710171972) |
| SD-flags on Add | The server ignores the control. Modify's section-mask semantics cannot preserve unspecified creation fields. [SD flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499) |

These are protocol/source findings, not newly recorded Windows or AD observations.
Opaque/unknown forms can be preserved in a request without any claim of server
acceptance. There is no general byte-identical server roundtrip claim for any class
of descriptor, including complete protected descriptors.

## Proposed opt-in comparison, not yet executable or authorized

An operator must first approve a concrete DC, disposable domain-NC OU, object-name
prefix, two parent fixtures, account identities, maximum object count and cleanup
window. Use an isolated test domain: NULL/empty DACL cases can create an inaccessible
or unexpectedly permissive object if assumptions are wrong. Do not run against
existing production objects or alter domain/schema settings for this experiment.

Prerequisites to be supplied and verified by that operator:

- One pinned writable Windows AD DC and its OS/build/patch, domain/forest functional
  levels and relevant SD standardization/Add-authorization settings; no referrals
  or multi-DC readback. Existing authenticated transport settings stay unchanged.
- Windows host for real Microsoft DirectoryEntry/ADSI and portable DirectoryEntry,
  plus Linux for the portable path, with exact framework/package versions recorded.
  Use the same explicit principal per comparison; no ambient identity assumptions.
- Preprovisioned disposable OU and two fixed parent fixtures: P0 with a recorded
  baseline ACL and P1 with additional identifiable inheritable access **and audit** ACEs
  for the test class. Record each ACE's trustee, mask, inheritance flags and class GUID;
  the audit fixture must be present and readable before claiming to test SACL inheritance.
  Record parent bytes and schema class GUID/defaultSecurityDescriptor before
  and after the run. The runner may not modify either parent ACL.
- A delegated creation account with class-specific Create Child on these parents,
  ability to set the chosen mandatory attributes, and required list/read permissions.
  A separate observer/cleanup account needs READ_CONTROL and attribute reads,
  existing authority for complete SACL retrieval (including the needed security
  privilege), and Delete Child on the disposable parents to remove even children
  with empty/protected ACLs. Do not grant privileges or change memberships in the run.
  The operator must establish a cleanup route for every planned descriptor first.
  For cell 3's protected empty DACL, parent read delegation does **not** inherit.
  Require a per-case observer identity and demonstrated authority on the exact protected
  descriptor under the target DC policy to read both objectGUID and every requested SD
  section, plus an independently demonstrated individual-delete route. Record the proof
  and identities before authorizing that case; do not assume ownership, parent read rights,
  SACL privilege or administrator membership alone supplies all of these capabilities.
  If the operator cannot supply that proof, cell 3 is blocked and must not create an object.
  Do not repair its ACL after creation or waive GUID verification to achieve cleanup.
- An explicitly chosen permitted owner SID and group SID; an unrelated owner SID
  for the negative case. Any privileged-owner comparison requires a separately
  supplied, already authorized account with the relevant restore privilege.
  SACL Add acceptance and privileged SACL readback are recorded independently.

Use a non-account leaf class such as `contact` for the first semantic matrix to avoid
passwords/logon side effects. Class-specific claims for users/groups/computers are
not established by that run. A later separate computer validation is mandatory before
claiming compatibility with the hardened computer Add path.

Three arms distinguish behavior: M = real Microsoft DirectoryEntry on Windows;
P = portable DirectoryEntry on Windows and Linux; R = explicit raw protocol Add
using exact bytes in a separately approved test harness. P retains its current
refusals. R is only a diagnostic comparator for forms P refuses or M normalizes;
it must never be wired around the production guard. Before any live send, preflight
the serializer in each arm and record actual payload/omission, refusals and errors.

The smallest initial semantic matrix is the following 15 input/parent cells, not a
cross-product of every flag. Use fresh unique names for each arm and runtime. Begin
with one matched runtime; repeat on the other supported runtime before a compatibility
claim. At most 60 attempted creations per runtime (M, P-Windows, P-Linux, R), 120 total;
P's local refusals reduce actual sends. No automatic retries or repeated fuzz cases.

| Cells | Creator descriptor | Parent / purpose |
| --- | --- | --- |
| 1–2 | Omitted | P0 and P1: schema/token defaults and parent effect |
| 3 | Owner/group explicit, empty protected DACL/SACL | P1: empty differs from omitted; requires proven per-case observer, GUID/SD reads and cleanup independent of inherited read delegation |
| 4 | Complete protected populated DACL, empty SACL | P1: existing accepted baseline |
| 5 | Same as 4, unprotected DACL | P1: isolate inheritance |
| 6 | Same as 4, unprotected populated SACL | P1: explicit inheritable audit fixture and independent SACL observer readback |
| 7 | Absent DACL, otherwise explicit | P0: negative; never substitute a default |
| 8 | NULL DACL, otherwise explicit | P0: negative; isolated domain required |
| 9 | Same as 4, absent SACL | P0: absent-to-NULL behavior |
| 10 | Same as 4, NULL SACL | P0: distinguish from absent and empty |
| 11 | Same as 4, omitted owner/group | P0: record actual defaulted SIDs |
| 12 | Same as 4, unrelated owner | P0: owner authorization failure/success under declared token |
| 13 | Same as 4, populated audit SACL | P0: Add result versus privileged readback; no assumed Modify rule |
| 14 | Same as 4, supplied inherited ACE | P1: recomputation despite client-supplied ACE |
| 15 | Same as 4, RM control and deliberately noncanonical explicit order | P0: record server transformations independently |

Callback/opaque encodings, unusual storage, object-specific inheritance, alternate
schema defaults and computer authorization form later targeted matrices. They are
excluded from the minimal claim and remain prerequisites for those compatibility areas.
Do not call their absence a passed test. Existing offline unknown-byte tests prove
request retention only.

Allowed operations after separate approval: bounded reads of RootDSE, named schema
classes, the two parents and run-created children; Add under those parents; immediate
and settled readback on the same DC; and individually verified leaf Delete for cleanup.
No Modify, Move, ACL repair, parent/schema mutation, account enablement/password/group
changes, recursive deletion or fault injection. A rejected operation is evidence;
do not change credentials/privileges/settings to force success.

Record case ID, input bytes, M's serialized bytes, P/R's exact request, controls,
result code/extended error, objectGUID when returned by successful readback, all raw
returned sections and requested coverage, decoded control/owner/group/ACE deltas,
parent/schema snapshots and cleanup outcome. Exclude secrets. Compare raw bytes first,
then enumerate every server transformation; semantic similarity does not excuse loss.
If complete readback is unavailable, label the case inconclusive, not equivalent.

If Add loses its response, stop that case: never replay or adopt an object solely by
DN, attributes or a newly discovered GUID. The existing creation handle stays
quarantined. Cleanup of an uncertain object requires operator-established creation
identity; no automatic deletion of that DN. For confirmed successes, verify the
recorded GUID at the exact run-owned DN before individual deletion; stop on any
mismatch. Log leftovers for the operator, then verify parents unchanged. No server
rejection/default/inheritance observation is to be fabricated in the detached oracle.

## Promotion gate

Before expanding production acceptance, obtain authorized recordings for the specific
new forms, isolate Microsoft serialization from server effects, reproduce failures in
offline planner tests, and review how explicit creation intent is represented without
inventing section defaults. Keep raw request state separate from observed server state.
No credentials, resolver connections or authority may travel in descriptor copies.
Public companion approval does not approve live AD or resolve this gate.
