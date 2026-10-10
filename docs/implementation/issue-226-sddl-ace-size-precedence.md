# Callback ACE size and malformed-field precedence

This is a bounded follow-up to the complete-ACE size guard independently cleared at
`790b141567f0e370f8809dbe82b721fe4fed6675`. It does not extend or close the native
near-64-KiB allocation investigation.

## Actual Windows observations

Probe head `1a0f7e35423c72ae775362233a04fd029cb416db`, run `38055011172`, records
108 cases on each runtime. The inputs cover XD, XU and ZA with zero GUIDs, an object
GUID only, an inherited-object GUID only, or both GUIDs. Each layout has an ordinary
control and an oversized form, crossed with nine field configurations: valid, bad flags,
rights, SID, object GUID, inherited GUID, condition, wrong ACL section, and combined
faults. This is a selected precedence matrix, not an exhaustive combination claim.

All native and managed outcomes agree across .NET 8/10. The six valid ordinary controls
succeed with exact native bytes accepted by the managed binary constructor and unchanged
input. The other 102 cases fail during native conversion: 38 error 1336, 24 error 1804,
16 error 1705, 12 error 1004 and 12 error 1337. All six otherwise-valid oversized
layouts return 1336, mapped to ArgumentException(sddlForm), confirming the full-ACE
size guard for the additional callback layouts.

Original three-row JSONL bytes are preserved in
`results/sddl-ace-size-net{8,10}.0.jsonl.gz`; `sddl-ace-size-provenance.json` retains
source head, run/jobs, compressed-file hashes and every original-file hash verified
against the Windows log record. Paths are relative to `docs/research/acl-windows-oracle`.
No locally generated outcome replaces native evidence. Existing worker isolation,
heap/time bounds, checked buffer copies and LocalFree cleanup apply.

## Demonstrated correction

Before the correction, portable import matches 92 cases and differs on 16: malformed
ZA object/inherited-object GUID fields, across the four ZA layouts and both sizes.
Windows reports Win32Exception(1705) before condition/size validation. Portable import
instead returned ArgumentException(sddlForm) from its generic GUID parser. The ordinary
controls reproduce the same difference; this is not an allocation-boundary rule.

The codec now retains native error 1705 for a failed ZA GUID conversion in either
field. Validation order and all other ACE families are unchanged. The public ACE
constructors, full-ACE size guard and preservation policy are unchanged. The new exact
replay suite reproduced 16 failures before this fix and passes all 108 cases plus its
inventory test afterward. Independent portable captures on both runtimes match all
108 native import outcomes; the complete before/after comparison is
`results/sddl-ace-size-portable-comparison.json`. It has no gap exclusions or
preservation allowlist: every directed input must match the recorded import outcome.
It also checks the native input identity and successful binary roundtrips; it makes
no text-export parity claim for these cases.

## Remaining gaps and stopping point

The **25 initial / 243 directed / overlapping 623 expanded allocation differences**
remain open, separately documented in [the boundary findings](issue-226-sddl-boundary-findings.md).
Their recorded comparisons are retained for their stated source versions; this ZA-only
error mapping does not affect their input types. These numbers must not be added as
unique inputs or relabeled passing parity. The 948 allocation inputs and their native
baselines are frozen. No further near-64-KiB expansion is proposed without a testable
causal model that predicts a new discriminating outcome.

## Recommended next slice: 64 ordinary-sized operation combinations

Prioritize mixed-ACE descriptors and section-scoped operations over more extreme-size
probes. The existing codec recordings cover many individual literals/operators and
families; the readiness inventory specifically leaves operation combinations and
unrelated raw-data preservation open.

Use eight detached descriptor fixtures with explicit numeric SIDs and owner/group:
ordinary ACEs mixed respectively with XA, XD, ZA object-only, ZA inherited-only,
ZA both-GUIDs, XU audit, typed RA claims, and FL. Keep each input below 2,048 UTF-16
code units and expression nesting at or below eight. The resource fixture can contain
several already-supported ordinary claim value types without exploring count limits.

For each fixture record eight operations: parse/binary copy; owner/group-only export;
DACL-only export; SACL-only export; full export; owner-only SDDL edit; group-only SDDL
edit; and one malformed selected-section edit. Record before/after binary images,
selected section flags, native results and exact errors. Portable assertions must
preserve unrelated raw sections/payloads and roll back failed edits. Native export
omission or partial failed mutation remains an explicit, individually pinned policy
difference, never a reason to weaken preservation or atomicity.

This 8-by-8 proposal targets ordinary usage and connects import, partial export and
editing behavior. It has not been implemented or recorded here. It needs no access
check evaluator, identity lookup, authority transfer, AD transport or live directory.

## Validation scope

Linux .NET 8/10 each pass 12,248 offline core tests, 55 fixture-free consumer tests,
34 metadata-only fixture-registration tests and four applicable companion tests;
14 Windows-only companion groups skip on Linux. Both pass five bounded invariant
workers (2,822 iterations each). The full six-project Release rebuild has zero errors
and 14 existing xUnit2013 warnings. Exact-head Windows test/freshness results and
artifact links are recorded in PR 228 after publication. Full unfiltered live-directory
suites remain outside this task. No live AD, merge, release, security/authority change,
preservation relaxation or next-slice implementation occurred.
