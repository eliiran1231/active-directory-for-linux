# Retained contributors and facade SDDL export

The RA/FL-only guard in `ee6435aac6f38036618bfffb2522a28e02d79be0` did not
cover the formatter's complete refusal boundary. The minimal reproduction
`new CommonSecurityDescriptor(true, true, "S:(ML;;NW;;;LW)").GetSddlForm(Audit)`
returned `S:` even though raw export refused the stored label's omission. A binary
DACL allow ACE with SuccessfulAccess also lost that flag through projection before
the raw formatter could reject its omission. Inactive no-GUID ZA tails and zero-mask
opaque ACEs provided additional bypasses.

## Shared validation, followed by contributor preservation

For each selected ACL, facade formatting now runs the existing raw ACE formatting
checks against the retained current raw contributors. `AppendAce` can validate
without building a second ACE/ACL output buffer; the checks are shared with raw
formatting. No second token/type denylist defines the facade boundary.

The existing reachable refusal families are:

| Raw formatter check | Directed fixtures |
| --- | --- |
| ML, SP, TL, RA and FL omission; wrong ACL section | All five families in both SACL and DACL |
| Non-audit ACE audit flags | Allow/deny common, object and callback types 0, 1, 5, 6, 9, 10, 11 |
| Opaque bytes on noncallback ACEs | Common, object, audit and zero-mask common payloads |
| Unrepresentable conditional encoding or tail | Unknown condition token, zero-mask condition and inactive no-GUID ZA tail |
| Unknown object flags | Object ACE flag bit 4 |
| No valid SDDL token/layout | Unknown type 22 in both ACLs |
| Audit/alarm without audit flags | Active and reviewed inactive ordinary audit controls |

The formatter's unsupported-layout fallback and conditional decoder's exact
re-encoding checks remain shared too. The label-specific payload branch is already
unreachable behind unconditional label omission refusal; it is not a separate
supported label-export mode. This change does not claim every possible binary
encoding or every existing raw text-validation rule is native-compatible.

Raw formattability alone does not prove projection preserved a contributor. Valid
callback conditions also disappeared when CommonAcl normalized a zero mask or
inactive IO ACE. After raw validation, contributors outside the core's reviewed
ordinary-ACE subset must therefore occur byte-for-byte in the selected observable
ACL, with duplicate occurrence counts preserved. This allows opaque ACE reordering
without authorizing payload/flag loss or unreviewed merging. The occurrence map is
linear in the serialized ACL bytes; it does not compare every raw ACE with every
observable ACE.

Fully understood ordinary ACE ordering, compaction and approved inactive
normalization remain allowed. The existing `IsInactiveInheritOnly` predicate
provides the precise D13 exception to raw validation: it excludes callback types,
opaque tails and unverified flags. The contributor check uses the existing
`IsUnderstoodAce` boundary. Mask zero or IO by itself never authorizes opaque-data
loss. Output is still the observable view; retained raw data is not substituted
as output or rewritten by a read.

## Bounded measurements and regressions

The matrix defines 37 ordinary-sized fixtures crossed with eight fresh operations:
None, Owner|Group, Access, Audit and All exports; owner edit; group edit; and owner
edit followed by selected-ACL export. Every row records raw export, direct
CommonSecurityDescriptor export and detached ActiveDirectorySecurity export,
original bytes, initial normalization, prepared state, final bytes and dirty flags.
The last operation tests refusal with already-pending owner intent.

The initial 264-case probe at `cf4a90562bbc4b25e5d292d314005c20ff6523a1`
recorded equal observations on Windows .NET 8/10. The first regression run failed
46 tests before the shared validation correction, including the minimal ML case.
Four further fixtures add valid inactive/zero-mask callback payloads and an active
callback control. Raw export succeeds for these representable payloads; only the
unapproved facade removal must refuse. Disabling only the contributor check
reproduced nine additional failing cases (289 passing); restoring it removes that
bypass. These are separate negative controls, not additive unique input counts.

The completed 296-case source probe is `a9726e01491dbaa3fdc8bc3075ba53235e327588`,
[Windows run 38059072847](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38059072847).
All rows agree across .NET 8/10; the first 264 also agree with the earlier probe.
The portable results agree across runtimes. **218 complete rows compare exactly;
78 rows have individually pinned differences in 216 export facets**: 171
retained-content loss refusals, 27 native non-roundtrippable callback exports,
12 pre-existing unsupported-condition exception-type differences, and six
pre-existing raw unaudited-ACE validation differences. Facets are not unique
inputs and must not be summed with older matrices as new distinct cases.

[Provenance](../research/acl-windows-oracle/results/sddl-retained-export-provenance.json)
pins source head, run/jobs/artifacts and all original-file SHA-256 values.
The `.jsonl.gz` files retain original Windows bytes, headers and newlines;
`.json.gz` files retain all headers and observations for replay/freshness.
Bytes were recovered from compressed connector logs and checked against Windows
file hashes. Artifact ZIPs were not downloaded.
[Comparison counts](../research/acl-windows-oracle/results/sddl-retained-export-comparison.json)
keep compatibility differences separate from deliberate refusals. The workflow
freshly compares every field of all 296 native observations.

Tests retain every original native row. Differences are pinned per row and per
RawExport/Result/CommonResult facet, including a hash of the complete native row.
All other fields compare exactly. Refusal proofs distinguish lost ACE bytes,
native callback text that cannot reparse, pre-existing unsupported-condition
exception-type differences, and pre-existing raw audit-validation differences.
The latter two are compatibility differences, not successful parity or evidence
that native raw export lost those ACEs.

Every export/refusal preserves the complete raw image, original image, observable
bytes, mutation generation, dirty flags, pending intent, source, attachment and
retrieval coverage. Owner/group edits change only the selected same-length SID
bytes and corresponding intent/dirty flag. The detached objects retain no server
read context or authority. The native and portable objects are freshly constructed
for every operation, and normalized native bytes never become portable source data.

## Local verification

Linux .NET 8/10 each pass 12,611 core, 55 fixture-free consumer, 34 metadata-only
fixture-registration and four applicable companion tests; 14 Windows-only companion
groups skip. The full six-project Release rebuild has zero errors and 14 existing
xUnit2013 warnings. Both runtimes pass all five bounded invariant workers (2,822
iterations each), including the existing deep-expression allocation checks. The new
suite contributes 296 replay/state cases, one minimal-label regression and one full
inventory/classification check. Exact publication-head Windows evidence is reported
on PR 228; local success alone does not establish that workflow result.

## Limits

The 25 initial, 243 directed and overlapping 623 expanded allocation gaps remain
frozen and unresolved. No allocation formula, cutoff, size sweep or preservation
relaxation is introduced. The renderer's existing linear traversal is unchanged.

The measured raw unaudited-ACE validation and unsupported-condition exception
differences still need context-specific compatibility work. Broader selected
DACL/SACL replacement combinations and the identity/server boundaries in the
[readiness inventory](issue-226-remaining-compatibility.md) also remain open.
These detached observations prove no live AD behavior. No credential, security,
transport, public-surface, merge or release change is part of this correction.
