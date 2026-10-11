# Raw SDDL formatting and validation contracts

The retained-export follow-up identified 12 malformed-condition exception-type
facets and six ordinary raw unaudited-ACE validation facets. All 18 now match the
actual native recording exactly, including exception type, parameter and native
error code, or complete text/reparse outcome. They are removed from the difference
manifest. They were compatibility defects, never evidence of native data loss.

## Measurements

The bounded matrix contains 80 detached observations: 40 small fixtures with fresh
selected and unselected section exports. It covers unknown condition opcodes,
missing signature, truncated literal and operator underflow; zero-mask and
unaudited controls; common/object audit and alarm layouts; supported callback
families; malformed condition combined with audit/reserved-object flags; valid
condition controls; extra condition padding and ordinary opaque tails. Eight
fixtures separate single/leading unaudited ACEs from an ordinary audited anchor.
No size sweep, identity lookup or directory operation occurs.

Source `defc8aaa729aa9ad699ec83c1c73e9fb7c1b4379`,
[Windows run 38062727560](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38062727560),
records 80 identical observations on .NET 8 and 10. Its first 64 agree with the
independent earlier probe at `9dd3df79881fd8de6f72367b606481556c2399f2`,
[run 38062527537](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38062527537).
Original Windows JSONL bytes, headers, job/artifact IDs and file hashes are retained
in the [provenance](../research/acl-windows-oracle/results/sddl-raw-contract-provenance.json).
Recovery used compressed connector logs and verified Windows-emitted hashes;
artifact ZIPs were not downloaded.

Native rejects the measured malformed conditions with InvalidOperationException,
including zero masks and competing audit/reserved-object flags. It exports and
reparses unaudited AU, OU and valid XU without losing the ACE, whether single,
leading or following an audited ACE. Native facade projection removes active
unaudited/zero-mask contributors. Raw unaudited AL/OL formatting succeeds but its
text reparse fails. Native formatting discards extra condition padding and opaque
ordinary-ACE tails. These outcomes are recorded separately, not inferred from
portable behavior.

## Correction and preservation boundary

Structurally malformed callback payloads now report InvalidOperationException.
Known token families outside the lossless codec subset, extra padding and
noncanonical encodings still refuse with NotSupportedException. Invalid condition
validation precedes the non-audit audit-flag loss check, matching measured error
precedence. A failed export never rewrites its input.

Raw SACL formatting and text parsing now accept unaudited AU/OU; valid unaudited XU
formatting also succeeds. Audit ACEs in a DACL remain invalid. The active unaudited
retained-facade check is explicit and independent of raw formatting. It continues
to refuse projection loss. The approved fully understood inactive ordinary-ACE
normalization predicate remains unchanged; it grants no callback/opaque exception.
Unaudited alarm output that cannot reparse refuses explicitly rather than
synthesizing a different ACE or condition.

The older 296-row matrix improves from 218 to **224 complete exact rows**. Its
remaining **72 pinned rows / 198 facets** are the existing 171 retained-content-loss
and 27 nonroundtrippable-output refusals. The six facade zero-mask condition
refusals still occur; their exception now reflects invalid retained condition data.
All original native recordings and full-row hashes are unchanged.

The new matrix has **55 complete exact rows** and **25 individually pinned refusal
rows / 56 facets**: 52 demonstrated retained-byte-loss refusals and four raw alarm
nonroundtrippable-output refusals. Every unpinned field compares exactly. Each loss
pin proves that an original ACE byte sequence is absent from native reparsed
output; alarm pins assert the exact native reparse error. The comparison is in
[the machine-readable inventory](../research/acl-windows-oracle/results/sddl-raw-contract-comparison.json).

All 80 cases assert unchanged raw/original/observable bytes, input buffers,
generation, dirty flags, pending intent, source, attachment and retrieval coverage.
Copies and exports gain no resolver, credentials, connection or read authority.
With the production correction disabled, the new 81-test suite fails **32 tests**
and passes 49. One inventory test separately requires all 18 original facets to
match exactly and forbids their presence in the old difference manifest.

## Local verification

Linux .NET 8 and 10 each pass 12,741 core, 55 fixture-free consumer, 34 metadata-only
registration and four applicable companion tests; 14 Windows-only companion groups
skip. Both runtimes pass all five bounded invariant workers (2,822 iterations each).
The full six-project Release rebuild has zero errors and 14 existing xUnit2013
warnings. Both native baseline freshness verifiers pass all 80 observations.

## Remaining limits

This establishes the recorded contexts and structural error families, not every
condition token, validation-order combination or malformed layout. Additional
native-accepted conditional encodings remain outside the codec's lossless subset.
The frozen 25 initial, 243 directed and overlapping 623 expanded allocation gaps
remain unresolved. Broader selected DACL/SACL replacement combinations remain the
next operation-composition gap. Identity authority/topology, interop and live-server
limits remain in the [readiness inventory](issue-226-remaining-compatibility.md).

The preceding empty-callback correction deliberately sacrifices native formatting
parity for reconstructibility. No new parser defect was found in that matrix.
No preservation relaxation, live AD, transport/security change, merge or release
is part of this work.
