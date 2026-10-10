# Empty callback export/reparse composition

Closure case 857 already correctly recorded native formatting of an empty callback
allow ACE as `D:(XA;;RP;;;WD)`. Cases 858 and 859 similarly recorded XD and ZA.
Portable formatting matched these strings. This follow-up does **not** identify a
new native formatting mismatch: it measures what happens when the returned text
is parsed again.

## Actual observations

The 48-row detached matrix covers all eight binary callback ACE types 9–16 in
their access or audit context, four GUID-presence layouts for type 11, selected,
unselected and All exports, and valid nonempty-condition controls for XA/XD/ZA/XU.
The final three rows use the literal binary inputs and All selection from closure
857–859. RawSecurityDescriptor, direct CommonSecurityDescriptor and detached
ActiveDirectorySecurity formatting/reparse outcomes and before/after bytes are
recorded separately. Every operation starts from a fresh source.

Source head `7465fda346bdb1dd577f1b05a5905c6872dd99e4`,
[Windows run 38061071192](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38061071192),
actually recorded all 48 rows on .NET 8 and 10. Every observation agrees across
runtimes. The first 45 also agree with the earlier probe at
`66a6ea48a14b1a5f3c5ecf9bc641b45f00631b7b`.

Native formatting succeeds for the supported empty XA/XD/ZA/XU layouts, but native
reparse throws ArgumentException with `sddlForm` for the missing condition.
This includes the exact text from each of closure 857, 858 and 859. Portable
parsing already rejects the same text with the same exception/parameter. **No
parser acceptance gap was observed in this matrix.** Unsupported empty callback
families retain their measured native formatting errors. Native facade projection
also omits alarm callback types 14/16; the existing retained-data guard already
refuses that omission.

## Preservation correction

The approved export policy does not permit inventing a condition or changing an
empty callback ACE into an ordinary allow/deny/audit ACE. Because the native text
cannot reconstruct the callback, selected export now refuses an empty qualified
callback with NotSupportedException. The shared ACE formatter applies the check
to raw and facade exports. Parser acceptance, condition rendering, ACE type and
binary storage do not change. Unselected sections and valid conditions continue
to export and reparse successfully.

Before the correction, 44 complete rows matched native, including non-reparsable
outputs; four differed because of the existing alarm-omission guard. After the
intentional preservation correction, **27 complete rows match and 21 rows have
59 individually pinned export-facet differences**: 51 non-roundtrippable empty
callback refusals and eight existing alarm-omission refusal facets. These are
facets, not unique input counts. Every other native field still compares exactly.
No row is broadly skipped.

The three original closure formatting observations remain unchanged. Their full
row hashes are pinned as new explicit composition-policy differences, taking that
closure inventory from 154 to 157 refusals. Tests verify their literal source bytes
and successful native formatting against the new exact reparse measurements.
This is a deliberate loss of formatting parity to preserve reconstructibility,
not evidence that the old formatter failed to match native text.

The regression negative control failed 17 of 48 cases before the correction.
Tests require unchanged raw/original/observable bytes, caller buffers, callback
identity, opaque length, generation, dirty flags, pending/write intent, source,
attachment and retrieval coverage on refusal. Detached objects acquire no server
read context or authority. The new inventory test checks every source, section
selection, native row and pinned facet, including all three historical cases.

[Provenance](../research/acl-windows-oracle/results/sddl-composition-provenance.json)
pins source head, jobs/artifacts and every original JSONL file hash. Original
Windows headers/newlines are retained in `.jsonl.gz`; the `.json.gz` replay files
retain all headers and observations. Recovery used compressed connector logs and
verified Windows-emitted hashes; artifact ZIPs were not downloaded.
[Comparison counts](../research/acl-windows-oracle/results/sddl-composition-comparison.json)
separate successful formatting from successful composition. The workflow freshly
compares all 48 native rows without altering the older baselines.

## Local verification

Linux .NET 8 and 10 each pass 12,660 core, 55 fixture-free consumer, 34
metadata-only registration and four applicable companion tests; 14 Windows-only
companion groups skip. Both pass all five bounded invariant workers (2,822
iterations each). The existing unary/left/right deep-expression allocation
regressions pass unchanged. Full six-project Release rebuild: zero errors and
14 existing xUnit2013 warnings.

## Remaining limits

The prior **12 unsupported-condition exception-type facets and six raw
unaudited-ACE validation facets were genuine compatibility gaps**, not loss
evidence. The subsequent [raw contract follow-up](issue-226-raw-formatting-contract.md)
closes all 18 with exact replay; this composition measurement itself did not. The frozen 25
initial, 243 directed and overlapping 623 expanded allocation gaps also remain.

This measures exact native-produced text in the listed contexts, not every empty
condition-field spelling or arbitrary parser context. Broader selected DACL/SACL
replacement combinations remain the next operation-composition gap; the identity,
interop and live-server boundaries in the [readiness inventory](issue-226-remaining-compatibility.md)
remain open. No live AD, merge, policy relaxation, security/transport change or
effective-access evaluator is part of this correction.
