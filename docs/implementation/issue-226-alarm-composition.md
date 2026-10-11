# Alarm-family SDDL export/reparse composition

The prior raw-contract correction refused unaudited AL/OL exports, but audited
SystemAlarm still formatted as `S:(AL;SA;RP;;;WD)`. Closure parse case 937 already
records native rejection of that text; case 987 records the corresponding OL text.
The missing measurement was native binary alarm formatting composed with reparse.

## Actual native evidence

The bounded matrix records 96 detached observations: 48 fresh binary fixtures,
each with selected Audit and unselected Access export. It covers:

- Common/object alarm types 3/8 and callback alarm types 14/16.
- No audit flags, SA, FA and SA|FA, each with and without inherit-only.
- Object GUID layouts absent, object-only, inherited-only and both present.
- Empty and valid-condition callback-alarm controls.
- Reviewed inactive ordinary AU/OU controls, unaudited and audited.
- Standalone AL/OL binary inputs whose actual native output is exactly the
  previously recorded parse strings from 937/987.

Source `2be57688a776e62b92f4b32b65820ff2b5612363`,
[Windows run 38064066296](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38064066296),
records 96 identical native observations on .NET 8 and 10. Binary input, raw export,
direct CommonSecurityDescriptor export, detached AD facade export and native text
reparse are separate fields. No directory lookup, persistence or size sweep occurs.

Native raw AL/OL formatting succeeds in all 21 selected non-callback alarm cases,
but its own text reparse throws ArgumentException with `sddlForm`. This includes
all measured audit-flag combinations and the exact historical strings. Callback
alarm raw formatting throws InvalidOperationException in all 23 selected cases,
including valid condition payloads. Native facade projection omits every alarm
contributor. The four reviewed inactive audit controls remain valid; unselected
sections do not validate or discard alarm data.

This is **native non-roundtrippability, not a new native-format mismatch**. Before
the correction, the 17 audited AL/OL raw export facets matched complete native
format/reparse outcomes exactly. The correction deliberately sacrifices that
formatting parity to preserve reconstructibility. No new parser defect was found.

## Correction and exact refusal inventory

The existing raw alarm guard now refuses both audited and unaudited AL/OL exports
with NotSupportedException. It never changes the ACE into AU/OU, invents a condition
or removes flags. Wrong-section validation and callback-alarm errors are unchanged.
Every CommonSecurityDescriptor and detached AD outcome in the new matrix is
unchanged. The stricter retained-facade boundary and reviewed inactive ordinary
normalization predicate remain intact.

The matrix contains **52 complete portable matches and 44 pinned refusal rows**.
Its 109 differing facets are 21 raw non-roundtrippable AL/OL refusals and 88 existing
facade alarm-omission refusals. Seventeen raw facets are newly refused; the four
unaudited raw refusals already existed. Every unpinned field compares exactly.
Raw pins verify the native reparse error and portable rejection of the exact native
text. Facade pins prove the original alarm exists and is absent after native reparse.
Full native row hashes are pinned; there are no whole-row exclusions.

All 96 cases verify unchanged raw/original/live bytes, input buffers, generation,
dirty flags, pending intent, source, attachment and retrieval coverage. No resolver,
credentials, connection or read authority transfers. The new 97-test suite fails
**17 tests** and passes 80 with only this production correction disabled.

The previous 18 exception/raw-validation facets remain exact replay requirements.
The prior **80-row raw-contract matrix remains 55 complete portable matches plus
25 pinned refusal rows**, not 80 portable matches. The original 296-row retained
matrix remains 224 exact rows plus 72 pinned refusal rows. Neither native recording
nor existing refusal manifest is changed by this correction.

[Provenance](../research/acl-windows-oracle/results/sddl-alarm-provenance.json) pins
source, jobs/artifacts and original Windows file hashes. Original JSONL headers and
newlines are retained. Evidence was recovered from compressed connector logs and
verified against Windows-emitted hashes; artifact ZIPs were not downloaded.
[Comparison](../research/acl-windows-oracle/results/sddl-alarm-comparison.json)
separates native agreement, portable parity, existing refusals and the 17 new ones.

## Local verification

Linux .NET 8 and 10 each pass 12,838 core, 55 fixture-free consumer, 34 metadata-only
registration and four applicable companion tests; 14 Windows-only companion groups
skip. Both pass all five bounded invariant workers (2,822 iterations each). Full
six-project Release rebuild: zero errors and 14 existing xUnit2013 warnings. Both
native freshness verifiers pass all 96 alarm observations.

## Remaining limits

This covers the stated alarm flags/layouts and contexts, not every mask, SID,
unknown flag or arbitrary callback payload. Native raw callback-alarm text remains
unsupported; no callback alarm evaluator or invented SDDL token is introduced.
The frozen 25 initial, 243 directed and overlapping 623 expanded allocation gaps
remain unresolved. Broader selected ACL replacement combinations and the identity,
interop and live-server limits in the [readiness inventory](issue-226-remaining-compatibility.md)
remain open. No policy relaxation, live AD, merge or release is part of this work.
