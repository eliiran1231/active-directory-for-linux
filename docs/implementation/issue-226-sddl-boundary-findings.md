# Measured SDDL boundaries: UTF-16 corrected, large-input compatibility incomplete

The prepared local commits `9654676a` and `43d441a` were published in cumulative
commit `4802c2fcfcb7d882c9f499090e32133015937ed5`, retaining their exact source
content. The publication also added isolated Windows probe batches. No production
change occurred in those probe commits.

## Actual evidence

Both runtimes completed the initial 220 cases in run `38048734645`. The artifact
transfer returned HTTP 403 from the workspace, and expanded job logs exceeded the
connector's usable transport. Commit `3564c743ad876364260183d8ffbeef46f24649db`
added compressed JSONL log records with SHA-256 of the original bytes, retaining full
artifact files. Run `38048966073` provided 14 verified batches per runtime. Every
decompressed file matched its Windows-emitted hash; all case intervals were complete.

The 220 native observations were identical on .NET 8 and .NET 10. The gzip baselines
`results/sddl-boundary-windows-net8.json.gz` and `...net10.json.gz` retain all rows,
original runtime/OS/assembly headers, source head, job IDs and per-file hashes.
The filenames refer to `docs/research/acl-windows-oracle/results`.

A directed follow-up recorded 260 size cases in run `38049289318` at
`62696bd1a4c70b9e033197243b002e3ca9e1531b`. Run `38049630692` at
`574255d449f5f9e4a12e8341a3f4c7e6ea3f46e3` retained those exact 260 rows and added
56 SID-length, attribute-length and neighboring-ACE cases. All 316 observations
again agreed across runtimes. `sddl-size-windows-net8.json.gz` and `...net10.json.gz`
retain this complete later matrix and its provenance.

These are 536 new distinct case definitions, each measured on both runtimes; repeated
runs are not additional coverage. They are separate from the unchanged 4,308 closure,
2,692 foundation and 1,845 mutation recordings. No outcome is locally fabricated.
The workflow now compares all 220 + 316 freshly recorded native rows with these
baselines, without normalizing exception type, parameter, code, input or binary bytes.
Native freshness is not a claim of portable parity.

## Implemented UTF-16 correction

Eighteen native rows preserve lone high/low and reversed surrogate code units in
conditional strings/attributes and resource names/values. Portable import previously
replaced these with U+FFFD through `Encoding.Unicode` fallback. `SddlUtf16` now reads
and writes little-endian UTF-16 code units explicitly. Conditional formatting also
retains these units; attribute escaping and the complete byte-reparse check remain.
Odd byte lengths still refuse. This restores all 18 import byte comparisons, including
six XA formatting comparisons. RA/FL formatting still refuses native ACE omission.

No evaluator, AD transport, resolver, authority, credential or persistence behavior
changes. Raw/write state remains separate from observable state and provenance.

## Preservation differences and unresolved compatibility

The initial matrix after the UTF-16 fix contains:

| Classification | Cases |
| --- | ---: |
| Exact parse and format/exception outcomes | 110 |
| Existing RA/FL ACE-omission export policy | 58 |
| Literal-NUL import truncation refused | 6 |
| Unresolved size acceptance/exception mismatch | 46 |

The 64 preservation rows are individually identified and fingerprinted in
`SddlBoundaryPreservationRefusals.json`; they are not parity. Native omits complete
RA/FL ACEs during ordinary export and discards text following literal NUL during
import. Portable behavior retains the established refusal rather than adopting loss.
These counts describe this separate matrix, not additions to the old closure ledger.

The 46 unresolved size rows are explicitly listed and fingerprinted in
`SddlBoundaryKnownSizeGaps.json`. They are excluded from the parity replay count and
are **not** labeled preservation exceptions or passing compatibility cases. The
remaining 174 cases run as native replay/preservation tests; a separate inventory
test checks all 220 inputs and the gap/refusal manifests.

The 316-case follow-up has 16 exact complete outcomes, 26 existing RA/FL export
refusals and **274 unresolved parse mismatches**. It remains research evidence,
not a passing portable replay suite. The full native-versus-portable comparison is
`results/sddl-boundary-portable-comparison.json`, including source-file hashes and
separate native/portable exception data or binary hashes. Both portable runtimes were
actually executed on all 536 inputs under bounded local process limits.

For the measured single WD condition, string lengths 32,690–32,701 succeed,
32,702–32,705 produce ArgumentException, 32,706–32,747 produce Win32 error 122 (XA)
or 1344 (FL), and 32,748 onward in the directed band produces ArgumentException.
These are measured examples, **not a general maximum**. SID length changes the
transition. At length 32,702, a small ordinary ACE following the large XA succeeds,
whereas putting that ACE first produces Win32 error 122; a single XA produces
ArgumentException. Hard-coding one string/payload cutoff would reject known native
successes or return the wrong failure. No speculative size rule is introduced.

Further work must isolate the native conversion/allocation behavior across these
contexts before implementing a general rule. The managed error mapping can be
inspected in the [.NET source](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/SecurityDescriptor.cs),
but it does not establish the underlying Windows allocation algorithm. Full SDDL
compatibility therefore remains incomplete; the next concrete gap is this size handling.

## Verification and limits

Linux .NET 8/10 each pass 12,044 offline core tests, 55 fixture-free consumer tests,
34 metadata-only fixture-registration tests, and four Linux-applicable companion
tests with 14 Windows-only groups skipped. The full six-project Release build has
zero errors and 14 existing xUnit2013 warnings. The bounded invariant pass is rerun
on both runtimes: five worker tests, 2,822 case iterations each, without a reproduced
preservation or rollback failure. Full unfiltered functional/differential execution
remains excluded because those fixtures perform live directory operations.

Final exact-head Windows results are reported in the PR/checkpoint after publication.
The probe-head Windows runs already passed their then-current 11,869 core and 321
companion tests per runtime, full builds, package checks and old oracle freshness.
No merge, release, issue closure, live AD or security-policy change was performed.
