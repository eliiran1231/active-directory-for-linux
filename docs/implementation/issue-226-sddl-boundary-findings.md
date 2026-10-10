# Measured SDDL boundaries: encoding limits corrected, native allocation compatibility incomplete

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

These are 536 case definitions with overlapping inputs, each measured on both runtimes; repeated
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

The initial matrix after the UTF-16 and encoded-ACE length corrections contains:

| Classification | Cases |
| --- | ---: |
| Exact parse and format/exception outcomes | 131 |
| Existing RA/FL ACE-omission export policy | 58 |
| Literal-NUL import truncation refused | 6 |
| Unresolved size acceptance/exception mismatch | 25 |

The 64 preservation rows are individually identified and fingerprinted in
`SddlBoundaryPreservationRefusals.json`; they are not parity. Native omits complete
RA/FL ACEs during ordinary export and discards text following literal NUL during
import. Portable behavior retains the established refusal rather than adopting loss.
These counts describe this separate matrix, not additions to the old closure ledger.

The 25 unresolved size rows are explicitly listed and fingerprinted in
`SddlBoundaryKnownSizeGaps.json`. They are excluded from the parity replay count and
are **not** labeled preservation exceptions or passing compatibility cases. The
remaining 195 cases run as native replay/preservation tests; a separate inventory
test checks all 220 inputs and the gap/refusal manifests.

The 316-case follow-up has 47 exact complete outcomes, 26 existing RA/FL export
refusals and **243 unresolved parse mismatches**. Its 73 supported/preservation rows
now run as replay tests, with a separate inventory test. The 243 unresolved rows
remain explicitly fingerprinted and excluded from parity in
`SddlSizeReplayExceptions.json`; they are not labeled preservation refusals. The full native-versus-portable comparison is
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

## Encoded ACE size correction

The `AceSize` field is 16 bits. Before constructing a portable ACE, SDDL import now
checks the complete encoded length (header, actual SID, optional object fields and
payload). An unrepresentable length produces `ArgumentException("sddlForm")`, as
measured in the isolated native conversion, rather than leaking the public ACE
constructor's `ArgumentOutOfRangeException("opaque")`. Those public constructors and
their conservative opaque limits are unchanged. This is a representation bound, not
an inferred native ACL allocation cutoff. Representable large ACEs remain unresolved.

Actual replay on both runtimes corrects 21 initial and 31 directed observations.
The case sets overlap in inputs; these are 52 corrected observations, not 52 unique
inputs. All original native outcomes remain unchanged. The comparison report records
every remaining mismatch, including the six separately pinned literal-NUL refusals.

## Isolated Win32 layers

At `d071213c684a3fb022adf45402fe981149d9e9aa`, run `38051153699` recorded 656
cases per runtime in separate processes. Both runtimes had 146 native successes and
510 native failures: 274 error 122, 72 error 1344, 96 error 1336 and 68 error 87.
Every native success returned a buffer accepted by the managed binary constructor;
its outcome equaled the managed string constructor's outcome, and input bytes stayed
unchanged. All 656 complete native/managed observations agree across runtimes.

The probes capture native return, immediate last error, returned size, LocalSize,
exact bytes and guaranteed LocalFree on managed exits. They separately capture managed
binary construction and string construction. Each worker has a time limit and bounded
managed heap; a crashed/timed-out worker cannot consume the following cases. Successful
buffers are copied only after the returned length fits the allocation and a 1 MiB bound.

Native errors 87/1336 become managed ArgumentException(sddlForm), whereas 122/1344
remain Win32Exception with their exact code. Thus the sampled failure layer is native
conversion, not managed binary validation. Equivalent SID/right spellings, whitespace,
and owner/group prefixes did not affect the tested outcomes. Successful final buffers
have no unexplained ACL slack. The native temporary allocation algorithm is not known.

Run `38051919801`, head `962a9e75500d1b17d925d534b20e981954cc3656`, added 36
suffix cases: all 692 observations agree across runtimes (161 native successes;
287 error 122, 76 error 1344, 96 error 1336, 72 error 87). They refute a monotonic
maximum-size rule and the tentative arithmetic wrap formula: two ordinary followers
fail with 1344 at XA string length 32690, but succeed at 32700. A maximum-length SID
follower fails at 32700 but succeeds at 32702, producing a 65528-byte ACL. One ordinary
follower at 32704 fails with 87, while two or three succeed. At 32706 all six tested
suffix variants fail with 122. Run `38052425269`, head `9cb342e4f85c0dc348f32c587827bfb23b503e8d`, added 256
count/order/SID/object/callback cases. All 948 native/managed observations agree across
runtimes: 239 successes, 418 error 122, 110 error 1344, 96 error 1336 and 85 error 87.
Every success again passes managed binary construction without input mutation.
One ordinary follower fails at 32658 (122) but succeeds at 32674; two preceding ordinary
ACEs fail with 122 across all 16 tested lengths. Thus neither string length nor final
binary length alone accounts for native acceptance.

`results/sddl-native-layers-net{8,10}.0.jsonl.gz` preserves all original JSONL bytes,
including environment headers. `sddl-native-layers-provenance.json` records source head,
run/jobs and every original file hash verified against the compressed Windows log
record. The native-layer workflow streams and compares all exact input, native and
managed outcome fields, excluding only environment metadata from equality. LocalSize,
returned size, bytes, last error and LocalFree result are not normalized.

Actual portable execution of all 948 cases on both runtimes after the narrow size fix
has 325 exact parse outcomes and **623 unresolved parse differences**: 531 portable
acceptances/native rejections and 92 differing rejections. No measured native success
is rejected by portable import. These cases overlap the earlier matrices; do not add
623 to 25/243 or call these unique inputs. The complete comparison is
`results/sddl-native-layers-portable-comparison.json`. Native freshness is not portable
parity, and no general native allocation algorithm has been established.

The next correction requires explaining the non-monotonic allocation bands, including
why following-ACE count/layout changes the bands while equivalent spellings do not.
Additional rules must be demonstrated by exact native evidence before implementation;
there is no guessed capacity cutoff in production.

## Verification and limits

Linux .NET 8/10 each pass 12,139 offline core tests, 55 fixture-free consumer tests,
34 metadata-only fixture-registration tests, and four Linux-applicable companion
tests with 14 Windows-only groups skipped. The full six-project Release build has
zero errors; existing xUnit2013 warnings remain. The bounded invariant pass is rerun
on both runtimes: five worker tests, 2,822 case iterations each, without a reproduced
preservation or rollback failure. Full unfiltered functional/differential execution
remains excluded because those fixtures perform live directory operations.

Final exact-head Windows results are reported in the PR/checkpoint after publication.
The probe-head Windows runs already passed their then-current 11,869 core and 321
companion tests per runtime, full builds, package checks and old oracle freshness.
No merge, release, issue closure, live AD or security-policy change was performed.

## Bounded callback-size precedence follow-up

[The separate 108-case follow-up](issue-226-sddl-ace-size-precedence.md) confirms the
full-ACE size guard for XD/XU/ZA and corrects 16 ZA malformed-GUID error outcomes.
The 25/243/overlapping-623 allocation differences above remain open. The allocation
matrix is frozen pending a testable causal model; no additional cutoff was introduced.
