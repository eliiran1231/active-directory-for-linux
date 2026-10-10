# Native SDDL assembly localization and fixed-total token experiment

The 25 initial, 243 directed and overlapping 623 expanded differences remain frozen.
Existing observations disprove a monotonic string/final-size threshold: at length 32702,
the large XA ACE is 65,444 bytes. Alone conversion fails with 87; one ordinary follower
succeeds with a 65,472-byte ACL; four followers fail with 1344 even though 65,532 bytes
fit a WORD-sized ACL. A 76-byte SID follower succeeds with a 65,528-byte ACL.

The research-only probe compares full SDDL conversion with caller-owned ACL assembly:
`InitializeAcl`, `AddConditionalAce`, and `AddAce` for surrounding ACEs. A separate fresh
buffer replays the exact large ACE extracted from an actually successful native sibling.
The eight witnesses are 32702 alone/one follower/one predecessor/four followers/long-SID
follower, 32690 with two followers, 32700 with two followers, and a short control.
The initial eight witnesses advertise 65,532 bytes; the six directed variants below advertise smaller bounded capacities. No null ACL sizing call or oversized
advertised ACL is used, and no ACL is applied to any object or token.

Every API result captures immediate last error before inspection. Conditional ReturnLength
is marked meaningful only on success or insufficient-buffer error. Before/after evidence
includes bounded bytes, headers, in-use/free accounting, canaries and native ACE equality.
Native descriptor copies check returned size against LocalSize and a 1 MiB read bound;
LocalFree and caller allocation cleanup run on managed exits. Each witness is process-
isolated with a 15-second limit and bounded managed heap. Failures retain partial evidence.

If direct compilation and replay succeed where full SDDL fails, that localizes the difference
to conversion/assembly behavior; compile failure with replay success points toward the
conditional API path/capacity. Neither establishes identical internal implementations or
a production formula. At most six capacity variants may follow a discriminating result,
including equal free space with different ACE counts. No guessed threshold, blanket error
mapping or alteration to existing recordings accompanies this initial probe.

API contracts: [AddConditionalAce](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addconditionalace),
[AddAce](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addace),
[GetAclInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getaclinformation).
## Actual initial results and next discriminating variants

At probe head `68bec3d8dc72fcb2c020df9b8d615078faf7332a`,
[run 38083120604](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38083120604)
recorded all eight witnesses on both runtimes. Every original JSONL file was recovered
from its gzip log record and verified against the Windows-emitted SHA-256. All 32 rows
per runtime match exactly apart from runtime/OS metadata, including entire buffer images.

| Witness | Full SDDL | Direct compile and replay final bytes in use |
| --- | --- | ---: |
| 32702 alone | error 87 | 65452 |
| 32702 + one follower | success | 65472 |
| one predecessor + 32702 | error 122 | 65472 |
| 32702 + four followers | error 1344 | 65532 |
| 32702 + long-SID follower | success | 65528 |
| 32690 + two followers | error 1344 | 65468 |
| 32700 + two followers | success | 65488 |
| short control + follower | success | 84 |

**Every direct compile and replay step succeeds**, with zero immediate last error.
Every compiled large ACE equals the exact sibling ACE, and every caller guard and source
ACE buffer remains intact. This localizes the discrepancy to full-descriptor conversion/
assembly behavior rather than intrinsic ACE validity or final representable capacity.
It does not establish Windows' internal allocation algorithm or shared implementation
between APIs, and introduces no production formula.

Exactly six further variants compare equal free space with different ACE counts at
length 32702: empty ACL capacities 65448/65452/65456 versus a 20-byte predecessor at
65468/65472/65476. These are four bytes below, exactly at and four bytes above the
measured fit, always within the WORD/DWORD bound. Each uses fresh compile/replay buffers;
no retry reuses a failed allocation. The result is not assumed in advance.


## Actual capacity-pair results and preserved evidence

At `c7125ad27e1809fa48a3c42ed77ed8de4550881d`,
[run 38083602105](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38083602105)
completed the six directed variants and repeated the original eight. All 56 rows agree
across runtimes apart from environment; the first eight case files are byte-identical to
the initial run. The committed `sddl-assembly-net{8,10}.0.jsonl.gz` recordings retain every
original JSONL byte. `sddl-assembly-provenance.json` records source head/run/job IDs and
both original-file and compressed-file hashes, verified against emitted Windows records.
Routine offline CI compares every field and buffer, excluding only runtime/OS metadata.

| Equal free bytes before large ACE | Empty / one-predecessor capacity | Compile and replay outcome |
| ---: | --- | --- |
| 65440 | 65448 / 65468 | Both fail with 122; complete pre/post buffers identical |
| 65444 | 65452 / 65472 | Both succeed with zero free bytes; exact native ACE |
| 65448 | 65456 / 65476 | Both succeed with four free bytes; exact native ACE |

On insufficient space, AddConditionalAce reports required ACL sizes 65452 and 65472,
respectively. Every guard and input ACE remains intact. These pairs show ordinary free-
space behavior independent of predecessor count for the direct APIs in this bounded band.
Whole SDDL conversion still fails for the equivalent alone/predecessor forms, strengthening
the localization to that conversion path's sizing/assembly behavior. They do not reveal
its temporary allocation plan, prove its internal API calls, or justify recreating errors
from a threshold. No production SDDL change or further probe expansion follows this result.
The 25/243/overlapping 623 portability gaps remain unresolved; a testable model of the
whole-converter allocation/order behavior is still required before implementing parity.

## One fixed-total token-partition experiment: unchanged outcomes

Six new inputs keep the XA token sequence and 32,703 total decoded UTF-16 units
fixed: attribute/literal splits (1,32702), (16351,16352), (32702,1), each alone and
with the existing 20-byte ordinary follower. Attribute text is `A` followed by
`x`; the literal contains only `x`. For each follower choice source length and
concatenated decoded characters stay identical across the three partitions.

Before interpreting whole-converter results, each case independently compiles
through AddConditionalAce at capacity 65,532 and checks the actual 65,444-byte
ACE, exact `artx`/attribute/string/equality token structure, four-byte length
fields, decoded bytes and padding. Failed controls are explicitly inconclusive.
The same guard, 15-second process and memory bounds apply; no ACL is installed.

Partition-dependent outcomes would disprove ordered final ACE sizes alone as
a sufficient model. Unchanged outcomes establish no formula and end this
experiment family. The first push records actual native evidence without changing any production
threshold or preservation policy.


At capture head `296c9baa31160f26e0b4ba6b673d275f4db13b47`,
[run 38089527663](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38089527663)
passed all four jobs. Each runtime recorded 24 rows. Every direct compile control
was established: exact 65,444-byte XA ACE, `artx` signature, attribute token 0xF9,
string token 0x10, equality 0x80, two four-byte length fields and three zero pad bytes.
The length-field values in bytes were (2,65404), (32702,32704), (65404,2).
All guards and source ACEs remained intact. Direct replay succeeded in all six cases.

| Attribute / literal UTF-16 units | Whole SDDL alone | Whole SDDL + 20-byte follower | Direct ACL bytes in use, alone / follower |
| --- | --- | --- | ---: |
| 1 / 32702 | error 87, returned size 0 | success, descriptor 65492 bytes | 65452 / 65472 |
| 16351 / 16352 | error 87, returned size 0 | success, descriptor 65492 bytes | 65452 / 65472 |
| 32702 / 1 | error 87, returned size 0 | success, descriptor 65492 bytes | 65452 / 65472 |

Successful native descriptors have LocalSize equal to returned size, successful
LocalFree and byte-identical compiled XA ACEs. Both runtimes agree on every field
and complete buffer apart from environment metadata. `sddl-partition-provenance.json`
records source head/run/jobs and Windows-emitted original-file SHA-256 values.
The two gzip recordings preserve the original JSONL bytes. Routine CI compares
all recorded fields and bytes except runtime/OS; a changed-error negative control
was rejected by the verifier.

**No partition-dependent outcome was observed. This produces no allocation formula
and closes this experiment family.** It neither establishes ordered final ACE sizes
as the cause nor rules out every per-token/intermediate-allocation implementation.
The original 25/243/overlapping-623 gap ledger remains frozen. There is no new sweep,
production threshold, error mapping, native ACL application or policy relaxation.

Portable checks compare all six compiled condition payloads byte-for-byte and verify
lossless formatting/reparse and unchanged source buffers. All three successful native
whole descriptors match portable string and binary construction exactly. For the three
alone cases, portable string construction succeeds with 65472-byte descriptors where
native conversion returns 87; tests explicitly pin those unresolved differences rather
than counting them as full converter parity. Seven cases (one exact inventory plus six
comparisons) cover this evidence without adding a production workaround.
