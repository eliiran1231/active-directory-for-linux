# Eight-witness native SDDL assembly localization

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
