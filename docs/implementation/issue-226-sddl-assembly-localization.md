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
The advertised capacity is always 65,532 bytes. No null ACL sizing call or oversized
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
Actual Windows results will be recorded after the push-triggered offline workflow.
