# Detached SDDL codec: measured slice and remaining work

`SddlCodec` supplies the portable descriptor string constructor and `GetSddlForm`. It is a managed parser/formatter; it never evaluates a condition, resolves an account name, calls native conversion, or writes to a directory. This is an implemented first SDDL slice, **not completion of the full required SDDL dependency**.

The syntax references are Microsoft's [descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format), [ACE strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings), and [SID strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings). Exact byte layout, accepted/rejected combinations, canonical output, and exception behavior come from the checked-in detached Windows recordings, not assumed compatibility with examples in those documents.

## Actual coverage

The current net8/net10 closure recordings each contain 774 SDDL observations:

| Result | Cases |
|---|---:|
| Successful byte/text parity | 449 |
| Native rejection parity, including exception type and parameter | 279 |
| Native exception-detail parity, including measured Win32 error code | 8 |
| Explicit staged `NotSupportedException` instead of native success | 38 |

The implemented cases include owner/group and section selection; absent, empty and NULL ACLs; P/AR/AI flags; standard allow/deny and supported SACL audit forms; object GUID presence, including a present zero GUID; object ACL revision even when the parsed ACE collapses to a common ACE; numeric and symbolic rights; critical/inheritance flags; static SID aliases; and native whitespace, overflow and error behavior covered by the recordings. ACE order and duplicate ACEs are preserved during parsing. Label/policy ACE inputs can produce preserved binary descriptors even though exporting those ACEs remains explicitly refused.

These counts describe the recorded cases, not every possible SDDL string. In particular, the presence of an enum value or an ACE class is not evidence that native SDDL accepts that ACE in either ACL kind. The supplemental audit matrix establishes the accepted context and rejects unsupported alarm/context combinations. The public raw binary classes remain available for forms not expressible by this text codec.

## Exact deferred observations

| Case IDs | Native behavior | Portable staging behavior |
|---|---|---|
| 331–332 | Parses/formats a callback conditional expression | Refuses pending a proper conditional token codec |
| 333–334 | Parses a resource attribute; ordinary `GetSddlForm(All)` omits it | Refuses pending the resource attribute codec and loss handling |
| 336, 338, 340 | Omits mandatory-label, scoped-policy, and trust-label ACEs from ordinary SDDL export | Refuses that information loss; their binary parsing is implemented |
| 655–662 | Uses the Windows host's machine SID for LA/LG owner/group aliases | Refuses implicit host authority; records host-independent semantic observations instead of a machine SID expectation |
| 872, 873, 875, 876, 878, 879, 881, 882, 884, 885, 887, 888, 890, 891, 892–900 | Omits common ACE opaque bytes and/or non-audit ACE SA/FA flags during export | Refuses to discard them |

The last row has 23 cases. The test registry pins their complete binary arguments and section mask, rather than allowing arbitrary unsupported exports. All 38 rows also have exact case IDs and SHA-256 fingerprints of the complete normalized native observation, including its successful outcome. Each deferred test requires the portable implementation to throw `NotSupportedException`; it does not return a canned native value or skip comparison silently. A separate inventory test fixes the counts by reason. Every binary export replay checks descriptor bytes before and after, including a failed export.

These refusals are tracked incomplete compatibility, not an assertion that native behavior was reproduced or a new user policy choice. Full SDDL completion still needs conditional syntax/binary encoding and decoding, resource attribute encoding and decoding, an explicit authority mechanism for host-relative aliases, and a deliberate representation for exports that cannot carry all stored data. Conditions need a codec, not an authorization evaluator. Unknown and trailing payload bytes must remain preserved in the binary representation while this work continues.
