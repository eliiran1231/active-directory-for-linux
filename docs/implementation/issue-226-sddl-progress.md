# Detached SDDL codec: measured slice and remaining work

`SddlCodec` supplies the portable descriptor string constructor and `GetSddlForm`. It is a managed parser/formatter; it never evaluates a condition, resolves an account name, calls native conversion, or writes to a directory. This is an implemented first SDDL slice, **not completion of the full required SDDL dependency**.

The syntax references are Microsoft's [descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format), [ACE strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings), and [SID strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings). Exact byte layout, accepted/rejected combinations, canonical output, and exception behavior come from the checked-in detached Windows recordings, not assumed compatibility with examples in those documents.

## Actual coverage

The current net8/net10 closure recordings each contain 1,681 SDDL observations:

| Result | Cases |
|---|---:|
| Successful byte/text parity | 935 |
| Native rejection parity, including exception type and parameter | 693 |
| Native exception-detail parity, including measured Win32 error code | 17 |
| Explicit staged `NotSupportedException` instead of native success | 36 |

The implemented cases include owner/group and section selection; absent, empty and NULL ACLs; P/AR/AI flags; standard allow/deny and supported SACL audit forms; object GUID presence, including a present zero GUID; object ACL revision even when the parsed ACE collapses to a common ACE; numeric and symbolic rights; critical/inheritance flags; static SID aliases; and native whitespace, overflow and error behavior covered by the recordings. ACE order and duplicate ACEs are preserved during parsing. Label/policy ACE inputs can produce preserved binary descriptors even though exporting those ACEs remains explicitly refused.

These counts describe the recorded cases, not every possible SDDL string. In particular, the presence of an enum value or an ACE class is not evidence that native SDDL accepts that ACE in either ACL kind. The supplemental audit matrix establishes the accepted context and rejects unsupported alarm/context combinations. The public raw binary classes remain available for forms not expressible by this text codec.

## Exact deferred observations

| Case IDs | Native behavior | Portable staging behavior |
|---|---|---|
| 2635 | No-GUID ZA imports four extra opaque zero bytes; native XA text omits them | Preserves native binary import and refuses lossy export |
| 334 | Ordinary `GetSddlForm(All)` omits the resource attribute | Refuses information loss; resource parsing now matches native bytes |
| 336, 338, 340 | Omits mandatory-label, scoped-policy, and trust-label ACEs from ordinary SDDL export | Refuses that information loss; their binary parsing is implemented |
| 655–662 | Uses the Windows host's machine SID for LA/LG owner/group aliases | Refuses implicit host authority; records host-independent semantic observations instead of a machine SID expectation |
| 872, 873, 875, 876, 878, 879, 881, 882, 884, 885, 887, 888, 890, 891, 892–900 | Omits common ACE opaque bytes and/or non-audit ACE SA/FA flags during export | Refuses to discard them |

The last row has 23 cases. The test registry pins their complete binary arguments and section mask, rather than allowing arbitrary unsupported exports. All 36 rows also have exact case IDs and SHA-256 fingerprints of the complete normalized native observation, including its successful outcome. Each deferred test requires the portable implementation to throw `NotSupportedException`; it does not return a canned native value or skip comparison silently. A separate inventory test fixes the counts by reason. Every binary export replay checks descriptor bytes before and after, including a failed export.

These refusals are tracked incomplete compatibility, not an assertion that native behavior was reproduced or a new user policy choice. Full SDDL completion still needs unrecorded syntax/encoding boundary coverage, resource attribute export loss handling, an explicit authority mechanism for host-relative aliases, and a deliberate representation for exports that cannot carry all stored data. Conditions need a codec, not an authorization evaluator. Unknown and trailing payload bytes must remain preserved in the binary representation while this work continues.

## Conditional/resource and pointer follow-up

Runs [37831311746](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37831311746)
and [37832226853](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37832226853)
add 203 SDDL observations and 40 caller-owned SID pointer observations per runtime. Both
source-only probes passed the preceding 7,761 portable tests and failed only the expected
closure freshness comparison. The [log-derived provenance](../research/acl-windows-oracle/results/log-derived-37832226853-provenance.json)
pins the actual JSON source and checksums. Earlier rows remain unchanged. These are not
reconstructed outcomes or artifact ZIP downloads.

`SddlConditionCodec` encodes/decodes the `artx` postfix representation. The measured slice
covers local/user/resource/device attributes; percent-escaped names; quoted Unicode and
literal percent/backslash text; signed/unsigned decimal, octal and hexadecimal integers;
SID, octet and composite literals; relational, membership, existence and logical operators;
precedence and canonical parenthesization; callback allow/deny/object/audit contexts; and
native validation. Numeric sign/base bytes are retained. A text export is returned only if
reparsing it reproduces the entire payload exactly. Unknown opcodes, unexplained trailing
bytes and non-representable encodings remain preserved in binary and explicitly refuse
text export. Parsing/rendering use explicit stacks rather than an arbitrary nesting cutoff.
This is a codec, not an evaluator: native text conversion accepts some expressions whose
access-check semantics may be unknown, and those expressions are retained without judgment.

`SddlResourceCodec` builds relative claims for TI/TU/TS/TD/TB/TX, with native unaligned value
offsets, flags, multiple values, binary SID/octet length prefixes and DWORD tail padding.
The native mask/SID/audit-flag restrictions and measured integer overflow errors are replayed.
Resource export still refuses native omission. No existing raw binary data is reinterpreted
or dropped to obtain a text string. Native text normalization, such as an escaped NUL ending
an attribute name, occurs only while constructing new binary values from text.

The original **38 refusals are reduced to 35**: cases 331, 332 and 333 now have exact parity.
All 203 additional SDDL observations have native outcome/exception parity. The 35 remaining
recorded successes comprise 27 lossy native exports and eight authority-dependent aliases.
They cannot be counted as parity without resolving their existing preservation/authority
constraints. Unrecorded conditional encodings and access-filter forms still need directed
native probes; this slice does not establish every possible SDDL form.

## Review follow-up: precedence, name grammar and native ZA tail

Actual Windows runs [37840392546](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37840392546)
and [37840983666](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37840983666)
add 704 SDDL observations, leaving every preceding 2,564 closure row unchanged. The current
closure total is **3,268 per runtime**; the only runtime differences remain cases 2314/2317.
[Log-derived provenance](../research/acl-windows-oracle/results/log-derived-37840983666-provenance.json)
pins both source heads/jobs and file hashes. Both source-only probes passed the old 8,006
tests and full solution builds, then failed only expected closure freshness.

Negation now binds after relations and before AND/OR, matching
[MS-DTYP precedence](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d1a8392f-3f54-4fea-8233-44ede9eb198c).
Unparenthesized `!@User.Age == 1` produces the same native binary as `!(@User.Age == 1)`.
Contains, inequality, AND/OR controls and rejection of adjacent double negation are recorded.
The [documented hash-octet syntax](https://learn.microsoft.com/en-gb/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
now treats interior `#` as zero and pads an odd digit count exactly as native conversion does.

Separate lexical classes replace the permissive shared word tokenizer. Local names use the
measured legacy Latin-1 alphanumeric class plus colon, dot, slash, underscore and subsequent
`@`. All 128 high-byte characters and higher-Unicode controls are recorded. Prefixed names
accept their broader punctuation/Unicode class, including semicolon and comma; formatting
escapes comma and non-ASCII values. All 128 ASCII percent-escape values are measured: native
rejects needless escapes for directly representable characters while accepting required
escapes and its already-recorded escaped-NUL termination behavior. Resource-name parsing
is kept separate from this conditional-name validation.

No-GUID ZA is a newly measured **loss boundary**, not just an ACL revision fix. Case 2634
imports revision 4 and a common callback ACE with four additional opaque zero bytes. The
input descriptor is 80 bytes; native case 2635 emits XA text whose independently recorded
parse (case 2638) is 76 bytes/revision 2. Portable import preserves the complete native bytes.
Export refuses instead of dropping the tail or returning different unmeasured text. The
new refusal pins case 2635, its exact arguments and full native-outcome hash, and checks
that failed export and binary copy leave the descriptor unchanged.

Therefore **35 refusals remain from the original 38, plus one newly discovered refusal**:
**36 total (28 lossy native exports and eight host-authority aliases)**. This is not counted
as parity and does not weaken preservation. All other new observations have exact native
binary/text/exception parity. Full SDDL/identity/ObjectSecurity closure remains unfinished.
