# Detached SDDL codec: measured slice and remaining work

`SddlCodec` supplies the portable descriptor string constructor and `GetSddlForm`. It is a managed parser/formatter; it never evaluates a condition, resolves an account name, calls native conversion, or writes to a directory. This is an implemented first SDDL slice, **not completion of the full required SDDL dependency**.

The syntax references are Microsoft's [descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format), [ACE strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings), and [SID strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings). Exact byte layout, accepted/rejected combinations, canonical output, and exception behavior come from the checked-in detached Windows recordings, not assumed compatibility with examples in those documents.

## Actual coverage

Before the access-filter follow-up below, the net8/net10 closure recordings each contained
1,681 SDDL observations (the historical accounting for that slice):

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

## Linear-time condition rendering

`SddlConditionCodec.Render` now emits nodes and punctuation through an explicit work stack
into one `StringBuilder`. It no longer constructs a complete string for every subtree;
rendering work and allocation grow linearly with the nodes and emitted text, including
skewed expression trees. Literal formatting and canonical parentheses remain unchanged.

The allocation regression measures warmed synchronous formatting at depths 512 and 2,048
for unary, left-skewed and right-skewed expressions, checks exact output and payload
roundtrips, and verifies the input bytes remain unchanged. It uses per-thread allocation
counts, not elapsed time. All three cases fail against the previous renderer: the fourfold
depth increase caused roughly 13–14 times the allocation on Linux .NET 10.

The complete-payload byte-identical reparse guard remains mandatory. No native recordings,
refusal inventory, raw/live state boundaries or preservation policy changed.

## Access Filter (FL) representation follow-up

Actual Windows probe runs [37999848527](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37999848527)
and [38000157544](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38000157544)
add **719 observations** (404 initial + 315 boundary rows), identical on .NET 8/10. Every
preceding 3,589 closure observation is unchanged. Total closure evidence is now **4,308**,
including **2,400 SDDL observations**. The [log-derived provenance](../research/acl-windows-oracle/results/log-derived-38000157544-provenance.json)
records exact probe heads/jobs and file hashes. Both probe-only heads passed the old 11,119
core and 321 companion tests per runtime; their expected failure was closure freshness
against the older baseline. No recording was fabricated or inferred from portable results.

The [documented FL/TP tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)
are implemented only as detached representation, not condition/access evaluation:

- FL belongs to the SACL. DACL text produces measured Win32 error 1804 before flag/trustee/
  condition validation; binary DACL FL formatting throws InvalidOperationException.
- Native text import creates ACL revision 2 and a type-21 CustomAce. Its payload is a
  little-endian 32-bit mask, a SID, then the same padded `artx` conditional encoding used
  by the existing callback codec. The exact bytes are replayed, including compound, member,
  attribute-only, octet, composite and integer-boundary expressions.
- Bits 0–23 of the mask are accepted, including the complete `0xffffff` mask; each bit 24–31
  and tested combinations containing them are rejected with ArgumentException(sddlForm).
  Generic-rights tokens therefore cannot be accepted merely because other ACEs accept them.
- Without TP, the trustee must be Everyone (`S-1-1-0`). TP uses flag bit 0x40 and requires
  authority 19 with exactly two subauthorities. First subauthority zero requires second zero;
  nonzero first values are not restricted to named trust levels (the probes include 1,
  512, 1024, 1536, 65535 and UINT_MAX). No trust decision is performed.
- OI/CI/NP/IO/ID and TP retain their bytes. SA, FA and CR are invalid FL flag tokens and
  report Win32 error 1004; SA must not become a spelling of TP despite sharing bit 0x40.
  Tested lowercase FL/TP and duplicate TP forms are accepted. GUID fields, missing/empty
  conditions, wrong trustees and malformed conditions retain measured rejection behavior.

**Ordinary native GetSddlForm(Audit/All) omits the entire FL ACE.** This also happens for
independently built malformed/unknown payloads, invalid mask/flag combinations and trailing
bytes. Mixed SACL output keeps audit ACEs while dropping the filter. It is not lossless
formatting, and this implementation deliberately refuses it with NotSupportedException.
Exports selecting only unrelated sections still succeed without changing stored bytes.
No alternative formatter or new public export mode is introduced.

The new rows account for 313 exact successful outcomes (including error-detail records),
288 exact native exceptions and **118 pinned preservation refusals** for native FL omission.
Each refusal fixes the complete row SHA-256, ID, inputs and native outcome; no generic
unknown-ACE allowlist hides mismatches. Existing 36 SDDL refusals remain unchanged: **154
SDDL refusals total**, of which 146 concern native information loss and eight host authority.
The closure totals are now 2,855 exact successes, 1,250 exact exceptions, 154 SDDL refusals,
eight facade preservation refusals and 41 atomic-failure differences.

Eight additional local preservation cases exercise exact condition payload reuse, section
selection, independent binary copies, and mutation of every condition byte plus truncated,
unknown and trailing payloads. CustomAce.GetOpaque retains its existing mutable-array contract;
copy isolation is tested between independently deserialized descriptors. Replaying the first
404 new native rows against the old codec produced 279 failures before implementation.

Limits remain explicit: this adds supported FL text-to-binary conversion, not a loss-bearing
text export, effective-access evaluator, live SACL persistence validation, or general FL
projection/mutation/companion conversion. The core continues to treat FL as opaque. Additional
unrecorded syntax, maximum-size/encoding combinations and conditional forms remain probe-driven
compatibility work; successful binary import never authorizes dropping their bytes.

Local verification for this FL implementation: full Release solution rebuild, zero errors and
14 existing xUnit2013 warnings. Linux .NET 8 and .NET 10 each pass 11,846 offline core tests,
55 offline consumer tests and 34 fixture-registration tests. Unfiltered companion runs pass
four Linux-applicable cases and skip 14 Windows-only groups each; local package checks pass.
Full unfiltered functional/differential suites remain outside this no-live-AD task because
their fixtures perform directory operations. Exact published-head Windows core/companion,
native freshness and artifact results are recorded on PR 228 after publication.
