# Selected ACL replacement and shared-alias transactions

This bounded follow-up adds evidence and regression tests. It demonstrates no
production defect: the existing replacement engine, raw/projection separation and
preservation policy remain unchanged. Non-identical replacement of unreviewed ACL
contents still refuses; byte-identical reassignment remains allowed. There is no
replacement fallback that normalizes away retained callback or opaque data.

## Matrix and actual native recording

The matrix contains 64 scenarios plus eight shared-alias cases, with 136 operation
steps. Each scenario starts from fresh bytes. DACL and SACL targets are each tested
beside ordinary, valid callback, malformed callback and unsupported opposite-ACL
data. The eight operations for each pairing are:

1. Selected binary replacement.
2. Selected SDDL replacement.
3. Byte-identical binary reassignment of all sections, including unreviewed data.
4. Prior owner edit followed by selected binary replacement.
5. Successful selected replacement followed by malformed compound text.
6. Malformed newly supplied unselected text and binary ACL input.
7. Prior owner edit followed by compound owner/group/DACL/SACL SDDL assignment.
8. Binary attempt to replace the opposite ACL with ordinary content.

The eight alias cases share the main descriptor with a second wrapper, and both
initial ACL objects with another descriptor. Each performs a prior owner edit,
byte-identical reassignment, selected binary replacement, an edit through the old
shared ACL and compound SDDL assignment. The old alias must remain coherent and
independent after the main descriptor replaces its selected ACL.

Source `e1762d3c4d81ad9ab2dc6d61cbcf44f6a6846865`,
[Windows run 38065846066](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38065846066),
records 72 identical native rows on .NET 8 and 10. The first probe at
`3584ffec3ceb2f1cc3196fa1515a79ca4217108b`,
[run 38065448333](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38065448333),
used binary compound assignments; the final matrix uses SDDL there so unreviewed
replacement is exercised through both entry points. The other 56 rows agree with
that independent initial probe.

Original input bytes, supplied binary/text, per-step before/result/after states,
wrapper dirty flags and reference identities are recorded separately. Native
observable bytes are never used as a substitute for portable retained raw state.
No directory lookup, persistence, credentials or security-setting changes occur.

## Results and preservation distinctions

**54 complete portable rows match native exactly.** The remaining **18 rows** are
deliberate atomic refusals of non-identical unreviewed ACL replacement. There are
182 individually pinned differing scalar fields across their result and after
states, including dependent descriptor images, flags and reference identities.
Each full native row hash is pinned. Every unpinned field compares exactly; no
operation or entire row is excluded.

Native succeeds on 112 operation steps and rejects 24 malformed new inputs.
Portable succeeds on 94, matches all 24 malformed-input rejections, and atomically
refuses the additional 18 unreviewed replacements. These refusals include text
compound assignments and binary opposite-ACL assignments. They preserve prior
owner/selected-ACL intent instead of adopting native replacement behavior.

Malformed newly supplied text or structurally malformed binary is parsed and
rejected even when its bad ACL is unselected. That is distinct from a malformed
callback payload already stored in an untouched ACL: supported selected edits
succeed and retain those bytes. Byte-identical reassignment also succeeds without
granting permission to replace unreviewed contents with different bytes.

The unsupported ACE can already be omitted from native observable state on import.
The preservation decision concerns original retained bytes, not a claim that every
native replacement newly discards a contributor still visible in its before state.
Valid and malformed callbacks, unknown ACEs and ordinary controls remain distinct.

## Portable state and alias assertions

Every operation boundary independently verifies raw/original/observable bytes,
prior pending intent, generation, dirty flags, retrieval coverage, source and
attachment. Successful operations change only permitted section components and
matching control bits; untouched raw ACL bytes and ACL references remain intact.
Supplied buffers are unchanged. No detached object gains a resolver, connection,
credentials or read authority.

Failed operations restore the exact descriptor, ACL, mutation-state and retained
provenance references, as well as bytes and flags. Compound failure rolls back
earlier staged owner/group/ACL work while retaining intent from prior successful
operations. The wrapper sharing the main descriptor sees coherent live bytes;
the separate descriptor retains its original shared ACL objects. Editing the old
selected ACL affects that alias without altering the replaced main descriptor.

The 73 focused tests pass with production code unchanged. Existing 18 raw-contract
fixes remain exact, and the prior 80-row matrix still has 55 complete matches plus
25 pinned refusal rows. The alarm/empty-callback reconstructibility refusals remain
deliberate formatting differences, not new native parser or formatter defects.

[Provenance](../research/acl-windows-oracle/results/sddl-replacement-provenance.json)
pins source, jobs/artifacts and original Windows file hashes. JSONL headers and
newlines are retained. Recovery used compressed connector logs and verified
Windows-emitted hashes; artifact ZIPs were not downloaded.
[Comparison](../research/acl-windows-oracle/results/sddl-replacement-comparison.json)
separates complete parity, deliberate refusals and operation-step counts.

## Local verification

Linux .NET 8 and 10 each pass 12,911 core, 55 fixture-free consumer, 34 metadata-only
registration and four applicable companion tests; 14 Windows-only companion groups
skip. Both pass all five bounded invariant workers (2,822 iterations each). Full
six-project Release rebuild: zero errors and 14 existing xUnit2013 warnings. Both
native freshness verifiers pass all 72 replacement observations.

## Remaining limits

This matrix does not establish replacement behavior for NULL/absent ACLs, every
protection/inheritance control transition, partial retrieval coverage, irregular
raw layouts or every alias topology. Those remain directed follow-up families,
not permission to relax refusal boundaries. The frozen 25 initial, 243 directed
and overlapping 623 expanded allocation gaps remain unresolved. Identity authority,
interop and live-server limits remain in the [readiness inventory](issue-226-remaining-compatibility.md).
No live AD, merge or release is part of this work.
