# NULL, absent and empty ACL replacement states

This follow-up contains 24 native scenarios and 48 portable partial-coverage cases.
It fixes a demonstrated raw-state bookkeeping defect without changing the native
observable outcomes, public surface, section-import guard or preservation policy.
The preceding 72-case replacement slice and its pinned refusals remain unchanged.

## Bounded native matrix

For each DACL/SACL target, all nine source/destination pairings of absent, NULL and
empty are tested: 18 cases. Source control flags are none for absent, P for NULL,
and AI|AR for empty. Supplied destination flags are AI for absent, AR for NULL,
and P|AI for empty. These choices expose assignable protection/auto-inherited
flags separately from non-assignable auto-inherit-request bits; they do not cover
every flag permutation.

The other six cases retain a valid callback in the opposite ACL, using native
Int8, Int16 or Int32 condition token codes 1, 2 and 3. The target begins with an
inherited CI ACE and is replaced by an empty protected/auto-inherited ACL. Native
raw export succeeds for each integer encoding and emits `(@USER.Level >= 2)`.
These are measured native-accepted conditions, not the older unknown-type-22
fixture. Portable export remains explicitly unsupported for these encodings.

Each fresh case runs seven operations: prior owner edit, byte-identical all-section
reassignment, selected binary replacement, protection with inheritance preserved,
unprotection, compound binary replacement and malformed compound SDDL. There are
168 steps. Two wrappers share the main descriptor, while another descriptor keeps
the original shared ACL objects. NULL SACL references remain explicitly nullable.

Actual Windows source `c6bf1a58bbf3acc17ee9a7d5d9a042d6b738f632`,
[run 38067374209](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38067374209),
records identical rows on .NET 8 and 10. Original JSONL, native headers, file hashes,
job IDs and artifact IDs are retained in the [provenance](../research/acl-windows-oracle/results/sddl-replacement-states-provenance.json).
Recovery used compressed connector logs with verified Windows SHA256 hashes;
artifact ZIPs were not downloaded. No recording was inferred from portable output.

## Results and deliberate differences

Eight complete portable rows match native exactly. Sixteen rows contain 530
individually pinned scalar differences. Full native row hashes and each native /
portable scalar value are checked. Every unpinned field compares exactly. Later
before/after differences carry an explicit earlier refusal step; they are not
whole-row exclusions or additional independent defects.

Native succeeds on 144 steps and rejects all 24 malformed-input steps. Portable
succeeds on 126, matches the 24 malformed-input rejections, and adds:

- Twelve `NotSupportedException` refusals for supplied AR bits: six identical
  reassignments from AI|AR empty sources, plus six AR-bearing NULL replacements.
  Native section setters do not assign these incoming bits. The existing complete
  input validation refuses them even for identical reassignment. No guard was
  bypassed to make these cases pass.
- Six `InvalidOperationException` refusals of compound replacement that would
  discard retained Int8/16/32 callback contents. Prior owner and selected-ACL intent
  survives. Ordinary selected replacement beside those untouched bytes succeeds.
- Separately from operation-step counts, six unsupported raw integer-condition
  exports. Native formatting success does not establish a lossless portable
  parser/formatter round trip for those encodings.

The [comparison](../research/acl-windows-oracle/results/sddl-replacement-states-comparison.json)
keeps complete row parity, deliberate differences and step counts distinct.

## Demonstrated correction

Before the fix, accepted identical reassignment of absent DACL input promotes the
retained raw present bit, despite unchanged native observable contents. Identical
NULL SACL reassignment transiently clears/reapplies its present bit, advancing the
raw generation and adding SACL intent even though the final raw bytes are unchanged.
The negative control fails 18 tests: six native replay scenarios and those six
scenarios under both partial-coverage choices. The other 127 focused tests pass.

The corrected setter still performs native live assignment, including replacing
ACL references and marking wrapper dirty flags. After existing validation, it
retains the original immutable engine, raw generation and section versions only
when the complete supplied image equals the retained image and the resulting
observable bytes differ at most in native NULL/absent present-bit normalization.
Newly assigned ACLs retain that original data provenance; untouched shared ACL
objects are not rewritten. Other live changes do not take this path. Raw state and
native observable presence remain separate. No incoming-data refusal is relaxed.

## State, coverage and rollback assertions

Both the prior 72-case matrix and the new matrix compare initial retained raw bytes
directly with the source fixture. Byte-identical reassignment must leave generation
unchanged, including successful NULL/absent cases and refused AR-bearing cases.

All operations verify original/raw/live bytes, unchanged unselected component
bytes and control bits, prior pending intent, dirty flags, source, attachment,
read version, coverage and descriptor/ACL identity. Failure restores mutation-engine
and retained-provenance references as well as bytes, intent and generation. Shared
wrappers stay coherent; separate aliases retain their original ACL references and
bytes. Supplied buffers remain unchanged. No descriptor gains identity authority.

The 48 partial-coverage cases replay each scenario twice using detached AD wrappers:
only the target ACL marked retrieved, then only the opposite ACL. Stored complete
bytes do not promote that metadata. Explicit setter intent outside retrieved
coverage remains in the snapshot. Coverage is a portable data contract, not an
invented native detached-wrapper field, server read, resolver or credential.
Destination assignment validation remains governed by existing coverage tests.

## Linux validation

Both .NET 8 and 10 pass 12,984 core tests, 55 fixture-free consumer tests,
34 metadata-only registration tests and four applicable companion tests (14
Windows-only companion groups skip). All five bounded invariant workers pass on
both runtimes, 2,822 iterations each. The full six-project Release rebuild has
zero errors and 14 existing xUnit2013 warnings. Native freshness verifies all 24
rows on each runtime. Exact-head Windows results are attached to PR228 after push.

## Limits

This slice does not establish every protection/inheritance combination, removal of
inherited entries through the protection API, aliased or irregular raw layouts,
partial server reads, all conditional integer values or canonical export of Int8/16/32.
The deliberately refused AR-bearing supplied inputs remain incompatible with native
acceptance. Broader identity authority, interop and live-server gaps remain in the
[readiness inventory](issue-226-remaining-compatibility.md).
The 25 initial / 243 directed / overlapping 623 expanded allocation gaps stay frozen
pending a causal model. No live AD, security-setting or credential change, public
contract expansion, merge or release is part of this work.
