# Ordinary-sized mixed ACE and section operations

The 64-case follow-up uses eight fresh detached fixtures, each at most 2,048 UTF-16
code units: ordinary access/audit ACEs mixed with XA, XD, ZA object-only, ZA
inherited-only, ZA both-GUIDs, XU, four typed RA claims, or FL. Each fixture is
independently reconstructed for binary copy, owner/group export, access export,
audit export, all-section export, owner edit, group edit, and malformed selected
section edit. No preceding operation supplies the next operation's baseline.

Actual Windows .NET 8 and 10 probe head
`057876c053d186ac778ea265559a6626b4ed6afc`,
[run 38056717673](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/38056717673),
recorded all 64 observations on each runtime. Every observation agrees across
runtimes. The 56 successful operations and eight malformed-input failures include
exact source UTF-16, original raw bytes, initial native facade normalization,
result/exception fields, partial-export text and reparsed bytes, final observable
bytes/flags, and caller-buffer/raw-object preservation. The malformed cases fail
atomically natively; this matrix observed no native partial failed mutation.

The shared recorder clears native initialization dirty flags before each operation.
Portable replay starts from the raw-preserving detached constructor, without server
read context or authority. It never imports normalized native output as source data.
XU normalization changes audit ACE ordering; RA and FL normalization omits those
ACE types from the observable SACL. Those measured projection behaviors remain
distinct from stored raw bytes and operation results.

## Demonstrated gap and correction

Before the correction every public observation matched, but four exports violated
the existing preservation policy: RA Audit/All (51/52) and FL Audit/All (59/60).
The formatter's raw RA/FL refusal was bypassed because CommonSecurityDescriptor
had already hidden those stored ACEs from its observable projection.

For a selected Audit section, formatting now also checks the retained current raw
SACL for RA/FL and refuses with NotSupportedException. It does not substitute raw
serialization for observable serialization or reject ordinary known-ACE reordering.
Owner/group and access-only exports still succeed when the unselected SACL contains
these ACEs. Owner/group edits still preserve all unrelated raw bytes.

All 64 native rows remain in replay. Sixty compare exactly; only the Result facet
of the four individually pinned loss cases differs. The refusal manifest hashes
each complete native row, and the tests prove the omitted type is present in the
original raw SACL and absent from the native exported/reparsed SACL. All other
facets, including normalized before/after state, still compare exactly. No broad
fixture exclusion or permission to discard data was added.

Regression checks compare the entire raw descriptor after each operation. The 16
owner/group edits change only the selected same-length SID bytes and corresponding
intent/dirty flag. The other 48 operations preserve raw bytes, original bytes,
observable bytes, generation and pending/write intent. Every case retains source,
attachment, retrieval coverage and detached status. Original input buffers and raw
objects also remain unchanged. These checks reproduced four failing loss-refusal
assertions before the production correction.

## Local verification

Linux .NET 8 and 10 each pass 12,313 core, 55 fixture-free consumer, 34
metadata-only fixture-registration and four applicable companion tests; 14
Windows-only companion groups skip. The full six-project Release rebuild has
zero errors and 14 existing xUnit2013 warnings. Both runtimes pass all five
bounded invariant workers (2,822 iterations per runtime), including the deep
expression allocation checks. Publication and exact-head Windows evidence are
reported on PR 228; local success alone does not claim that workflow result.

## Evidence and remaining work

[Provenance](../research/acl-windows-oracle/results/sddl-mixed-provenance.json)
pins source head, jobs/artifacts and SHA-256 of each original JSONL file. The
`.jsonl.gz` files retain original Windows bytes including headers/newlines;
`.json.gz` files contain headers and all observation rows for replay/freshness.
Recordings were recovered from compressed Windows connector logs and checked
against emitted file hashes; artifact ZIPs were not downloaded.
[Comparison](../research/acl-windows-oracle/results/sddl-mixed-portable-comparison.json)
records the complete scope and individually pinned differences. The Windows
workflow freshly compares every field of all 64 rows.

The initial 25, directed 243 and overlapping expanded 623 native allocation gaps
remain frozen and unresolved. No cutoff, allocation formula or new size sweep was
introduced. These small inputs do not prove general SDDL compatibility, arbitrary
operation sequences or live AD behavior.

The next missing ObjectSecurity combination coverage is selected DACL/SACL
replacement on mixed payload descriptors, including valid selected edits beside
malformed unselected data and failures after a previously successful detached edit.
That work needs fresh native measurements and raw-section/atomicity assertions;
this matrix covers identity-section edits and malformed selected edits only.
The broader [readiness inventory](issue-226-remaining-compatibility.md), including
identity authority/topology, SDDL allocation and live-server gaps, remains open.
No credential, security, transport, public-surface or preservation policy changed.
