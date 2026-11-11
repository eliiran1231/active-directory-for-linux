# Narrow reviewed live scalar policy

Offline validation: all 43 synthetic checks passed, and the original differential
project compiled for net8.0-windows and net10.0-windows with no errors or warnings.
No live suite, directory operation, or credential access was performed.

`SuiteCapture` retains its default `redacted-scalars-v2` output format and detached
numeric site allowlist. The opt-in `reviewed-live-lab-scalars-v1` policy admits
already-evaluated null, boolean, integral primitive and enum values at existing
hooks. It adds no hooks and changes no original assertion overload or evaluation.
Existing finite exception identifiers remain admitted under both policies.
Strings outside that finite list, bytes, dates, GUIDs, floats, decimals, chars,
collections and arbitrary objects remain redacted. Enum conversions use runtime
Enum operations only, never custom IConvertible, ToString, fields or getters.

## Activation contract

The Windows wrapper must verify an operator-reviewed exact source-tree hash and
binary pins, obtain explicit isolated-lab/privacy acknowledgment, create private
local output, and write a bounded private review JSON document. Only then set:

- `ADFL_SUITE_CAPTURE_DIRECTORY`: private absolute existing output directory.
- `ADFL_SUITE_CAPTURE_MODE`: `reviewed-live-lab-scalars-v1`.
- `ADFL_SUITE_CAPTURE_REVIEW_FILE`: private absolute local review JSON file.

The review document has exactly five unique camel-case properties:
`schemaVersion` (1), `capturePolicy` (the mode above), `privacyScope`
(`isolated-lab-scalar-values-reviewed`), `sourceTreeSha256`, `assemblySha256`.
Both hashes are 64 lowercase hexadecimal digits. The collector checks the loaded
test assembly hash; the wrapper owns source-tree verification. The source hash
is an attestation, not collector proof that the assembly was built from those
sources. The token is not an authentication or security boundary. Neither a mode
flag alone nor an ambiguous default-mode review file is accepted.

The collector emits a separate `live-scalar-review` metadata event containing
policy/scope and hashes, never the token path. These events are not observations.
The Windows wrapper defines and pins the canonical source-tree hashing algorithm.
Private directories are required: numeric values and null/presence observations
can still reveal lab state. Review files are bounded to 4096 bytes, exact fields,
and non-reparse local paths. Filesystem path checks are not race-proof security
against an adversary who can mutate the local directory; operator-controlled ACLs
remain mandatory.

## Provenance and coverage limits

`explicit-microsoft-comparison` means the existing Comparison helper's Microsoft
parameter role, not independently proven library origin. Its Microsoft parameter
is ordinal 1, after the property label. Constants, locals and transformed values
must not be upgraded to Microsoft oracles. `assertion-operand-unverified` remains
unverified. A separate source/binding provenance ledger can strengthen particular
sites after review; neither this policy nor `replayable: true` automatically admits
any Linux oracle. That boolean describes only the scalar serialization shape.

Static lexical inspection found 1,430 `SuiteCapture.Expected(` occurrences across
125 top-level differential source files and two shared `SuiteCapture.Comparison(`
hook bodies. These are textual hook counts, not unique assertions, semantic
eligible sites, executed values, Microsoft-origin results, or runtime coverage.
Eligible runtime scalar count remains unknown until an authorized capture. Hooks
may execute zero, one or many times. CheckSet materializes sets in the original
helper; the collector does not enumerate them and records them as opaque.

Sink faults still propagate and can change original test outcomes; this collector
is **not failure-transparent**. Existing suite assertions and diagnostics can
contain sensitive data independently of this scalar stream. Keep all raw TRX,
console and capture output private. No full-suite or complete-value claim is made.

## Isolated validation (requires parent's notification first)

The package-free console project links the exact collector source with inert xUnit
and DirectoryServices stubs. It never calls Begin, test discovery, or a live test.
It checks primitive/redaction boundaries, throwing ToString/enumerator objects,
full-width enums, review rejection cases and pair-versus-assertion origin labels.
Only synthetic temporary files are created and removed. Build/run offline with
the available .NET 10 SDK, no package download. Pending validation is not a pass.
