# Local-only SDDL boundary investigation

Publication follow-up: the original local preparation below is retained as history.
`Run-SddlBoundary.ps1` now schedules all 220 cases in 14 isolated batches per runtime
from the push-triggered offline Windows workflow. Each batch has a 60-second timeout
and retains partial evidence; completed files must contain the exact case interval.
No new native outcomes are asserted until the resulting recordings are inspected.

Prepared after published implementation head `e7d7a43149b432577ede600674468bd9524e8c4f`
(tree `068b425d590265386d4d6568551889c70209e8a1`). That implementation and its prior FL
recordings remain unchanged. This follow-up contains proposed probes and local preservation
regressions, **not new Windows evidence or acceptance-rule changes**. It has not been published
or run in Windows CI. The existing closure baseline stays at 4,308 observations and 154 SDDL
preservation/authority refusals.

## Proposed native observations

`SddlBoundaryInputs.Create` defines 220 deterministic cases. Labels and zero-based case indices
are stable within this prepared revision:

| Cases | Count | Question to measure, not an expected result |
| --- | ---: | --- |
| ASCII conditional strings in FL/XA; resource TS names/values | 68 | Seventeen lengths from 0 through 65,536 UTF-16 units, with a directed band near the 16-bit ACE/ACL byte-size boundary. Which layer rejects, at which size, with which parameter/error? |
| Resource TU value counts | 8 | Counts 0, 1, 2, 255, 4,095, 4,096, 8,191 and 8,192; observe offset-table/payload/ACL limits independently of string length. |
| Unicode and NUL inside conditional strings/attributes and resource names/values | 66 | Composed/decomposed text, CJK, paired/lone/reversed surrogates, literal NUL, `%0000`, U+FFFF and BOM. Record bytes rather than assuming normalization, truncation or rejection. |
| Literal NUL around descriptor syntax | 9 | Prefix, valid-descriptor suffix plus garbage, and middle of an ACE field. Distinguish managed string length from native conversion termination. |
| Combined-invalid-input precedence | 69 | FL/XA/RA each have one valid control, six single faults, all 15 fault pairs, and all six faults. Faults cover wrong ACL context, flags, rights, GUID, trustee and condition/resource payload. Observe exception type, parameter and Win32 code without predicting order. |

The recorder calls only detached Microsoft `RawSecurityDescriptor` string/binary/SDDL APIs.
It performs no lookup, directory I/O, persistence, access evaluation, privilege changes or
credential handling. Large values are bounded by this explicit input list. It does not add
unbounded randomized input or invoke unsafe pointers.

## Opt-in recording and evidence integrity

`SddlBoundaryContracts` is a separate opt-in recorder. It does not append to the existing
closure recorder or change the ordinary offline workflow. On Windows only, an example batch is:

```powershell
dotnet run --project docs/research/acl-windows-oracle/AclWindowsOracle.csproj -c Release -f net8.0 -- --sddl-boundary-jsonl artifacts/boundary-net8-000.jsonl 0 8
```

Repeat with `net10.0` and the required numbered ranges only after the next authorized
publication/native run. Default start/count is 0/8; the maximum batch is 16. The last batch
is clipped to the 220-case manifest. A successful first batch is not evidence for all cases.
Use distinct output paths: files are created exclusively and existing recordings are not
overwritten. On Linux the existing top-level Windows guard exits without running the probes.
No workflow invocation or change is part of this local preparation.

Each JSONL file begins with a schema/runtime/OS/assembly header and its exact start/count/total.
Every case records its label, family, input UTF-16 code units in little-endian hexadecimal,
managed code-unit count, and separate parse and format results. Parse success retains complete
native binary bytes, length and control flags. Format success retains exact output UTF-16 units;
errors retain type, parameter and native Win32 code. Failed parse leaves format unattempted
(null), not a fabricated success. `BinaryUnchangedByFormat` records an actual comparison.

UTF-16 hex is deliberate: ordinary JSON or UTF-8 encoding can replace lone surrogates. Neither
`Encoding.Unicode` replacement fallbacks nor text logging may silently alter the input under
measurement. Rows are flushed individually to the file and emitted as `SDDL_BOUNDARY_JSONL=`
lines so a partial batch remains recoverable. Inspect the declared case interval and actual
row count before calling a batch complete; a native crash/timeout is an incomplete run.

The next authorized native pass must retain exact source head, both runtime jobs and complete
recording hashes. Compare runtime observations without blanket-normalizing exception details.
Only then decide which new rows are native parity, deliberate loss refusals, authority refusals
or unresolved mismatches. Do not copy a locally computed outcome into a Windows baseline.
Any production change requires that measured evidence plus preservation/atomicity regressions.

## Local assertions and limits

The new local tests check evidence encoding and the already approved preserve-or-refuse
contract. They do not assert native size thresholds, Unicode acceptance, literal-NUL behavior
or combined-error precedence from unrun probes:

- Exact UTF-16 transport and the 220-case unique-label/family inventory, including lone
  surrogates and NUL, survive JSON encoding without replacing input code units.
- Eight independently assembled conditional payloads contain valid Unicode, NUL, lone/reversed
  surrogates, odd byte length or an invalid declared length. If portable text export succeeds,
  reparsing must preserve the complete payload; otherwise it must explicitly refuse. Export
  and binary copies must leave original bytes unchanged. This is a local safety invariant.
- Eight arbitrary RA/FL payload cases, including 65,520 opaque bytes inside the binary ACL
  limit, retain exact binary storage after the existing lossy-format refusal. Independent
  input buffers and unrelated owner export must not alter that storage. Their acceptance as
  native SDDL is not asserted.
- Six already-recorded cases (2369, 2402, 2418, 2540, 3012, 3076) pin actual native Unicode and
  escaped-NUL import bytes across independent copies. Resource export still refuses the
  established native omission. No FL/resource NUL expectation is extrapolated from XA.

Production source, the existing native recordings and workflows are unchanged. The new
Windows recorder's outcomes and native execution safety at these boundaries remain unverified
until that explicitly deferred run. Existing live-AD exclusions and preservation policy remain.

## Local verification and changed files

Linux .NET 8/10 each pass **11,869 offline core tests**, including the 23 new local cases,
plus 55 fixture-free consumer and 34 fixture-registration cases. Unfiltered companion runs
each pass four Linux-applicable cases and skip 14 Windows-only groups. The full six-project
Release rebuild has zero errors and 14 existing xUnit2013 warnings. The separate oracle
project builds for both targets with zero errors/warnings. No new native probes ran. Full
unfiltered functional/differential execution remains excluded because its fixtures access AD.

Exact changed files in this local follow-up:

- `docs/research/acl-windows-oracle/SddlBoundaryInputs.cs`
- `docs/research/acl-windows-oracle/SddlBoundaryContracts.cs`
- `docs/research/acl-windows-oracle/Program.cs`
- `docs/research/acl-windows-oracle/README.md`
- `tests/AdForLinux.FunctionalTests/PortableSecurityFoundationTests.SddlBoundarySafety.cs`
- `tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj`
- `docs/implementation/issue-226-sddl-boundary-plan.md`

Logs and TRX files are retained under `/workspace/pr228-evidence/boundary-*`. A separate
local format-patch and checkpoint accompany the local commit. Before any later publication,
recheck the current PR head and use the authorized expected-head update route; the local
commit's parent has the same tree as the published FL head but different commit metadata.
Do not push the detached local history over the PR branch.
