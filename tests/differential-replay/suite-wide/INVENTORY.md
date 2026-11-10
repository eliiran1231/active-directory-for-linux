# Suite-wide source and replay inventory

`inventory.py` inventories the existing Windows differential project without
building or running C#, resolving directory settings, evaluating theory data,
provisioning fixtures, connecting to a directory, or importing the offline runner.
It is safe to run as a source-only check on Linux. Python standard library only.

From the repository root:

```sh
python tests/differential-replay/suite-wide/test_inventory.py
python tests/differential-replay/suite-wide/inventory.py --summary
python tests/differential-replay/suite-wide/inventory.py --output /tmp/differential-inventory.json
```

The full deterministic JSON is the deliverable for auditing individual sites. It
contains source file SHA-256 hashes, every recognized test's full name and line
range, its attributes/data declarations, each call site's source line and owning
test or helper, and each class's admission/replay classification. It emits no
source literal values or directory/test configuration. `--root` selects a different
checkout to inspect; it does not execute that checkout's code.

## What the numbers mean

The denominator is **source declarations and lexical call sites**, not runtime
cases or behavior coverage. Fact/Theory/OfflineFact/OfflineTheory declarations
are recognized with comments and string/character literals masked. Multiline
method declarations, qualified attributes, multiple attributes per block, nested
classes, primary constructors, expression bodies and the suite's partial classes
are handled. Unsupported recognized test declarations and duplicate identities
fail the inventory instead of silently disappearing.

- `source_test_declarations`: one per recognized method, not one per data row.
- `inline_data_declarations`: attributes written in source. Conditional branches,
  skips, discovery and execution can change how many cases actually run.
- `tests_with_dynamic_data`: MemberData/ClassData exists but is **not evaluated**.
  Reflection-derived fixture rows are not guessed from a textual search.
- `comparison_constructions`, `check_calls`, `check_set_calls` and
  `comparison_assert_calls`: named constructor/member invocation sites. These are
  lexical receiver matches, not C# type or control-flow analysis.
- `direct_assert_calls`: `Assert.*(...)`, including generic and qualified xUnit
  calls. These include prerequisites, reference checks, exception assertions,
  collection checks and helper assertions, not only Microsoft/clone comparisons.
- `suite_operand_wrapper_calls`: `SuiteCapture.Expected(...)` sites. A wrapper
  records an assertion operand with **unverified origin**. An expected/actual
  argument position is not proof the value came from Microsoft.
- `direct_assert_calls_with_wrapped_operands` and
  `direct_assert_calls_without_wrapped_operands`: direct assertion sites with or
  without a whole top-level operand wrapper. Every direct assertion is assigned
  to one of these counts. Each site lists the wrapped argument positions.
  `direct_assert_calls_first_two_operands_wrapped` is a narrower lexical count.
- `suite_comparison_recording_calls`: central `SuiteCapture.Comparison(...)`
  instrumentation sites. The explicit Microsoft/clone contract of `Comparison`
  differs from an arbitrary assertion operand, but a source site still does not
  prove an observation was recorded in a particular execution.
- `structured_recording_calls`: the existing `DifferentialRecording.Write` calls,
  reported independently of the new suite-wide instrumentation.

Test-body and helper/support counts are separate and sum to the all-source
counts. A helper can be reached from many rows, from no row, or before another
assertion fails. Helpers are **not attributed transitively**. Loops, branches,
failures and conditional compilation prevent treating call-site totals as
executed observation totals. Both `#if` branches are included. Literal contents,
including interpolation expressions, are excluded from lexical call-site counts.
Aliases and static imports may be missed. This is a bounded source lexer, not
Roslyn, xUnit discovery, MSBuild evaluation or a coverage engine.

Accordingly, `runtime_discovered_cases`, `executed_cases`,
`captured_observations`, and each method's `runtime_case_count` are always `null`.
Use separately validated run results and recording manifests to answer those
questions. An `end` capture marker alone is not evidence that a test passed or
that its data rows and all assertion sites were captured. A redacted value or
unverified assertion operand is not an admitted portable Microsoft expectation.

## Offline admission is independent from replay classification

The tool reads the literal `GROUPS["surface"]` and `EXTRA["surface"]` from
[`run-offline-tests.py`](../../run-offline-tests.py) using Python AST, without
executing that file. Admission matches exact namespace-qualified class names.
The current runner has seven default and three optional differential classes.
Changes to the runner are reflected automatically; missing allowlisted test
classes are an error. This inventory does not broaden that list.

Read [OFFLINE-TESTING.md](../../OFFLINE-TESTING.md) before running any C# tests.
The classes in the portable replay project are admitted by that **separate bounded
project**, not implicitly admitted to the guarded Windows surface runner.
A class name containing `Offline`, a `Detached` method name, an absence of fixture
references, or capture instrumentation is not permission to run it.

The replay classifications are deliberately conservative:

| Classification | Evidence and remaining work |
| --- | --- |
| `existing_linked_portable_pilot` | The test source files are explicitly linked by the current portable replay project. Its existing provenance, allowlist and runner checks still apply. |
| `detached_oracle_adapter_review_needed` | An exact class is in the Windows guarded offline allowlist, but not in the portable replay pilot. Review shared exercise code, dependencies and typed Microsoft observations before adding a Linux oracle adapter. Reflection/surface tests and native Windows operations do not become portable merely because they are detached from AD. |
| `controlled_transport_or_live_scenario_review_needed` | A non-allowlisted class references a known live fixture/settings/owned-object identifier. Review its scenario and dependencies; directory-backed behavior needs a controlled transport with explicit request/response and state semantics, or a separately authorized live run. |
| `unreviewed_windows_or_live_dependencies` | Neither reviewed admission nor a known direct dependency signal establishes requirements. Manually review helpers, native APIs, fixtures and transports. This does **not** mean the class is safe offline or definitely live. |

Live dependency signals are visible separately and are lexical evidence, not a
call graph. Guard-negative tests intentionally mention settings/fixtures without
using a directory. The exact offline allowlist takes precedence for admission.
Other classes can call a live helper without mentioning one of the known
identifiers directly, so absence of a signal is not absence of a dependency.

The existing four-class, 42-row-per-framework replay remains a small prototype.
Suite-wide capture can collect more observations on an appropriately authorized
Windows run; it does not convert all those tests into Linux replay. Persisted
state, authentication, permissions, writes, cache lifetimes, directory controls,
cleanup and multi-controller behavior require purpose-built shared scenarios and
controlled transports or live validation. Do not synthesize their expected state
from clone results or unprinted assertions.

## Scope and maintenance

The inventory includes SDK-default `.cs` sources under the differential project
(excluding `bin` and `obj`) and explicit linked `Compile Include` files, including
the shared offline attribute. It refuses wildcard, conditional, removed or
out-of-repository explicit source selections that need review. It does not
reimplement imported MSBuild rules or generated source discovery. A future build
configuration change requires reviewing this scope alongside its tests.

Do not commit generated inventories as evidence of Windows execution. Generate a
fresh inventory after instrumentation/source changes and retain its file hashes
with a reviewed capture package when measuring a particular build. Keep private
raw captures out of the repository. This tool cannot authorize or start a live
run, disable the offline guard, push changes, or turn assertion operands into
trusted Microsoft fixtures.
