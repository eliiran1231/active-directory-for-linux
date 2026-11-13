# Linux tests against recorded Microsoft results

`RecordedMicrosoft` executes real clone operations on Linux and compares them with values captured from the original Microsoft implementation in [run 43105205156](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/43105205156/job/130806631589).

This is a **partial port**, not a copy that silently skips or fakes the rest of the Windows suite. The current subset covers one complete metadata Fact and 149 partially adapted source methods, with 2,975 scalar observations per runtime, with 508 source-declared theory inputs compared as per-method multisets. Recorded theory-row identities remain unresolved. The original complete suite remains under `tests/windows`.

See [admission details and commands](RecordedMicrosoft/README.md). The Linux workflow is manual-only and does not contact AD.

The separate [historical source-linked pilot](../windows/differential-replay/README.md) passes 42 exact cases per runtime from run #202. It has a separate manual workflow job and is not included in the current-run observation count above.

`GroupPrincipalCultureTests.cs` is a separate clone regression linked into the functional test project. Four guarded offline cases verify that unsaved group flags survive changes between invariant, Persian and Arabic cultures. It is not recorded-Microsoft coverage. Run it through `tests/windows/run-offline-tests.py functional --framework net8.0 --class GroupPrincipalCultureTests` (or `net10.0`).

`ProtocolTimeCultureTests.cs` separately checks AD FILETIME and negative lockout-duration conversion under invariant, Persian and Arabic cultures, including boxed duration values and sentinel boundaries. Run it with the same guarded launcher using `--class ProtocolTimeCultureTests`. These are clone regressions, not added recorded-Microsoft observations.

The missing-property theory uses an explicitly reviewed two-of-three input subset (Contains/Count); PropertyNames is excluded. The ledger and runtime report show this scope, and no missing row is replaced with an empty expectation.
