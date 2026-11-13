# Test layout

- `windows/`: all pre-existing tests, fixtures, runners and recording tools, preserved together. This is the legacy suite location; it also retains existing portable/offline utilities rather than changing their behavior during the move.
- `linux/RecordedMicrosoft/`: clone-only Linux operation tests against source-verified recorded Microsoft observations. See its README for exact coverage and provenance.

The Linux suite currently covers 2,975 scalar observations from 150 distinct source methods per runtime (one complete metadata Fact and 149 partial adaptations), not all 1,398 executions in the Windows run. Missing theory identities and redacted observations are not inferred or counted as passing. The existing differential workflow still runs the original Windows suite. The separate Linux recorded-oracle workflow is manual-only and does not use AD credentials or contact AD.

The [method-level ledger](linux/RecordedMicrosoft/coverage-inventory.json) records 359 source declarations: one complete metadata Fact, 149 partial methods and 209 not mirrored.

The missing-property theory uses an explicitly reviewed two-of-three input subset (Contains/Count); PropertyNames is excluded. The ledger and runtime report show this scope, and no missing row is replaced with an empty expectation.
