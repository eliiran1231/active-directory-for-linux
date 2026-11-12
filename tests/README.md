# Test layout

- `windows/`: all pre-existing tests, fixtures, runners and recording tools, preserved together. This is the legacy suite location; it also retains existing portable/offline utilities rather than changing their behavior during the move.
- `linux/RecordedMicrosoft/`: clone-only Linux operation tests against source-verified recorded Microsoft observations. See its README for exact coverage and provenance.

The Linux suite currently covers 1,895 scalar observations from 44 distinct **partial** source methods per runtime, not all 1,398 executions in the Windows run. Missing theory identities and redacted observations are not inferred or counted as passing. The existing differential workflow still runs the original Windows suite. The separate Linux recorded-oracle workflow is manual-only and does not use AD credentials or contact AD.

The [method-level ledger](linux/RecordedMicrosoft/coverage-inventory.json) records 359 source declarations: 44 partial and 315 not mirrored, with no fully mirrored methods claimed.
