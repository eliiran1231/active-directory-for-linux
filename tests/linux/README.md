# Linux tests against recorded Microsoft results

`RecordedMicrosoft` executes real clone operations on Linux and compares them with values captured from the original Microsoft implementation in [run 43105205156](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/43105205156/job/130806631589).

This is a **partial port**, not a copy that silently skips or fakes the rest of the Windows suite. The current subset covers 44 distinct partial source methods and 1,895 scalar observations per runtime, with 190 source-declared theory inputs compared as per-method multisets. Recorded theory-row identities remain unresolved. The original complete suite remains under `tests/windows`.

See [admission details and commands](RecordedMicrosoft/README.md). The Linux workflow is manual-only and does not contact AD.
