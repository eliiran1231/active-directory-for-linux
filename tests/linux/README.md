# Linux tests against recorded Microsoft results

`RecordedMicrosoft` executes real clone operations on Linux and compares them with values captured from the original Microsoft implementation in [run 43105205156](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/43105205156/job/130806631589).

This is a **partial port**, not a copy that silently skips or fakes the rest of the Windows suite. Four parameterless Windows Facts currently contribute 79 scalar checks on each framework. The original complete suite remains under `tests/windows`.

See [admission details and commands](RecordedMicrosoft/README.md). The Linux workflow is manual-only and does not contact AD.
