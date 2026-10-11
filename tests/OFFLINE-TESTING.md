# Guarded offline tests

Use the reviewed runner for offline work:

```sh
python tests/test_offline_runner.py
python tests/run-offline-tests.py functional --framework net8.0
python tests/run-offline-tests.py functional --framework net10.0
python tests/run-offline-tests.py functional --framework net8.0 --class OfflineExecutionGuardTests
```

`surface` and `companion` select the existing Windows offline groups. The
`--dotnet` option selects an installed SDK executable. `--results-directory`
records TRX output; `--check-only` prints the bounded command without executing it.
Dependencies must already be restored. The runner always builds current sources,
so a stale unguarded assembly cannot be selected with `--no-build`.

The allowlist is in `run-offline-tests.py`. Only exact reviewed class names are
accepted, with a trailing class/method boundary in generated filters. Unknown
classes, prefixes, raw filter expressions and additional dotnet arguments refuse
before a process starts. Do not broaden the list just to make a live test run.
The existing audit Windows workflow uses this runner for its three test groups;
its triggers, native oracle work and publication policy are unchanged.

The runner sets `ADFL_OFFLINE_TESTS=1` only in the child environment. Any nonempty
value enables the guard; set it before process startup. Enablement is captured
once and cannot be switched off later in that process. No credentials, LDAP
options or operating-system network settings are changed.

In this mode:

- Production `LdapConnectionFactory.Create` refuses before constructing the
  native connection. Entry/context, identity and cross-context session binds
  therefore cannot reach the normal live LDAP transport.
- Functional `TestSettings` and differential `DifferentialSettings` reject live
  setting access before reading endpoint or credential values.
- `TestDataFixture` rejects at constructor entry before its provisioning/cleanup
  block. Negative tests invoke that actual constructor and the accidental
  `DirectoryEntryReadTests.Reads_a_string_property` body under the guard.
- Controlled fake sessions and request overrides remain usable. The full audit
  suite runs through those boundaries with offline mode enabled.

These are application safeguards, not a network sandbox. They cannot intercept
arbitrary third-party/native sockets or a malicious implementation passed as a
controlled transport. The exact allowlist and review of injected transports are
still required. A failure caused by this guard must not be worked around by
removing offline mode. Live execution requires separately scoped authorization.

The earlier aborted invocation had test-host startup output but no case results,
network trace or server audit. Connection/bind/read attempts and server-side
authentication effects remain unknown; no claim of zero server effects is made.
Its inspected test paths contain no application-issued LDAP modifications. The
original evidence is preserved separately and is not reused as validation.
