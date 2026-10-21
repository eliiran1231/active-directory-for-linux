# One-job Windows referral diagnostic

`Trust-Fixture.ps1` is an opt-in diagnostic helper, never part of ordinary PR CI.
It requires a disposable GitHub-hosted Windows runner, generates one loopback TEST
certificate valid for one hour, and temporarily adds only its public certificate
to that runner user's CurrentUser Root. Its private PFX stays in RUNNER_TEMP and is
used only by the loopback fixture. Neither private keys nor LDAP payloads belong in
artifacts.

The exact thumbprint is recorded before import. The helper removes and verifies
absence of that thumbprint in `finally`; the invoking job must also run
`Trust-Fixture.ps1 -Cleanup` in a separate `if: always()` step. If termination
interrupts cleanup, destruction of the disposable VM is the final isolation
boundary. Do not run this helper on a user machine, persistent runner, or domain.

The single approved job for this investigation is run
[39661592499](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39661592499),
at commit `31ae9c0538a061a71672e4994b3f87a37c66a4e0`, triggered by the unique tag
`diagnostic/windows-basic-trust-20261021-once`. The tag must not be recreated or the
job rerun. The one-off workflow was removed from the PR branch after launch.
Any additional trust job requires new authorization; retaining this helper does
not authorize it.

The job runs both runtimes sequentially with the same certificate. Normal
certificate validation and the pre-existing primary callback are separate controls.
IP/localhost and ldap/ldaps referral URL variants use TLS-only targets. A failure
under anonymous impersonation can reflect CurrentUser Root visibility and cannot
by itself prove credential substitution. Successful primary TLS does not establish
referred identity, reuse, StartTLS behavior, or failure eviction.

The ordinary native fixture also classifies a single peeked target socket byte
without consuming it or logging payloads, and reports final counters after endpoint
shutdown. A completed TCP connection with zero completed TLS handshakes is not
sufficient to identify certificate trust as the cause.

## Additional authorized stage diagnostic

A separately authorized, single additional job ran as
[39668854908](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39668854908)
at `0c2c8e2a6235410184a4cbf1ddab70292a12d84c`, using frozen tag
`diagnostic/windows-basic-trust-stages-20261021-once`. It ran on an isolated
diagnostic branch; PR #235 remained unchanged at `9a6382c`.

PowerShell parsing and both runtime builds passed before certificate setup.
The setup child completed generation, public certificate export, manifest writing,
PFX export, PFX writing and opening CurrentUser Root. Its last stage was
`import:start`, immediately before `X509Store.Add`. The parent terminated the child
after 60 seconds and reported exit 124. Import did not return, and trust verification
was not reached. A confirmation dialog remains a possible explanation; the logs
establish the stalled API stage, not the presence of a dialog.

The parent `finally` and the independent `always()` cleanup each found zero matches
and verified absence of exact thumbprint
`0B528147D1200B6161CE0673B30D2EFB0D125C68` from CurrentUser Root. Both also verified
the fixture PFX was absent. No .NET 8 or .NET 10 tests started because trust was
not verified. No LocalMachine trust changes or reruns were performed. The one-off
trigger workflow was removed from this branch after execution; the tag must not
be recreated. Any further trust diagnostic requires new authorization.

The helper now uses a 60-second setup child, bounded process-output draining,
and separate cleanup. If setup and default chain verification succeed in an
independently authorized future run, it runs net8.0 then net10.0 sequentially,
each with a 180-second process limit. The retained helper is not recurring CI.

## Authorized CryptUI no-UI diagnostic

A separately authorized single job used `CryptUIWizImport` with
`CRYPTUI_WIZ_NO_UI`, a public-only certificate context and an explicitly opened
CurrentUser Root store. [Run 39670664161](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/39670664161)
executed at `fbbfa0be67d60966c2e69b5087c7ed866a3653b5` using frozen tag
`diagnostic/windows-basic-trust-cryptui-20261021-once`. PR #235 stayed at `9a6382c`.

PowerShell parsing and both runtime builds passed. The setup child compiled the
interop helper, generated and exported the certificate, wrote the thumbprint and
PFX, and opened CurrentUser Root. `CryptUIWizImport` did not return: the last
stage was `import:start`, and the parent terminated the child after 60 seconds
(exit 124). Neither certificate-presence/default-chain verification nor the
.NET 8 and .NET 10 tests were reached. The logs establish the import-call stall;
they do not establish its underlying cause or Windows referral pooling safety.

The parent finally and separate `always()` cleanup each found zero matches and
verified exact thumbprint `DA79AA16962C3AAAFF41DA63B6BCBB8B81594D8D` absent from
CurrentUser Root. Both also verified deletion of the temporary fixture PFX.
No LocalMachine trust, registry or policy changes, or reruns were performed.
The one-off trigger was removed after this run. The tag must not be recreated;
the approval is consumed. Production Windows pooling eligibility remains unchanged.
