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
