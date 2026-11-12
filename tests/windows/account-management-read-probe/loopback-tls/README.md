# Isolated native SDK experiment

This is a separate loopback-only executable, not a backend substitution or an
activation path for the read probe. See [the runbook](../RUNBOOK.md) for commands,
prerequisites and the remaining live-read gates.

Cloud validation on 2026-11-09 completed 16 cases per runtime: .NET 8.0.33 and
.NET 10.0.14, each using System.DirectoryServices.Protocols assembly 9.0.0.0.
All 32 case assertions passed:

| Cases per runtime | Observation |
| --- | --- |
| Valid TLS before/after negative cases | One synthetic bind and one exact Base search each |
| Wrong SAN, CN-only, expired, untrusted CA | TLS reached; zero synthetic binds; failure at Bind |
| Isolated insecure control | Wrong-SAN synthetic server binds/searches when verification is deliberately disabled only in this test child |
| Bind referrals over LDAP/LDAPS URLs | One referral emitted, Bind operation exception, no search and no trap contact; exception has no response code |
| Search referrals over LDAP/LDAPS URLs | Referral recognized, no trap contact |
| Search references over LDAP/LDAPS URLs | Reference recognized, no trap contact |
| Stalled TLS, stalled search, partial BER | Each required independent six-second process termination; SDK two-second timeout did not stop it |

Both localhost address families are owned at each chosen port. Referral traps
are drained before zero-contact assertions. The fixture accepts only the fixed
synthetic bind and exact read request. Fresh CA/server keys live in a private
temporary directory and were removed on successful completion. Neither system
trust nor global LDAP configuration is modified. The optional private native
directory affects the synthetic child only.

The initial host library control failed before TCP: Protocols 9 requires
`libldap-2.5.so.0`, while the host provides the 2.6 soname. This requirement is
visible in the [pinned runtime source](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/Common/src/Interop/Linux/Interop.Libraries.cs).
The successful experiment used privately extracted Debian package
`libldap-2.5-0` version `2.5.13+dfsg-5`, amd64, without installation or ABI aliases.
Its SHA256 was verified through a signed Debian Bookworm Release and matching
Packages index:

```text
package: 4b6c30f6554149c594628d945edc6003f0eea8d0cc1341638c0e71375db147ed
libldap: 062bb940f27b45cdcac5d3d66a727f441755b17f59842641ceaebaf990e1634d
liblber: 64f183c14330855843841747ff1975ed87e767de2e2f1b1cc4d7abd2302cb7a9
```

The package checksum also appears on the [official Debian package page](https://packages.debian.org/bookworm/amd64/libldap-2.5-0/download).
Package provenance is evidence for this experiment, not a recommendation to
install an old package across distributions on a live runner. The valid fixture
certificate includes localhost and the current local hostname because
[OpenLDAP 2.5's GnuTLS hostname check](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_5_13/libraries/libldap/tls_g.c)
substitutes its local hostname for the literal localhost. No arbitrary target
host is accepted by the executable.

The experiment uses LDAPNOINIT=1 plus explicit process-local native TLS options.
It does **not** verify production environment-based TLS configuration, the
eventual machine, exact controller endpoint/port636, credentials, AD permissions,
the public facade against native LDAP, or Microsoft AccountManagement behavior.
The actual read probe's unconditional live gate remains false.
