# AdForLinux — Active Directory for Linux

A Linux copy of Microsoft's directory APIs, built on the cross-platform
`System.DirectoryServices.Protocols`. It lets .NET code that used
`System.DirectoryServices` and `System.DirectoryServices.AccountManagement`
run on Linux against Active Directory.

Same shape as Microsoft, new name (so it does not clash with the real DLL on
Windows).

## Layers

| Our namespace | Copies |
| --- | --- |
| `AdForLinux.DirectoryServices` | `System.DirectoryServices` (`DirectoryEntry`, `DirectorySearcher`) |
| `AdForLinux.DirectoryServices.AccountManagement` | `System.DirectoryServices.AccountManagement` (`PrincipalContext`, `UserPrincipal`, `GroupPrincipal`, `PrincipalSearcher`) |

## Targets

`net8.0` and `net10.0`.

## Auth

Simple bind (username + password) over LDAPS / StartTLS. A self-signed
certificate can be trusted for tests. No Kerberos yet.

## Testing

Two test projects:

- **`tests/AdForLinux.FunctionalTests`** — runs on Linux in Docker against the
  `smblds` Samba AD DC. Checks our clone works.
- **`tests/AdForLinux.DifferentialTests`** — runs on **Windows**. Compares the
  real Microsoft library with our clone, side by side. See its README.

### Run the Linux tests

The `smblds` container must be running (LDAPS on host port 636). Then:

```bash
docker compose up --build --abort-on-container-exit
```

This builds an image with both .NET 8 and .NET 10 and runs the functional
tests on each.
