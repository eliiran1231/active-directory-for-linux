# Differential tests (run these on Windows)

These tests compare **the real Microsoft library** with **our Linux clone**.

They cannot run on Linux, because `System.DirectoryServices` and
`System.DirectoryServices.AccountManagement` only work on Windows. So this
project is **not** part of the Linux/Docker test run. You run it yourself on a
Windows machine.

> The project *compiles* on Linux (that is checked in CI-style by building it),
> but every Microsoft call throws `PlatformNotSupportedException` at runtime
> there. Windows is required to actually run it.

## What they do

Each test runs the *same* operation twice:

1. with Microsoft's library (aliased as `Ms` in the code)
2. with our library (aliased as `Ours`)

then compares the answers. Because the two libraries use different namespaces,
both can be referenced at the same time with no clash.

Differences are collected and reported together, so one failure shows you every
property that disagreed, not just the first.

### What is covered

| File | Compares |
| --- | --- |
| `UserPrincipalComparisonTests` | user properties, account state (dates, flags, lockout), `FindByIdentity`, `ValidateCredentials` |
| `GroupPrincipalComparisonTests` | group properties, `Members`, `GetGroups`, `GetAuthorizationGroups` |
| `DirectoryEntryComparisonTests` | `DirectoryEntry` properties, `DirectorySearcher` `FindOne`/`FindAll` |
| `PrincipalSearcherComparisonTests` | query-by-example search, including wildcards |

## How to run

1. Use a Windows machine that can reach a domain controller.
2. Set these environment variables (PowerShell):

   ```powershell
   $env:AD_HOST    = "your-dc.example.com"
   $env:AD_PORT    = "636"
   $env:AD_BIND_DN = "administrator@example.com"
   $env:AD_BIND_PW = "yourPassword"
   $env:AD_BASE_DN = "DC=example,DC=com"
   ```

3. Run:

   ```powershell
   dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows
   dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows
   ```

The tests create their own temporary user and two groups under `CN=Users`, and
delete them at the end.

## Things to know before you read a failure

- **The account running the tests needs rights** to create and delete objects in
  `CN=Users`, and to set a password.
- **`GetAuthorizationGroups` is not compared one-for-one.** Microsoft also
  returns computed groups (like *Domain Users* and well-known SIDs) that a plain
  LDAP query cannot see. So the test checks that our answer is a *subset* of
  Microsoft's, plus that the nested group is found by both. This is a known and
  accepted difference, not a bug.
- **Times.** We return `DateTime` values in UTC (`Kind = Utc`), which is what
  `DateTime.FromFileTimeUtc` gives, matching Microsoft's own conversion. The
  comparison compares the instant rather than the `Kind`, so a difference here
  means a real difference in the moment, not just the kind.
- **Self-signed certificates.** Against a test server with a self-signed
  certificate, Windows may refuse the TLS connection for *both* libraries. Use a
  DC with a trusted certificate, or install the test CA on the Windows machine.
