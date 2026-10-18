# 1. Connect and read a user

[README](../README.md) → Connect → [Migrate](migration.md) → [Identities and permissions](identity-resolution.md)

## Build and reference the library

The source targets .NET 8 and .NET 10. Install the .NET 10 SDK to build the full
solution; install the .NET 8 runtime too if you run its tests.

```sh
git clone https://github.com/eliiran1231/active-directory-for-linux.git
cd active-directory-for-linux
dotnet build AdForLinux.sln --configuration Release
```

Reference the high-level project from your application. This also brings in the
low-level directory API. For example, with `MyApp` beside the checkout:

```sh
dotnet add ../MyApp/MyApp.csproj reference src/AdForLinux.DirectoryServices.AccountManagement/AdForLinux.DirectoryServices.AccountManagement.csproj
```

For an application that only uses `DirectoryEntry` and `DirectorySearcher`,
reference `src/AdForLinux.DirectoryServices/AdForLinux.DirectoryServices.csproj` instead.
These instructions use a source checkout; they do not assume a published v1 package.

## Prepare the connection

Use an explicit domain-controller DNS name, reachable LDAPS port 636, and an
account permitted to read your target container. On Linux, the runtime also needs
the distribution's native OpenLDAP client libraries.

Trust the issuing certificate authority in the environment used by OpenLDAP, and
connect using a name covered by the certificate. Disabling certificate verification
is not a substitute for installing that trust.

Supply `AD_HOST`, `AD_BASE_DN`, `AD_BIND_DN`, and `AD_BIND_PW` through your deployment's
configuration/secret mechanism. For example, the base DN might be
`OU=People,DC=example,DC=com`, and the bind identity `reader@example.com`.
Do not commit passwords or put them in command-line arguments.

## Read one existing account

```csharp
using AdForLinux.DirectoryServices.AccountManagement;

static string Required(string name) =>
    Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException($"Missing {name}");

using var context = new PrincipalContext(
    ContextType.Domain,
    Required("AD_HOST"),
    Required("AD_BASE_DN"),
    ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer,
    Required("AD_BIND_DN"),
    Required("AD_BIND_PW"));

using var user = UserPrincipal.FindByIdentity(
    context, IdentityType.SamAccountName, "alice");

Console.WriteLine(user is null ? "Account not found" : user.DisplayName);
```

This example only reads. A successful read does not establish write permissions.
If connection fails, check DNS, port reachability, certificate trust, credentials,
and the container DN before changing authentication options.

Next: [migrate your application](migration.md), including writes and searches.
