using System.Text.Json;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Writes disposable accounts. Run only in a verified isolated differential lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityWorkstationConversionComparisonTests
{
    // Pinned reference: CommaStringToLdapConverter turns a serialized empty
    // string into null; CommaStringFromLdapConverter splits persisted commas.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs
    // Source blob: 605ace5c6eca9d0c1ac4f7477a8c8b70e6faf51f
    [Theory]
    [InlineData("clear")]
    [InlineData("one-empty")]
    [InlineData("two-empty")]
    [InlineData("embedded-comma")]
    public void Workstation_list_serialization_and_reload_match_microsoft(string scenario)
    {
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var parent = Open(DifferentialSettings.UsersContainer);
        var suffix = Guid.NewGuid().ToString("N")[..10];
        var names = new[] { $"ws-ms-{suffix}", $"ws-our-{suffix}" };
        var created = new List<MsDirectory.DirectoryEntry>();
        try
        {
            foreach (var name in names)
            {
                var entry = parent.Children.Add($"CN={name}", "user");
                created.Add(entry);
                entry.Properties["sAMAccountName"].Value = name;
                entry.Properties["userAccountControl"].Value = 0x202;
                entry.Properties["userWorkstations"].Value = "BASELINE";
                entry.CommitChanges();
            }
            using var expected = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, names[0]);
            using var actual = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.SamAccountName, names[1]);
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            Assert.Equal(new[] { "BASELINE" }, expected.PermittedWorkstations.ToArray());
            Assert.Equal(new[] { "BASELINE" }, actual.PermittedWorkstations.ToArray());
            expected.PermittedWorkstations.Clear();
            actual.PermittedWorkstations.Clear();
            var replacement = scenario switch
            {
                "clear" => Array.Empty<string>(),
                "one-empty" => new[] { "" },
                "two-empty" => new[] { "", "" },
                "embedded-comma" => new[] { "DESK01,DESK02" },
                _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
            };
            foreach (var value in replacement)
            {
                expected.PermittedWorkstations.Add(value);
                actual.PermittedWorkstations.Add(value);
            }
            var comparison = new Comparison($"PermittedWorkstations serialization: {scenario}");
            comparison.Check("pending values", JsonSerializer.Serialize(expected.PermittedWorkstations.ToArray()),
                JsonSerializer.Serialize(actual.PermittedWorkstations.ToArray()));
            var expectedError = Record.Exception(expected.Save);
            var actualError = Record.Exception(actual.Save);
            comparison.Check("Save exception", expectedError?.GetType().Name, actualError?.GetType().Name)
                .Check("Save parameter", (expectedError as ArgumentException)?.ParamName, (actualError as ArgumentException)?.ParamName);

            // A fresh low-level entry observes the wire result, including absent
            // versus empty attributes. Both reads use Microsoft so decoding
            // differences cannot hide a serialization discrepancy.
            comparison.Check("persisted attribute", ReadRaw(names[0]), ReadRaw(names[1]));
            using var expectedReload = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, names[0]);
            using var actualReload = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.SamAccountName, names[1]);
            Assert.NotNull(expectedReload);
            Assert.NotNull(actualReload);
            comparison.Check("fresh principal values", JsonSerializer.Serialize(expectedReload.PermittedWorkstations.ToArray()),
                JsonSerializer.Serialize(actualReload.PermittedWorkstations.ToArray()));
            comparison.Assert();
            if (scenario == "clear") Assert.Null(expectedError);
        }
        finally
        {
            // Try every cleanup even if one account deletion fails. If a commit
            // failed after server creation, lookup still finds that account.
            var cleanupErrors = new List<Exception>();
            foreach (var name in names)
            {
                try
                {
                    var dn = $"CN={name},{DifferentialSettings.UsersContainer}";
                    using var entry = Open(dn);
                    // Find through the authenticated context rather than using
                    // DirectoryEntry.Exists, which would use default credentials.
                    using var principal = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, name);
                    if (principal is not null) entry.DeleteTree();
                }
                catch (Exception error) { cleanupErrors.Add(error); }
            }
            foreach (var entry in created) entry.Dispose();
            if (cleanupErrors.Count > 0) throw new AggregateException("Disposable workstation accounts could not all be deleted.", cleanupErrors);
        }
    }

    private static string ReadRaw(string name)
    {
        using var entry = Open($"CN={name},{DifferentialSettings.UsersContainer}");
        return JsonSerializer.Serialize(entry.Properties["userWorkstations"].Cast<object?>().ToArray());
    }

    private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
