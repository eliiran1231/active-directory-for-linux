using System.Runtime.ExceptionServices;
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
        var suffix = Guid.NewGuid().ToString("N");
        var names = new[] { $"ws-ms-{suffix}", $"ws-our-{suffix}" };
        var created = new List<MsDirectory.DirectoryEntry>();
        var attempted = new List<string>();
        Exception? primaryFailure = null;
        var cleanupErrors = new List<Exception>();
        try
        {
            foreach (var name in names)
            {
                CompatibilityOwnedDirectoryObjects.RequireAbsent($"CN={name},{DifferentialSettings.UsersContainer}");
                attempted.Add(name);
                var entry = parent.Children.Add($"CN={name}", "user");
                created.Add(entry);
                entry.Properties["sAMAccountName"].Value = name[..18];
                entry.Properties["userAccountControl"].Value = 0x202;
                entry.Properties["userWorkstations"].Value = "BASELINE";
                entry.CommitChanges();
            }
            using var expected = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.DistinguishedName, $"CN={names[0]},{DifferentialSettings.UsersContainer}");
            using var actual = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.DistinguishedName, $"CN={names[1]},{DifferentialSettings.UsersContainer}");
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            Assert.Equal(new[] { "BASELINE" }, expected.PermittedWorkstations.ToArray());
            Assert.Equal(new[] { "BASELINE" }, actual.PermittedWorkstations.ToArray());
            // Every row proves post-creation write access with a real change
            // before comparing potentially rejected values. Matching Save
            // failures must not hide a generally unwritable test account.
            expected.PermittedWorkstations.Clear();
            actual.PermittedWorkstations.Clear();
            expected.PermittedWorkstations.Add("CONTROL");
            actual.PermittedWorkstations.Add("CONTROL");
            Assert.Null(Record.Exception(expected.Save));
            Assert.Null(Record.Exception(actual.Save));
            Assert.Equal(JsonSerializer.Serialize(new[] { "CONTROL" }), ReadRaw(names[0]));
            Assert.Equal(JsonSerializer.Serialize(new[] { "CONTROL" }), ReadRaw(names[1]));

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
            using var expectedReload = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.DistinguishedName, $"CN={names[0]},{DifferentialSettings.UsersContainer}");
            using var actualReload = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.DistinguishedName, $"CN={names[1]},{DifferentialSettings.UsersContainer}");
            Assert.NotNull(expectedReload);
            Assert.NotNull(actualReload);
            comparison.Check("fresh principal values", JsonSerializer.Serialize(expectedReload.PermittedWorkstations.ToArray()),
                JsonSerializer.Serialize(actualReload.PermittedWorkstations.ToArray()));
            comparison.Assert();
            // Microsoft serializes both empty-list forms to null. For comma
            // cases retain the observed server outcome rather than prescribing
            // acceptance of empty/embedded workstation tokens.
            if (scenario is "clear" or "one-empty") Assert.Null(expectedError);
        }
        catch (Exception error)
        {
            primaryFailure = error;
        }
        finally
        {
            // Try every cleanup even if one account deletion fails. If a commit
            // failed before SAM was written, the exact-DN probe still finds it.
            foreach (var name in attempted)
            {
                try
                {
                    CleanupOwnedAccount($"CN={name},{DifferentialSettings.UsersContainer}");
                }
                catch (Exception error) { cleanupErrors.Add(error); }
            }
            foreach (var entry in created)
            {
                try { entry.Dispose(); }
                catch (Exception error) { cleanupErrors.Add(error); }
            }
        }
        if (cleanupErrors.Count > 0)
        {
            if (primaryFailure is not null) cleanupErrors.Insert(0, primaryFailure);
            throw new AggregateException("Account conversion test and/or cleanup failed; primary test failure is first when present.", cleanupErrors);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private static string ReadRaw(string name)
    {
        using var entry = Open($"CN={name},{DifferentialSettings.UsersContainer}");
        return JsonSerializer.Serialize(entry.Properties["userWorkstations"].Cast<object?>().ToArray());
    }

    private static void CleanupOwnedAccount(string distinguishedName)
    {
        // Probe the exact test-owned DN using configured credentials. SAM may
        // be absent after a partial creation; only no-such-object is ignorable.
        using var entry = Open(distinguishedName);
        try { entry.RefreshCache(new[] { "distinguishedName" }); }
        catch (System.Runtime.InteropServices.COMException error)
            when (error.HResult == unchecked((int)0x80072030))
        {
            return;
        }
        entry.DeleteTree();
    }

    private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
