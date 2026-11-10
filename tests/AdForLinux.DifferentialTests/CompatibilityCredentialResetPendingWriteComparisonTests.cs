using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates two uniquely owned disabled users, edits only their descriptions,
// and deletes those exact leaf objects. Authorized disposable AD lab only.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityCredentialResetPendingWriteComparisonTests
{
    private const string SeedDescription = "credential-reset baseline";
    private const string EditedDescription = "credential-reset pending edit";

    // Microsoft's Password setter Unbinds; CommitChanges returns when unbound.
    // The clone's ResetCredentialBinding retains pending property changes for
    // later commit. Existing persisted objects isolate this from new-child state.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Pending_existing_entry_write_after_password_reset_matches_microsoft(bool bouncePassword)
    {
        var expectedOwned = new OwnedUser("ms");
        var actualOwned = new OwnedUser("our");
        var attempted = new List<OwnedUser>();
        Exception? primaryFailure = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            foreach (var owned in new[] { expectedOwned, actualOwned })
            {
                CompatibilityOwnedDirectoryObjects.RequireAbsent(owned.Dn);
                attempted.Add(owned);
                Seed(owned);
                Assert.Equal(SuiteCapture.Expected(SeedDescription, "assert-equal-expected", 39), SuiteCapture.Expected(ReadPersistedDescription(owned), "assert-equal-actual", 39));
            }

            // Seed wrappers are already disposed. These are ordinary existing
            // entries, never DirectoryEntries.Add objects with JustCreated state.
            using var expected = MicrosoftEntry(expectedOwned.Dn);
            using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(actualOwned.Dn),
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
            Assert.True(expected.UsePropertyCache);
            Assert.True(actual.UsePropertyCache);
            RequireOwned(expected, expectedOwned);
            Assert.Equal(SuiteCapture.Expected(actualOwned.Guid, "assert-equal-expected", 50), SuiteCapture.Expected(actual.Guid, "assert-equal-actual", 50));
            Assert.Equal(SuiteCapture.Expected(actualOwned.Dn, "assert-equal-expected", 51), SuiteCapture.Expected(Assert.IsType<string>(actual.Properties["distinguishedName"].Value), "assert-equal-actual", 51), ignoreCase: true);
            Assert.Equal(SuiteCapture.Expected(actualOwned.Sam, "assert-equal-expected", 52), SuiteCapture.Expected(Assert.IsType<string>(actual.Properties["sAMAccountName"].Value), "assert-equal-actual", 52));
            Assert.Equal(SuiteCapture.Expected(actualOwned.Marker, "assert-equal-expected", 53), SuiteCapture.Expected(Assert.IsType<string>(actual.Properties["telephoneNumber"].Value), "assert-equal-actual", 53));
            var leftDescription = expected.Properties["description"];
            var rightDescription = actual.Properties["description"];
            Assert.Equal(SuiteCapture.Expected(SeedDescription, "assert-equal-expected", 56), SuiteCapture.Expected(Assert.IsType<string>(Assert.Single(leftDescription.Cast<object>())), "assert-equal-actual", 56));
            Assert.Equal(SuiteCapture.Expected(SeedDescription, "assert-equal-expected", 57), SuiteCapture.Expected(Assert.IsType<string>(Assert.Single(rightDescription.Cast<object>())), "assert-equal-actual", 57));
            leftDescription.Value = EditedDescription;
            rightDescription.Value = EditedDescription;
            Assert.Equal(SuiteCapture.Expected(EditedDescription, "assert-equal-expected", 60), SuiteCapture.Expected(leftDescription.Value, "assert-equal-actual", 60));
            Assert.Equal(SuiteCapture.Expected(EditedDescription, "assert-equal-expected", 61), SuiteCapture.Expected(rightDescription.Value, "assert-equal-actual", 61));

            if (bouncePassword)
            {
                // Configuration only: no property access, native bind, or
                // directory operation occurs while either password is temporary.
                // Append a token so it cannot equal the configured password.
                var temporary = DifferentialSettings.BindPassword + ":local-only:" + System.Guid.NewGuid().ToString("N");
                expected.Password = temporary;
                actual.Password = temporary;
            }
            // The unchanged case exercises the setter's no-op branch. For the
            // changed case restore both credentials before any operation below.
            expected.Password = DifferentialSettings.BindPassword;
            actual.Password = DifferentialSettings.BindPassword;

            // Do not reacquire Properties or read a native value between the
            // password assignments and CommitChanges; that would change binding.
            var leftError = Record.Exception(expected.CommitChanges);
            var rightError = Record.Exception(actual.CommitChanges);
            var leftPersisted = ReadPersistedDescription(expectedOwned);
            var rightPersisted = ReadPersistedDescription(actualOwned);
            Assert.Null(leftError);
            Assert.Equal(SuiteCapture.Expected(bouncePassword ? SeedDescription : EditedDescription, "assert-equal-expected", 84), SuiteCapture.Expected(leftPersisted, "assert-equal-actual", 84));
            if (!bouncePassword)
            {
                Assert.Null(rightError);
                Assert.Equal(SuiteCapture.Expected(EditedDescription, "assert-equal-expected", 88), SuiteCapture.Expected(rightPersisted, "assert-equal-actual", 88));
            }
            new Comparison($"Pending write after credential reset: bounce={bouncePassword}")
                .Check("commit exception", leftError?.GetType().Name, rightError?.GetType().Name)
                .Check("commit exception parameter", (leftError as ArgumentException)?.ParamName,
                    (rightError as ArgumentException)?.ParamName)
                .Check("persisted description", leftPersisted, rightPersisted)
                .Assert();
        }
        catch (Exception error) { primaryFailure = error; }
        finally
        {
            foreach (var owned in attempted)
            {
                try { Cleanup(owned); }
                catch (Exception error)
                {
                    cleanupFailures.Add(new InvalidOperationException($"Cleanup failed for owned user {owned.Dn}.", error));
                }
            }
        }
        if (cleanupFailures.Count > 0)
        {
            if (primaryFailure is not null) cleanupFailures.Insert(0, primaryFailure);
            throw new AggregateException("Credential reset test and/or cleanup failed; primary failure is first when present.", cleanupFailures);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private sealed class OwnedUser
    {
        internal OwnedUser(string provider)
        {
            var suffix = System.Guid.NewGuid().ToString("N");
            Name = $"compat-credential-{provider}-{suffix}";
            Sam = $"cr-{provider}-{suffix[..10]}";
            Marker = $"credential-owner-{suffix}";
        }
        internal string Name { get; }
        internal string Sam { get; }
        internal string Marker { get; }
        internal string Dn => $"CN={Name},{DifferentialSettings.UsersContainer}";
        internal Guid? Guid { get; set; }
    }

    private static void Seed(OwnedUser owned)
    {
        using var parent = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var created = parent.Children.Add($"CN={owned.Name}", "user");
        created.Properties["sAMAccountName"].Value = owned.Sam;
        created.Properties["userAccountControl"].Value = 514; // Disabled normal account.
        created.Properties["telephoneNumber"].Value = owned.Marker;
        created.Properties["description"].Value = SeedDescription;
        created.CommitChanges();
        created.RefreshCache();
        RequireOwned(created, owned);
        owned.Guid = created.Guid;
    }

    private static string ReadPersistedDescription(OwnedUser owned)
    {
        // Always a fresh Microsoft entry, even for the clone-owned object.
        using var probe = MicrosoftEntry(owned.Dn);
        RequireOwned(probe, owned);
        return Assert.IsType<string>(Assert.Single(probe.Properties["description"].Cast<object>()));
    }

    private static void RequireOwned(Ms.DirectoryEntry entry, OwnedUser owned)
    {
        Assert.Equal(SuiteCapture.Expected(owned.Dn, "assert-equal-expected", 157), SuiteCapture.Expected(Assert.IsType<string>(entry.Properties["distinguishedName"].Value), "assert-equal-actual", 157), ignoreCase: true);
        Assert.Equal(SuiteCapture.Expected(owned.Sam, "assert-equal-expected", 158), SuiteCapture.Expected(Assert.IsType<string>(entry.Properties["sAMAccountName"].Value), "assert-equal-actual", 158));
        Assert.Equal(SuiteCapture.Expected(owned.Marker, "assert-equal-expected", 159), SuiteCapture.Expected(Assert.IsType<string>(entry.Properties["telephoneNumber"].Value), "assert-equal-actual", 159));
        if (owned.Guid is { } expectedGuid) Assert.Equal(SuiteCapture.Expected(expectedGuid, "assert-equal-expected", 160), SuiteCapture.Expected(entry.Guid, "assert-equal-actual", 160));
    }

    private static void Cleanup(OwnedUser owned)
    {
        using var remaining = MicrosoftEntry(owned.Dn);
        try { remaining.RefreshCache(); }
        catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { return; }
        RequireOwned(remaining, owned);
        using var parent = MicrosoftEntry(DifferentialSettings.UsersContainer);
        parent.Children.Remove(remaining); // Exact owned leaf, never recursive.
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
