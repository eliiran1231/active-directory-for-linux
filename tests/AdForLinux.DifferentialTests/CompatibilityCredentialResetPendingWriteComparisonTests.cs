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
                Assert.Equal(SeedDescription, ReadPersistedDescription(owned));
            }

            // Seed wrappers are already disposed. These are ordinary existing
            // entries, never DirectoryEntries.Add objects with JustCreated state.
            using var expected = MicrosoftEntry(expectedOwned.Dn);
            using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(actualOwned.Dn),
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
            Assert.True(expected.UsePropertyCache);
            Assert.True(actual.UsePropertyCache);
            RequireOwned(expected, expectedOwned);
            Assert.Equal(actualOwned.Guid, actual.Guid);
            Assert.Equal(actualOwned.Dn, Assert.IsType<string>(actual.Properties["distinguishedName"].Value), ignoreCase: true);
            Assert.Equal(actualOwned.Sam, Assert.IsType<string>(actual.Properties["sAMAccountName"].Value));
            Assert.Equal(actualOwned.Marker, Assert.IsType<string>(actual.Properties["telephoneNumber"].Value));
            var leftDescription = expected.Properties["description"];
            var rightDescription = actual.Properties["description"];
            Assert.Equal(SeedDescription, Assert.IsType<string>(Assert.Single(leftDescription.Cast<object>())));
            Assert.Equal(SeedDescription, Assert.IsType<string>(Assert.Single(rightDescription.Cast<object>())));
            leftDescription.Value = EditedDescription;
            rightDescription.Value = EditedDescription;
            Assert.Equal(EditedDescription, leftDescription.Value);
            Assert.Equal(EditedDescription, rightDescription.Value);

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
            Assert.Equal(bouncePassword ? SeedDescription : EditedDescription, leftPersisted);
            if (!bouncePassword)
            {
                Assert.Null(rightError);
                Assert.Equal(EditedDescription, rightPersisted);
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
        Assert.Equal(owned.Dn, Assert.IsType<string>(entry.Properties["distinguishedName"].Value), ignoreCase: true);
        Assert.Equal(owned.Sam, Assert.IsType<string>(entry.Properties["sAMAccountName"].Value));
        Assert.Equal(owned.Marker, Assert.IsType<string>(entry.Properties["telephoneNumber"].Value));
        if (owned.Guid is { } expectedGuid) Assert.Equal(expectedGuid, entry.Guid);
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
