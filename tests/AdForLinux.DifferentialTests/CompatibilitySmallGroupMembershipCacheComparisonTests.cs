using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates and deletes two uniquely owned leaf groups. The known fixture user
// is only referenced as a member; its attributes are never changed.
// Execute solely in a separately authorized disposable AD lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySmallGroupMembershipCacheComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    // Group.IsSmallGroup retains a SearchResult independently of its native
    // DirectoryEntry cache. IsMemberOfInStore consults that retained snapshot.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Group.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Retained_contains_after_external_membership_change_and_native_refresh_matches(bool externalRemove)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expectedUser = Ms.UserPrincipal.FindByIdentity(expectedContext, Ms.IdentityType.DistinguishedName, data.UserDn);
        using var actualUser = Ours.UserPrincipal.FindByIdentity(actualContext, Ours.IdentityType.DistinguishedName, data.UserDn);
        Assert.NotNull(expectedUser);
        Assert.NotNull(actualUser);
        Assert.Equal(data.UserDn, expectedUser.DistinguishedName, ignoreCase: true);
        Assert.Equal(data.UserDn, actualUser.DistinguishedName, ignoreCase: true);
        var expectedOwned = new OwnedGroup("ms");
        var actualOwned = new OwnedGroup("our");
        var attempted = new List<OwnedGroup>();
        Exception? primaryFailure = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            foreach (var owned in new[] { expectedOwned, actualOwned })
            {
                CompatibilityOwnedDirectoryObjects.RequireAbsent(owned.Dn);
                attempted.Add(owned); // Commit may persist before reporting an error.
                Seed(owned, data.UserDn);
                AssertServerMembership(owned, data.UserDn, present: true);
            }

            // Reload after seeding: no completed insertion list may mask the
            // native membership query on either principal under observation.
            using var expected = Ms.GroupPrincipal.FindByIdentity(expectedContext, Ms.IdentityType.DistinguishedName, expectedOwned.Dn);
            using var actual = Ours.GroupPrincipal.FindByIdentity(actualContext, Ours.IdentityType.DistinguishedName, actualOwned.Dn);
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            Assert.Equal(expectedOwned.Guid, expected.Guid);
            Assert.Equal(actualOwned.Guid, actual.Guid);
            var leftMembers = expected.Members;
            var rightMembers = actual.Members;
            Assert.True(leftMembers.Contains(expectedUser));
            Assert.True(rightMembers.Contains(actualUser));

            if (externalRemove)
            {
                RemoveMember(expectedOwned, data.UserDn);
                RemoveMember(actualOwned, data.UserDn);
            }
            AssertServerMembership(expectedOwned, data.UserDn, present: !externalRemove);
            AssertServerMembership(actualOwned, data.UserDn, present: !externalRemove);

            // These entries belong to the retained principals. Refresh them,
            // but neither dispose them separately nor Save those principals.
            // Full refresh avoids coupling this probe to absent-attribute
            // partial-refresh semantics when the sole member was removed.
            var leftNative = Assert.IsType<MsDirectory.DirectoryEntry>(expected.GetUnderlyingObject());
            var rightNative = Assert.IsType<OurDirectory.DirectoryEntry>(actual.GetUnderlyingObject());
            leftNative.RefreshCache();
            rightNative.RefreshCache();
            Assert.Same(leftMembers, expected.Members);
            Assert.Same(rightMembers, actual.Members);
            var leftContains = leftMembers.Contains(expectedUser);
            var rightContains = rightMembers.Contains(actualUser);

            // Fresh principals must see the independently verified server state.
            // This also distinguishes a retained cache from a failed mutation.
            using var freshExpected = Ms.GroupPrincipal.FindByIdentity(expectedContext, Ms.IdentityType.DistinguishedName, expectedOwned.Dn);
            using var freshActual = Ours.GroupPrincipal.FindByIdentity(actualContext, Ours.IdentityType.DistinguishedName, actualOwned.Dn);
            Assert.NotNull(freshExpected);
            Assert.NotNull(freshActual);
            Assert.Equal(!externalRemove, freshExpected.Members.Contains(expectedUser));
            Assert.Equal(!externalRemove, freshActual.Members.Contains(actualUser));
            if (!externalRemove)
            {
                Assert.True(leftContains);
                Assert.True(rightContains);
            }
            new Comparison($"Retained small-group membership, externalRemove={externalRemove}")
                .Check("Contains after native member refresh", leftContains, rightContains)
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
                    cleanupFailures.Add(new InvalidOperationException($"Cleanup failed for owned group {owned.Dn}.", error));
                }
            }
        }
        if (cleanupFailures.Count > 0)
        {
            if (primaryFailure is not null) cleanupFailures.Insert(0, primaryFailure);
            throw new AggregateException("Membership cache test and/or cleanup failed; primary failure is first when present.", cleanupFailures);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private sealed class OwnedGroup
    {
        internal OwnedGroup(string provider)
        {
            var suffix = System.Guid.NewGuid().ToString("N");
            Name = $"compat-member-cache-{provider}-{suffix}";
            Sam = $"mc-{provider}-{suffix[..10]}";
            Marker = $"compat-member-cache-owned:{suffix}";
        }
        internal string Name { get; }
        internal string Sam { get; }
        internal string Marker { get; }
        internal string Dn => $"CN={Name},{DifferentialSettings.UsersContainer}";
        internal Guid? Guid { get; set; }
    }

    private static void Seed(OwnedGroup owned, string userDn)
    {
        using var parent = Entry(DifferentialSettings.UsersContainer);
        using var seed = parent.Children.Add($"CN={owned.Name}", "group");
        seed.Properties["sAMAccountName"].Value = owned.Sam;
        seed.Properties["description"].Value = owned.Marker;
        seed.Properties["groupType"].Value = unchecked((int)0x80000002); // Security-enabled global group.
        seed.Properties["member"].Value = userDn;
        seed.CommitChanges();
        seed.RefreshCache(new[] { "objectGUID", "distinguishedName", "sAMAccountName", "description" });
        RequireOwned(seed, owned);
        owned.Guid = seed.Guid;
    }

    private static void RemoveMember(OwnedGroup owned, string userDn)
    {
        using var writer = Entry(owned.Dn);
        RequireOwned(writer, owned);
        Assert.Equal(userDn, Assert.IsType<string>(Assert.Single(writer.Properties["member"].Cast<object>())), ignoreCase: true);
        writer.Properties["member"].Remove(userDn);
        writer.CommitChanges();
    }

    private static void AssertServerMembership(OwnedGroup owned, string userDn, bool present)
    {
        using var probe = Entry(owned.Dn);
        RequireOwned(probe, owned);
        var values = probe.Properties["member"].Cast<string>().ToArray();
        if (present) Assert.Equal(userDn, Assert.Single(values), ignoreCase: true);
        else Assert.Empty(values);
    }

    private static void Cleanup(OwnedGroup owned)
    {
        using var remaining = Entry(owned.Dn);
        try { remaining.RefreshCache(new[] { "distinguishedName", "objectGUID", "sAMAccountName", "description" }); }
        catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { return; }
        RequireOwned(remaining, owned);
        using var parent = Entry(DifferentialSettings.UsersContainer);
        parent.Children.Remove(remaining); // Exact-DN leaf deletion, never DeleteTree.
    }

    private static void RequireOwned(MsDirectory.DirectoryEntry entry, OwnedGroup owned)
    {
        Assert.Equal(owned.Dn, Assert.IsType<string>(entry.Properties["distinguishedName"].Value), ignoreCase: true);
        Assert.Equal(owned.Sam, Assert.IsType<string>(entry.Properties["sAMAccountName"].Value));
        Assert.Equal(owned.Marker, Assert.IsType<string>(entry.Properties["description"].Value));
        if (owned.Guid is { } expectedGuid) Assert.Equal(expectedGuid, entry.Guid);
    }

    private static MsDirectory.DirectoryEntry Entry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
