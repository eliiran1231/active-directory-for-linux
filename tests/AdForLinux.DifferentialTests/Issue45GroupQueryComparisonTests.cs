using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

/// <summary>Focused Microsoft comparisons for issue 45.</summary>
[Collection("differential")]
public sealed class Issue45GroupQueryComparisonTests
{
    private static string NewName(string kind) =>
        $"i45-{kind}-{Guid.NewGuid():N}"[..18];

    [Fact]
    public void GetGroups_overloads_match_container_scoping()
    {
        var baseDn = DifferentialSettings.BaseDn;
        var userOu = $"OU={NewName("uou")},{baseDn}";
        var otherOu = $"OU={NewName("gou")},{baseDn}";
        var userName = NewName("usr");
        var insideName = NewName("gin");
        var outsideName = NewName("gout");
        var userDn = $"CN={userName},{userOu}";
        var insideDn = $"CN={insideName},{userOu}";
        var outsideDn = $"CN={outsideName},{otherOu}";

        try
        {
            CreateOrganizationalUnit(userOu);
            CreateOrganizationalUnit(otherOu);
            CreateUser(userDn, userName);
            CreateGroup(insideDn, insideName, userDn);
            CreateGroup(outsideDn, outsideName, userDn);

            using var msUserContext = MicrosoftContext(userOu);
            using var ourUserContext = OurContext(userOu);
            using var msOtherContext = MicrosoftContext(otherOu);
            using var ourOtherContext = OurContext(otherOu);
            using var msBaseContext = MicrosoftContext(baseDn);
            using var ourBaseContext = OurContext(baseDn);
            using var msUser = Ms.UserPrincipal.FindByIdentity(msUserContext, userName)!;
            using var ourUser = Ours.UserPrincipal.FindByIdentity(ourUserContext, userName)!;

            Compare("GetGroups(context) scoped to a sibling OU",
                msUser.GetGroups(msOtherContext), ourUser.GetGroups(ourOtherContext));
            Compare("GetGroups(context) scoped to the configured base OU",
                msUser.GetGroups(msBaseContext), ourUser.GetGroups(ourBaseContext));

            using var authorizationGroups = ourUser.GetAuthorizationGroups();
            var authorizationDns = authorizationGroups
                .Select(group => group.DistinguishedName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains(insideDn, authorizationDns);
            Assert.Contains(outsideDn, authorizationDns);

            // GetGroups() is covered against Samba in the functional suite.
            // Microsoft's overload performs forest locator discovery, which is
            // unavailable on non-domain-joined differential runners even when
            // their explicit LDAPS connection to this DC succeeds.
        }
        finally
        {
            Delete(otherOu);
            Delete(userOu);
        }
    }

    [Fact]
    public void GetGroups_matches_cross_domain_fsp_and_nested_membership_when_configured()
    {
        var secondHost = Environment.GetEnvironmentVariable("AD_SECOND_HOST");
        var secondBaseDn = Environment.GetEnvironmentVariable("AD_SECOND_BASE_DN");
        if (string.IsNullOrWhiteSpace(secondHost) || string.IsNullOrWhiteSpace(secondBaseDn))
        {
            return; // A two-domain trust lab is optional; the single-domain test remains mandatory.
        }

        var userName = NewName("xusr");
        var directName = NewName("xdir");
        var nestedName = NewName("xnest");
        var userDn = $"CN={userName},{DifferentialSettings.BaseDn}";
        var directDn = $"CN={directName},{secondBaseDn}";
        var nestedDn = $"CN={nestedName},{secondBaseDn}";

        try
        {
            CreateUser(userDn, userName);
            using var msSource = MicrosoftContext(DifferentialSettings.BaseDn);
            using var msTarget = MicrosoftSecondContext(secondHost, secondBaseDn);
            using var ourSource = OurContext(DifferentialSettings.BaseDn);
            using var ourTarget = OurSecondContext(secondHost, secondBaseDn);
            using var msUser = Ms.UserPrincipal.FindByIdentity(msSource, userName)!;

            using (var direct = new Ms.GroupPrincipal(msTarget, directName)
            {
                GroupScope = Ms.GroupScope.Local,
                IsSecurityGroup = true,
            })
            {
                direct.Members.Add(msUser);
                direct.Save();
            }

            using (var nested = new Ms.GroupPrincipal(msTarget, nestedName)
            {
                GroupScope = Ms.GroupScope.Local,
                IsSecurityGroup = true,
            })
            using (var direct = Ms.GroupPrincipal.FindByIdentity(msTarget, directName)!)
            {
                nested.Members.Add(direct);
                nested.Save();
            }

            using var ourUser = Ours.UserPrincipal.FindByIdentity(ourSource, userName)!;
            Compare("cross-domain direct groups",
                msUser.GetGroups(msTarget), ourUser.GetGroups(ourTarget));

            using var msAuthorization = msUser.GetAuthorizationGroups();
            using var ourAuthorization = ourUser.GetAuthorizationGroups();
            var microsoftSids = msAuthorization
                .Select(group => group.Sid?.Value ?? group.DistinguishedName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var ourSids = ourAuthorization
                .Select(group => group.Sid?.Value ?? group.DistinguishedName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.True(ourSids.IsSubsetOf(microsoftSids));
            Assert.Contains(directDn,
                ourAuthorization.Select(group => group.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);
            Assert.Contains(nestedDn,
                ourAuthorization.Select(group => group.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteOnSecond(secondHost, nestedDn);
            DeleteOnSecond(secondHost, directDn);
            Delete(userDn);
        }
    }

    private static void Compare(
        string label,
        Ms.PrincipalSearchResult<Ms.Principal> microsoft,
        Ours.PrincipalSearchResult<Ours.Principal> ours)
    {
        using (microsoft)
        using (ours)
        {
            new Comparison(label)
                .CheckSet("group DNs",
                    microsoft.Select(group => group.DistinguishedName),
                    ours.Select(group => group.DistinguishedName))
                .Assert();
        }
    }

    private static Ms.PrincipalContext MicrosoftContext(string container) =>
        new(Ms.ContextType.Domain, DifferentialSettings.ServerName, container,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string container) =>
        new(Ours.ContextType.Domain, DifferentialSettings.ServerName, container,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ms.PrincipalContext MicrosoftSecondContext(string host, string container) =>
        new(Ms.ContextType.Domain, host, container,
            DifferentialSettings.MicrosoftContextOptions,
            Environment.GetEnvironmentVariable("AD_SECOND_BIND_DN") ?? DifferentialSettings.BindDn,
            Environment.GetEnvironmentVariable("AD_SECOND_BIND_PW") ?? DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurSecondContext(string host, string container) =>
        new(Ours.ContextType.Domain, host, container,
            DifferentialSettings.OurContextOptions,
            Environment.GetEnvironmentVariable("AD_SECOND_BIND_DN") ?? DifferentialSettings.BindDn,
            Environment.GetEnvironmentVariable("AD_SECOND_BIND_PW") ?? DifferentialSettings.BindPassword);

    private static void CreateOrganizationalUnit(string dn)
    {
        var separator = dn.IndexOf(',');
        using var parent = Open(dn[(separator + 1)..]);
        using var child = parent.Children.Add(dn[..separator], "organizationalUnit");
        child.CommitChanges();
    }

    private static void CreateUser(string dn, string samAccountName)
    {
        var separator = dn.IndexOf(',');
        using var parent = Open(dn[(separator + 1)..]);
        using var child = parent.Children.Add(dn[..separator], "user");
        child.Properties["sAMAccountName"].Value = samAccountName;
        child.CommitChanges();
    }

    private static void CreateGroup(string dn, string samAccountName, string memberDn)
    {
        var separator = dn.IndexOf(',');
        using var parent = Open(dn[(separator + 1)..]);
        using var child = parent.Children.Add(dn[..separator], "group");
        child.Properties["sAMAccountName"].Value = samAccountName;
        child.Properties["member"].Add(memberDn);
        child.CommitChanges();
    }

    private static System.DirectoryServices.DirectoryEntry Open(string dn) =>
        new(DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static void Delete(string dn)
    {
        try
        {
            using var entry = Open(dn);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }

    private static void DeleteOnSecond(string? host, string dn)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return;
        }

        try
        {
            using var entry = new System.DirectoryServices.DirectoryEntry(
                $"LDAP://{host}/{dn}",
                Environment.GetEnvironmentVariable("AD_SECOND_BIND_DN") ?? DifferentialSettings.BindDn,
                Environment.GetEnvironmentVariable("AD_SECOND_BIND_PW") ?? DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }
}
