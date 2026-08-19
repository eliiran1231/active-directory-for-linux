using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using MsDs = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class PrincipalInsertIdentityComparisonTests
{
    private static Ms.PrincipalContext MicrosoftContext(string container) =>
        new(Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string container) =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    [Fact]
    public void New_principal_identity_state_matches_microsoft_without_manual_refresh()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var msNames = Names.For($"i71ms{suffix}");
        var ourNames = Names.For($"i71our{suffix}");

        using var isolatedOu = IsolatedOu.Create($"adfl-i71-id-{suffix}");
        using var msContext = MicrosoftContext(isolatedOu.DistinguishedName);
        using var ourContext = OurContext(isolatedOu.DistinguishedName);
        try
        {
            var microsoft = ObserveMicrosoft(msContext, msNames);
            var ours = ObserveOurs(ourContext, ourNames);

            Assert.Equal(microsoft, ours);
            Assert.All(ours, state =>
            {
                Assert.True(state.GuidAvailable);
                Assert.True(state.SidAvailable);
                Assert.True(state.UnderlyingGuidAvailable);
                Assert.True(state.EqualsQueriedPrincipal);
            });
        }
        finally
        {
            DeleteMicrosoft(msContext, msNames);
            DeleteOurs(ourContext, ourNames);
        }
    }

    [Fact]
    public void Sid_based_membership_query_works_immediately_after_insert()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var msUserName = $"i71msu{suffix}";
        var msGroupName = $"i71msg{suffix}";
        var ourUserName = $"i71ouru{suffix}";
        var ourGroupName = $"i71ourg{suffix}";

        using var isolatedOu = IsolatedOu.Create($"adfl-i71-mem-{suffix}");
        using var msContext = MicrosoftContext(isolatedOu.DistinguishedName);
        using var ourContext = OurContext(isolatedOu.DistinguishedName);
        try
        {
            using var msUser = NewMicrosoftUser(msContext, msUserName);
            using var msGroup = new Ms.GroupPrincipal(msContext, msGroupName);
            msUser.Save();
            msGroup.Save();
            msGroup.Members.Add(msUser);
            msGroup.Save();
            using var msGroups = msUser.GetGroups(msContext);
            var microsoftFound = msGroups.Any(candidate => candidate.Equals(msGroup));

            using var ourUser = NewOurUser(ourContext, ourUserName);
            using var ourGroup = new Ours.GroupPrincipal(ourContext, ourGroupName);
            ourUser.Save();
            ourGroup.Save();
            ourGroup.Members.Add(ourUser);
            ourGroup.Save();
            using var ourGroups = ourUser.GetGroups(ourContext);
            var oursFound = ourGroups.Any(candidate => candidate.Equals(ourGroup));

            Assert.Equal(microsoftFound, oursFound);
            Assert.True(oursFound);
        }
        finally
        {
            DeleteMicrosoft(msContext, new Names(msUserName, msGroupName, string.Empty));
            DeleteOurs(ourContext, new Names(ourUserName, ourGroupName, string.Empty));
        }
    }

    private static IdentityState[] ObserveMicrosoft(Ms.PrincipalContext context, Names names)
    {
        using var user = NewMicrosoftUser(context, names.User);
        using var group = new Ms.GroupPrincipal(context, names.Group);
        using var computer = NewMicrosoftComputer(context, names.Computer);
        user.Save();
        group.Save();
        computer.Save();

        var immediate = new[]
        {
            ImmediateMicrosoftState(user),
            ImmediateMicrosoftState(group),
            ImmediateMicrosoftState(computer),
        };

        using var foundUser = Ms.UserPrincipal.FindByIdentity(context, names.User);
        using var foundGroup = Ms.GroupPrincipal.FindByIdentity(context, names.Group);
        using var foundComputer = Ms.ComputerPrincipal.FindByIdentity(context, names.Computer);
        return new[]
        {
            immediate[0] with { EqualsQueriedPrincipal = user.Equals(foundUser) },
            immediate[1] with { EqualsQueriedPrincipal = group.Equals(foundGroup) },
            immediate[2] with { EqualsQueriedPrincipal = computer.Equals(foundComputer) },
        };
    }

    private static IdentityState[] ObserveOurs(Ours.PrincipalContext context, Names names)
    {
        using var user = NewOurUser(context, names.User);
        using var group = new Ours.GroupPrincipal(context, names.Group);
        using var computer = NewOurComputer(context, names.Computer);
        user.Save();
        group.Save();
        computer.Save();

        var immediate = new[]
        {
            ImmediateOurState(user),
            ImmediateOurState(group),
            ImmediateOurState(computer),
        };

        using var foundUser = Ours.UserPrincipal.FindByIdentity(context, names.User);
        using var foundGroup = Ours.GroupPrincipal.FindByIdentity(context, names.Group);
        using var foundComputer = Ours.ComputerPrincipal.FindByIdentity(context, names.Computer);
        return new[]
        {
            immediate[0] with { EqualsQueriedPrincipal = user.Equals(foundUser) },
            immediate[1] with { EqualsQueriedPrincipal = group.Equals(foundGroup) },
            immediate[2] with { EqualsQueriedPrincipal = computer.Equals(foundComputer) },
        };
    }

    private static IdentityState ImmediateMicrosoftState(Ms.Principal principal) => new(
        principal.Guid is not null,
        principal.Sid is not null,
        ((System.DirectoryServices.DirectoryEntry)principal.GetUnderlyingObject()).Guid != Guid.Empty,
        false);

    private static IdentityState ImmediateOurState(Ours.Principal principal) => new(
        principal.Guid is not null,
        principal.SidValue is not null && principal.Sid is not null,
        ((AdForLinux.DirectoryServices.DirectoryEntry)principal.GetUnderlyingObject()!).Guid != Guid.Empty,
        false);

    private static Ms.UserPrincipal NewMicrosoftUser(Ms.PrincipalContext context, string name) =>
        new(context) { Name = name, SamAccountName = name, Enabled = false };

    private static Ours.UserPrincipal NewOurUser(Ours.PrincipalContext context, string name) =>
        new(context) { Name = name, SamAccountName = name, Enabled = false };

    private static Ms.ComputerPrincipal NewMicrosoftComputer(Ms.PrincipalContext context, string name) =>
        new(context) { Name = name, SamAccountName = name, Enabled = false };

    private static Ours.ComputerPrincipal NewOurComputer(Ours.PrincipalContext context, string name) =>
        new(context) { Name = name, SamAccountName = name, Enabled = false };

    private static void DeleteMicrosoft(Ms.PrincipalContext context, Names names)
    {
        if (!string.IsNullOrEmpty(names.User))
        {
            Delete(() => Ms.UserPrincipal.FindByIdentity(context, names.User));
        }
        if (!string.IsNullOrEmpty(names.Group))
        {
            Delete(() => Ms.GroupPrincipal.FindByIdentity(context, names.Group));
        }
        if (!string.IsNullOrEmpty(names.Computer))
        {
            Delete(() => Ms.ComputerPrincipal.FindByIdentity(context, names.Computer));
        }
    }

    private static void DeleteOurs(Ours.PrincipalContext context, Names names)
    {
        if (!string.IsNullOrEmpty(names.User))
        {
            Delete(() => Ours.UserPrincipal.FindByIdentity(context, names.User));
        }
        if (!string.IsNullOrEmpty(names.Group))
        {
            Delete(() => Ours.GroupPrincipal.FindByIdentity(context, names.Group));
        }
        if (!string.IsNullOrEmpty(names.Computer))
        {
            Delete(() => Ours.ComputerPrincipal.FindByIdentity(context, names.Computer));
        }
    }

    private static void Delete<TPrincipal>(Func<TPrincipal?> find)
        where TPrincipal : IDisposable
    {
        using var principal = find();
        switch (principal)
        {
            case Ms.Principal microsoft:
                microsoft.Delete();
                break;
            case Ours.Principal ours:
                ours.Delete();
                break;
        }
    }

    private sealed record IdentityState(
        bool GuidAvailable,
        bool SidAvailable,
        bool UnderlyingGuidAvailable,
        bool EqualsQueriedPrincipal);

    private sealed record Names(string User, string Group, string Computer)
    {
        public static Names For(string prefix) =>
            new($"{prefix}u", $"{prefix}g", $"{prefix}c$");
    }

    private sealed class IsolatedOu : IDisposable
    {
        private IsolatedOu(string distinguishedName)
        {
            DistinguishedName = distinguishedName;
        }

        public string DistinguishedName { get; }

        public static IsolatedOu Create(string name)
        {
            using var parent = Open(DifferentialSettings.BaseDn);
            using var child = parent.Children.Add($"OU={name}", "organizationalUnit");
            child.CommitChanges();
            return new IsolatedOu($"OU={name},{DifferentialSettings.BaseDn}");
        }

        public void Dispose()
        {
            try
            {
                using var entry = Open(DistinguishedName);
                entry.DeleteTree();
            }
            catch (MsDs.DirectoryServicesCOMException)
            {
                // Best-effort cleanup after an earlier live assertion failure.
            }
        }

        private static MsDs.DirectoryEntry Open(string distinguishedName) =>
            new(
                DifferentialSettings.PathFor(distinguishedName),
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
    }
}
