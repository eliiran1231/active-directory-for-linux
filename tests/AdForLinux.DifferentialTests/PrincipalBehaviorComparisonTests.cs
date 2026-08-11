using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class PrincipalBehaviorComparisonTests
{
    private sealed class MicrosoftExtendedUser : Ms.UserPrincipal
    {
        public MicrosoftExtendedUser(Ms.PrincipalContext context)
            : base(context)
        {
        }

        public object[] Read(string attribute) => ExtensionGet(attribute);

        public void Write(string attribute, object value) => ExtensionSet(attribute, value);
    }

    private sealed class OurExtendedUser : Ours.UserPrincipal
    {
        public OurExtendedUser(Ours.PrincipalContext context)
            : base(context)
        {
        }

        public object?[] Read(string attribute) => ExtensionGet(attribute);

        public void Write(string attribute, object? value) => ExtensionSet(attribute, value);
    }

    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    [Fact]
    public void ExtensionSet_treats_non_array_collections_as_one_value()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUser = new MicrosoftExtendedUser(msContext);
        using var ourUser = new OurExtendedUser(ourContext);
        var msCollection = new List<string> { "one", "two" };
        var ourCollection = new List<string> { "one", "two" };

        msUser.Write("otherTelephone", msCollection);
        ourUser.Write("otherTelephone", ourCollection);
        var msValues = msUser.Read("otherTelephone");
        var ourValues = ourUser.Read("otherTelephone");

        Assert.Single(msValues);
        Assert.Single(ourValues);
        Assert.Same(msCollection, msValues[0]);
        Assert.Same(ourCollection, ourValues[0]);
    }

    [Fact]
    public void Disposed_principals_throw_the_same_exception_type()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        var msUser = new Ms.UserPrincipal(msContext);
        var ourUser = new Ours.UserPrincipal(ourContext);
        msUser.Dispose();
        ourUser.Dispose();

        Assert.IsType<ObjectDisposedException>(Record.Exception(() => msUser.GetGroups()));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => ourUser.GetGroups()));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => msUser.Save()));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => ourUser.Save()));
        Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => msUser.IsMemberOf((Ms.GroupPrincipal)null!)));
        Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => ourUser.IsMemberOf((Ours.GroupPrincipal)null!)));
    }

    [Fact]
    public void GetGroups_with_context_matches_for_unsaved_principals()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUser = new Ms.UserPrincipal(msContext);
        using var ourUser = new Ours.UserPrincipal(ourContext);
        string?[]? msGroupDns = null;
        string?[]? ourGroupDns = null;

        var msException = Record.Exception(() =>
        {
            using var groups = msUser.GetGroups(msContext);
            msGroupDns = groups.Select(group => group.DistinguishedName).ToArray();
        });
        var ourException = Record.Exception(() =>
        {
            using var groups = ourUser.GetGroups(ourContext);
            ourGroupDns = groups.Select(group => group.DistinguishedName).ToArray();
        });

        Assert.Equal(msException?.GetType(), ourException?.GetType());
        if (msException is null)
        {
            Assert.Equal(msGroupDns, ourGroupDns);
        }
    }
}
