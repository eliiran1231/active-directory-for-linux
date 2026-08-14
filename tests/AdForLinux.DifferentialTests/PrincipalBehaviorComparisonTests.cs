using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class PrincipalBehaviorComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public PrincipalBehaviorComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

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

    [Fact]
    public void Password_members_match_for_unsaved_principals()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msComputer = new Ms.ComputerPrincipal(msContext);
        using var ourComputer = new Ours.ComputerPrincipal(ourContext);
        using var msUser = new Ms.UserPrincipal(msContext);
        using var ourUser = new Ours.UserPrincipal(ourContext);

        Assert.Equal(msComputer.UserCannotChangePassword, ourComputer.UserCannotChangePassword);
        msComputer.UserCannotChangePassword = true;
        ourComputer.UserCannotChangePassword = true;
        Assert.Equal(msComputer.UserCannotChangePassword, ourComputer.UserCannotChangePassword);

        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => msUser.ChangePassword("old", "new")));
        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => ourUser.ChangePassword("old", "new")));
    }

    [Fact]
    public void Saved_computer_password_members_match_microsoft()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msComputer = Ms.ComputerPrincipal.FindByIdentity(msContext, $"{_data.ComputerName}$");
        using var ourComputer = Ours.ComputerPrincipal.FindByIdentity(ourContext, $"{_data.ComputerName}$");
        Assert.NotNull(msComputer);
        Assert.NotNull(ourComputer);

        Assert.Equal(msComputer!.UserCannotChangePassword, ourComputer!.UserCannotChangePassword);

        msComputer.UserCannotChangePassword = true;
        ourComputer.UserCannotChangePassword = true;
        var msSaveException = Record.Exception(msComputer.Save);
        var ourSaveException = Record.Exception(ourComputer.Save);
        Assert.Equal(msSaveException?.GetType(), ourSaveException?.GetType());
        Assert.Null(msSaveException);
        Assert.Equal(msComputer.UserCannotChangePassword, ourComputer.UserCannotChangePassword);

        Assert.IsType<NotSupportedException>(
            Record.Exception(() => msComputer.ChangePassword("old", "new")));
        Assert.IsType<NotSupportedException>(
            Record.Exception(() => ourComputer.ChangePassword("old", "new")));
    }

    [Fact]
    public void Password_rejection_exception_types_match_microsoft()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);
        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        Assert.IsType<Ms.PasswordException>(Record.Exception(
            () => msUser!.ChangePassword("Wr0ng!OldPass#2026", "Str0ng!NewPass#2026")));
        Assert.IsType<Ours.PasswordException>(Record.Exception(
            () => ourUser!.ChangePassword("Wr0ng!OldPass#2026", "Str0ng!NewPass#2026")));

        Assert.IsType<Ms.PasswordException>(Record.Exception(
            () => msUser!.ChangePassword(_data.UserPassword, "short")));
        Assert.IsType<Ours.PasswordException>(Record.Exception(
            () => ourUser!.ChangePassword(_data.UserPassword, "short")));

        Assert.Equal(
            Record.Exception(() => msUser!.SetPassword("short"))?.GetType().Name,
            Record.Exception(() => ourUser!.SetPassword("short"))?.GetType().Name);
    }
}
