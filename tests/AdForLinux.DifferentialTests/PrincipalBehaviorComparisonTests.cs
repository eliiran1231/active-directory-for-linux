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

    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    private sealed class MicrosoftCustomAuthenticablePrincipal : Ms.AuthenticablePrincipal
    {
        public MicrosoftCustomAuthenticablePrincipal(Ms.PrincipalContext context)
            : base(context)
        {
        }

        public static MicrosoftCustomAuthenticablePrincipal? Find(
            Ms.PrincipalContext context,
            string identityValue) =>
            (MicrosoftCustomAuthenticablePrincipal?)FindByIdentityWithType(
                context,
                typeof(MicrosoftCustomAuthenticablePrincipal),
                identityValue);
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    private sealed class OurCustomAuthenticablePrincipal : Ours.AuthenticablePrincipal
    {
        public OurCustomAuthenticablePrincipal(Ours.PrincipalContext context)
            : base(context)
        {
        }

        public static OurCustomAuthenticablePrincipal? Find(
            Ours.PrincipalContext context,
            string identityValue) =>
            (OurCustomAuthenticablePrincipal?)FindByIdentityWithType(
                context,
                typeof(OurCustomAuthenticablePrincipal),
                identityValue);
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
    public void Required_name_setter_validation_matches_microsoft_across_principal_states()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUnsaved = new Ms.UserPrincipal(msContext);
        using var ourUnsaved = new Ours.UserPrincipal(ourContext);

        foreach (var value in new string?[] { null, string.Empty })
        {
            AssertRequiredNameSetterValidation(msUnsaved, ourUnsaved, value);
        }

        msUnsaved.Name = " ";
        ourUnsaved.Name = " ";
        msUnsaved.SamAccountName = "\t";
        ourUnsaved.SamAccountName = "\t";
        msUnsaved.Description = null;
        ourUnsaved.Description = null;
        Assert.Equal(msUnsaved.Name, ourUnsaved.Name);
        Assert.Equal(msUnsaved.SamAccountName, ourUnsaved.SamAccountName);
        Assert.Equal(msUnsaved.Description, ourUnsaved.Description);

        using var msPersisted = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourPersisted = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);
        Assert.NotNull(msPersisted);
        Assert.NotNull(ourPersisted);
        foreach (var value in new string?[] { null, string.Empty })
        {
            AssertRequiredNameSetterValidation(msPersisted!, ourPersisted!, value);
        }

        var msDisposed = new Ms.UserPrincipal(msContext);
        var ourDisposed = new Ours.UserPrincipal(ourContext);
        msDisposed.Dispose();
        ourDisposed.Dispose();
        foreach (var value in new string?[] { null, string.Empty })
        {
            AssertRequiredNameSetterValidation(msDisposed, ourDisposed, value);
        }
        Assert.Equal(
            Record.Exception(() => msDisposed.Name = "valid")?.GetType().Name,
            Record.Exception(() => ourDisposed.Name = "valid")?.GetType().Name);
        Assert.Equal(
            Record.Exception(() => msDisposed.SamAccountName = "valid")?.GetType().Name,
            Record.Exception(() => ourDisposed.SamAccountName = "valid")?.GetType().Name);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msDeletedName = $"adfl-nm-{suffix}";
        var ourDeletedName = $"adfl-no-{suffix}";
        using var msDeleted = new Ms.UserPrincipal(msContext)
        {
            Name = msDeletedName,
            SamAccountName = msDeletedName,
        };
        using var ourDeleted = new Ours.UserPrincipal(ourContext)
        {
            Name = ourDeletedName,
            SamAccountName = ourDeletedName,
        };
        try
        {
            msDeleted.Save();
            ourDeleted.Save();
            msDeleted.Delete();
            ourDeleted.Delete();

            foreach (var value in new string?[] { null, string.Empty })
            {
                AssertRequiredNameSetterValidation(msDeleted, ourDeleted, value);
            }
            Assert.Equal(
                Record.Exception(() => msDeleted.Name = "valid")?.GetType().Name,
                Record.Exception(() => ourDeleted.Name = "valid")?.GetType().Name);
            Assert.Equal(
                Record.Exception(() => msDeleted.SamAccountName = "valid")?.GetType().Name,
                Record.Exception(() => ourDeleted.SamAccountName = "valid")?.GetType().Name);
        }
        finally
        {
            DeleteIfPresent(msContext, msDeletedName);
            DeleteIfPresent(ourContext, ourDeletedName);
        }
    }

    private static void AssertRequiredNameSetterValidation(
        Ms.UserPrincipal microsoft,
        Ours.UserPrincipal ours,
        string? value)
    {
        var msName = Assert.IsType<ArgumentNullException>(
            Record.Exception(() => microsoft.Name = value));
        var ourName = Assert.IsType<ArgumentNullException>(
            Record.Exception(() => ours.Name = value));
        Assert.Equal(msName.ParamName, ourName.ParamName);

        var msSam = Assert.IsType<ArgumentNullException>(
            Record.Exception(() => microsoft.SamAccountName = value));
        var ourSam = Assert.IsType<ArgumentNullException>(
            Record.Exception(() => ours.SamAccountName = value));
        Assert.Equal(msSam.ParamName, ourSam.ParamName);
    }

    private static void DeleteIfPresent(Ms.PrincipalContext context, string name)
    {
        try
        {
            using var principal = Ms.UserPrincipal.FindByIdentity(context, name);
            principal?.Delete();
        }
        catch
        {
            // Best-effort cleanup for a failed comparison.
        }
    }

    private static void DeleteIfPresent(Ours.PrincipalContext context, string name)
    {
        try
        {
            using var principal = Ours.UserPrincipal.FindByIdentity(context, name);
            principal?.Delete();
        }
        catch
        {
            // Best-effort cleanup for a failed comparison.
        }
    }

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
    public void Disposed_context_members_match_exception_type_and_object_name()
    {
        var msContext = MicrosoftContext();
        var ourContext = OurContext();
        msContext.Dispose();
        ourContext.Dispose();

        (Action Microsoft, Action Ours)[] members =
        {
            (() => _ = msContext.ContextType, () => _ = ourContext.ContextType),
            (() => _ = msContext.Name, () => _ = ourContext.Name),
            (() => _ = msContext.Container, () => _ = ourContext.Container),
            (() => _ = msContext.UserName, () => _ = ourContext.UserName),
            (() => _ = msContext.Options, () => _ = ourContext.Options),
            (() => _ = msContext.ConnectedServer, () => _ = ourContext.ConnectedServer),
            (() => msContext.ValidateCredentials("user", "password"),
             () => ourContext.ValidateCredentials("user", "password")),
        };

        foreach (var (microsoft, ours) in members)
        {
            var msException = Assert.IsType<ObjectDisposedException>(Record.Exception(microsoft));
            var ourException = Assert.IsType<ObjectDisposedException>(Record.Exception(ours));
            Assert.Equal(
                msException.ObjectName?.Replace(
                    "System.DirectoryServices.AccountManagement",
                    "AdForLinux.DirectoryServices.AccountManagement",
                    StringComparison.Ordinal),
                ourException.ObjectName);
        }
    }

    [Fact]
    public void Disposed_cached_principal_properties_match_exception_contract()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        var msUser = new Ms.UserPrincipal(msContext) { Name = "cached", GivenName = "given" };
        var ourUser = new Ours.UserPrincipal(ourContext) { Name = "cached", GivenName = "given" };
        msUser.Dispose();
        ourUser.Dispose();

        (Action Microsoft, Action Ours)[] members =
        {
            (() => _ = msUser.Context, () => _ = ourUser.Context),
            (() => _ = msUser.ContextType, () => _ = ourUser.ContextType),
            (() => _ = msUser.DistinguishedName, () => _ = ourUser.DistinguishedName),
            (() => _ = msUser.Name, () => _ = ourUser.Name),
            (() => _ = msUser.GivenName, () => _ = ourUser.GivenName),
            (() => msUser.Name = "changed", () => ourUser.Name = "changed"),
            (() => msUser.SetPassword(null!), () => ourUser.SetPassword(null!)),
        };

        foreach (var (microsoft, ours) in members)
        {
            var msException = Assert.IsType<ObjectDisposedException>(Record.Exception(microsoft));
            var ourException = Assert.IsType<ObjectDisposedException>(Record.Exception(ours));
            // Principal.CheckDisposedOrDeleted uses GetType().ToString(), so the
            // ObjectName is namespace-qualified; normalize the namespace before
            // comparing, same as Disposed_context_members_match_exception_type_and_object_name.
            Assert.Equal(
                msException.ObjectName?.Replace(
                    "System.DirectoryServices.AccountManagement",
                    "AdForLinux.DirectoryServices.AccountManagement",
                    StringComparison.Ordinal),
                ourException.ObjectName);
        }
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
    public void Saved_custom_authenticable_principal_can_attempt_password_change_like_microsoft()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msPrincipal = MicrosoftCustomAuthenticablePrincipal.Find(msContext, _data.UserName);
        using var ourPrincipal = OurCustomAuthenticablePrincipal.Find(ourContext, _data.UserName);
        Assert.NotNull(msPrincipal);
        Assert.NotNull(ourPrincipal);

        Assert.IsType<Ms.PasswordException>(Record.Exception(
            () => msPrincipal!.ChangePassword("Wr0ng!OldPass#2026", "Str0ng!NewPass#2026")));
        Assert.IsType<Ours.PasswordException>(Record.Exception(
            () => ourPrincipal!.ChangePassword("Wr0ng!OldPass#2026", "Str0ng!NewPass#2026")));
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
