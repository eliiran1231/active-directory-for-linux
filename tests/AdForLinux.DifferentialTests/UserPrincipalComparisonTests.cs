using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Reads the same user with the real Microsoft library and with our clone, then
/// compares every property.
/// </summary>
[Collection("differential")]
public class UserPrincipalComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public UserPrincipalComparisonTests(TestDataFixture data)
    {
        _data = data;
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
    public void All_user_properties_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var ms = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        var ours = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(ms);
        Assert.NotNull(ours);

        new Comparison($"user {_data.UserName}")
            .Check(nameof(ms.SamAccountName), ms!.SamAccountName, ours!.SamAccountName)
            .Check(nameof(ms.Name), ms.Name, ours.Name)
            .Check(nameof(ms.DisplayName), ms.DisplayName, ours.DisplayName)
            .Check(nameof(ms.Description), ms.Description, ours.Description)
            .Check(nameof(ms.DistinguishedName), ms.DistinguishedName, ours.DistinguishedName)
            .Check(nameof(ms.UserPrincipalName), ms.UserPrincipalName, ours.UserPrincipalName)
            .Check(nameof(ms.GivenName), ms.GivenName, ours.GivenName)
            .Check(nameof(ms.Surname), ms.Surname, ours.Surname)
            .Check(nameof(ms.MiddleName), ms.MiddleName, ours.MiddleName)
            .Check(nameof(ms.EmailAddress), ms.EmailAddress, ours.EmailAddress)
            .Check(nameof(ms.VoiceTelephoneNumber), ms.VoiceTelephoneNumber, ours.VoiceTelephoneNumber)
            .Check(nameof(ms.EmployeeId), ms.EmployeeId, ours.EmployeeId)
            .Check(nameof(ms.Guid), ms.Guid, ours.Guid)
            .Check(nameof(ms.Enabled), ms.Enabled, ours.Enabled)
            .Check(nameof(ms.HomeDirectory), ms.HomeDirectory, ours.HomeDirectory)
            .Check(nameof(ms.HomeDrive), ms.HomeDrive, ours.HomeDrive)
            .Check(nameof(ms.ScriptPath), ms.ScriptPath, ours.ScriptPath)
            .Check(nameof(ms.StructuralObjectClass), ms.StructuralObjectClass, ours.StructuralObjectClass)
            .Assert();

        ms.Dispose();
        ours.Dispose();
    }

    [Fact]
    public void Account_state_properties_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var ms = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        var ours = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(ms);
        Assert.NotNull(ours);

        new Comparison($"user account state {_data.UserName}")
            .Check(nameof(ms.AccountExpirationDate), ms!.AccountExpirationDate, ours!.AccountExpirationDate)
            .Check(nameof(ms.AccountLockoutTime), ms.AccountLockoutTime, ours.AccountLockoutTime)
            .Check(nameof(ms.LastLogon), ms.LastLogon, ours.LastLogon)
            .Check(nameof(ms.LastPasswordSet), ms.LastPasswordSet, ours.LastPasswordSet)
            .Check(nameof(ms.BadLogonCount), ms.BadLogonCount, ours.BadLogonCount)
            .Check(nameof(ms.LastBadPasswordAttempt), ms.LastBadPasswordAttempt, ours.LastBadPasswordAttempt)
            .Check(nameof(ms.PasswordNeverExpires), ms.PasswordNeverExpires, ours.PasswordNeverExpires)
            .Check(nameof(ms.PasswordNotRequired), ms.PasswordNotRequired, ours.PasswordNotRequired)
            .Check(nameof(ms.DelegationPermitted), ms.DelegationPermitted, ours.DelegationPermitted)
            .Check(nameof(ms.SmartcardLogonRequired), ms.SmartcardLogonRequired, ours.SmartcardLogonRequired)
            .Check("IsAccountLockedOut()", ms.IsAccountLockedOut(), ours.IsAccountLockedOut())
            .Assert();

        ms.Dispose();
        ours.Dispose();
    }

    [Theory]
    [InlineData(Ms.IdentityType.SamAccountName, Ours.IdentityType.SamAccountName)]
    [InlineData(Ms.IdentityType.Name, Ours.IdentityType.Name)]
    public void FindByIdentity_agrees_for_each_identity_type(
        Ms.IdentityType msType, Ours.IdentityType ourType)
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var ms = Ms.UserPrincipal.FindByIdentity(msContext, msType, _data.UserName);
        var ours = Ours.UserPrincipal.FindByIdentity(ourContext, ourType, _data.UserName);

        new Comparison($"FindByIdentity by {msType}")
            .Check("found", ms is not null, ours is not null)
            .Check("DistinguishedName", ms?.DistinguishedName, ours?.DistinguishedName)
            .Assert();

        ms?.Dispose();
        ours?.Dispose();
    }

    [Fact]
    public void FindByIdentity_agrees_when_the_user_is_missing()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var ms = Ms.UserPrincipal.FindByIdentity(msContext, "no-such-user-xyz-123");
        var ours = Ours.UserPrincipal.FindByIdentity(ourContext, "no-such-user-xyz-123");

        new Comparison("missing user")
            .Check("found", ms is not null, ours is not null)
            .Assert();
    }

    [Fact]
    public void ValidateCredentials_agrees()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var upn = $"{_data.UserName}@{DomainSuffix()}";

        new Comparison("ValidateCredentials")
            .Check("correct password",
                msContext.ValidateCredentials(upn, _data.UserPassword),
                ourContext.ValidateCredentials(upn, _data.UserPassword))
            .Check("wrong password",
                msContext.ValidateCredentials(upn, "definitely-wrong"),
                ourContext.ValidateCredentials(upn, "definitely-wrong"))
            .Assert();
    }

    private static string DomainSuffix() =>
        string.Join(".", DifferentialSettings.BaseDn
            .Split(',')
            .Select(part => part.Trim())
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part.Substring(3)));
}
