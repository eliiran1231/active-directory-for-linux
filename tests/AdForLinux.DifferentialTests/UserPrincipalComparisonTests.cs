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
            DifferentialSettings.Host,
            DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.Host,
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

    public enum DateFinder
    {
        BadPasswordAttempt,
        Expiration,
        Lockout,
        Logon,
        PasswordSet,
    }

    public enum DateBoundary
    {
        ExactExpiration,
        Past,
        Future,
    }

    public static IEnumerable<object[]> DateFinderCases()
    {
        foreach (var finder in Enum.GetValues<DateFinder>())
        {
            foreach (var match in Enum.GetValues<Ms.MatchType>())
            {
                var boundary = match switch
                {
                    Ms.MatchType.Equals or Ms.MatchType.NotEquals when finder == DateFinder.Expiration =>
                        DateBoundary.ExactExpiration,
                    Ms.MatchType.LessThan or Ms.MatchType.LessThanOrEquals => DateBoundary.Future,
                    _ => DateBoundary.Past,
                };
                yield return [finder, match, boundary];
            }
        }
    }

    [Theory]
    [MemberData(nameof(DateFinderCases))]
    public void Date_finders_match_microsoft_for_ranges_and_zero_or_unset_values(
        DateFinder finder,
        Ms.MatchType match,
        DateBoundary boundary)
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        var time = boundary switch
        {
            DateBoundary.ExactExpiration => _data.UserExpirationTime,
            DateBoundary.Past => new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            DateBoundary.Future => new DateTime(2040, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            _ => throw new ArgumentOutOfRangeException(nameof(boundary)),
        };
        var oursMatch = (Ours.MatchType)(int)match;

        using var microsoft = FindMicrosoft(finder, msContext, time, match);
        using var ours = FindOurs(finder, ourContext, time, oursMatch);
        var microsoftNames = microsoft.Select(principal => principal.SamAccountName).ToArray();
        var ourNames = ours.Select(principal => principal.SamAccountName).ToArray();

        new Comparison($"UserPrincipal.FindBy{finder}Time({match}, {boundary})")
            .CheckSet(
                "SamAccountName",
                microsoftNames,
                ourNames)
            .Check(
                "seeded nonzero user membership",
                microsoftNames.Contains(_data.UserName, StringComparer.OrdinalIgnoreCase),
                ourNames.Contains(_data.UserName, StringComparer.OrdinalIgnoreCase))
            .Check(
                "zero/unset user membership",
                microsoftNames.Contains(_data.UnsetUserName, StringComparer.OrdinalIgnoreCase),
                ourNames.Contains(_data.UnsetUserName, StringComparer.OrdinalIgnoreCase))
            .Assert();
    }

    private static Ms.PrincipalSearchResult<Ms.UserPrincipal> FindMicrosoft(
        DateFinder finder,
        Ms.PrincipalContext context,
        DateTime time,
        Ms.MatchType match) => finder switch
        {
            DateFinder.BadPasswordAttempt => Ms.UserPrincipal.FindByBadPasswordAttempt(context, time, match),
            DateFinder.Expiration => Ms.UserPrincipal.FindByExpirationTime(context, time, match),
            DateFinder.Lockout => Ms.UserPrincipal.FindByLockoutTime(context, time, match),
            DateFinder.Logon => Ms.UserPrincipal.FindByLogonTime(context, time, match),
            DateFinder.PasswordSet => Ms.UserPrincipal.FindByPasswordSetTime(context, time, match),
            _ => throw new ArgumentOutOfRangeException(nameof(finder)),
        };

    private static Ours.PrincipalSearchResult<Ours.UserPrincipal> FindOurs(
        DateFinder finder,
        Ours.PrincipalContext context,
        DateTime time,
        Ours.MatchType match) => finder switch
        {
            DateFinder.BadPasswordAttempt => Ours.UserPrincipal.FindByBadPasswordAttempt(context, time, match),
            DateFinder.Expiration => Ours.UserPrincipal.FindByExpirationTime(context, time, match),
            DateFinder.Lockout => Ours.UserPrincipal.FindByLockoutTime(context, time, match),
            DateFinder.Logon => Ours.UserPrincipal.FindByLogonTime(context, time, match),
            DateFinder.PasswordSet => Ours.UserPrincipal.FindByPasswordSetTime(context, time, match),
            _ => throw new ArgumentOutOfRangeException(nameof(finder)),
        };

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

    [Fact]
    public void ValidateCredentials_with_explicit_options_agrees()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        var upn = $"{_data.UserName}@{DomainSuffix()}";

        new Comparison("ValidateCredentials with explicit ContextOptions")
            .Check("correct password",
                msContext.ValidateCredentials(
                    upn,
                    _data.UserPassword,
                    Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer),
                ourContext.ValidateCredentials(
                    upn,
                    _data.UserPassword,
                    Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer))
            .Check("wrong password",
                msContext.ValidateCredentials(
                    upn,
                    "definitely-wrong",
                    Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer),
                ourContext.ValidateCredentials(
                    upn,
                    "definitely-wrong",
                    Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer))
            .Assert();
    }

    [Fact]
    public void ValidateCredentials_with_negotiate_signing_and_sealing_agrees()
    {
        using var msContext = new Ms.PrincipalContext(
            Ms.ContextType.Domain,
            DifferentialSettings.Host,
            DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(
            Ours.ContextType.Domain,
            DifferentialSettings.Host,
            DifferentialSettings.UsersContainer,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        var upn = $"{_data.UserName}@{DomainSuffix()}";

        new Comparison("ValidateCredentials with negotiate, signing, and sealing")
            .Check("correct password",
                msContext.ValidateCredentials(
                    upn,
                    _data.UserPassword,
                    Ms.ContextOptions.Negotiate |
                    Ms.ContextOptions.Signing |
                    Ms.ContextOptions.Sealing),
                ourContext.ValidateCredentials(
                    upn,
                    _data.UserPassword,
                    Ours.ContextOptions.Negotiate |
                    Ours.ContextOptions.Signing |
                    Ours.ContextOptions.Sealing))
            .Check("wrong password",
                msContext.ValidateCredentials(
                    upn,
                    "definitely-wrong",
                    Ms.ContextOptions.Negotiate |
                    Ms.ContextOptions.Signing |
                    Ms.ContextOptions.Sealing),
                ourContext.ValidateCredentials(
                    upn,
                    "definitely-wrong",
                    Ours.ContextOptions.Negotiate |
                    Ours.ContextOptions.Signing |
                    Ours.ContextOptions.Sealing))
            .Assert();
    }

    [Fact]
    public void PrincipalContext_default_domain_options_agree()
    {
        using var msContext = new Ms.PrincipalContext(
            Ms.ContextType.Domain,
            DifferentialSettings.Host,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(
            Ours.ContextType.Domain,
            DifferentialSettings.Host,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

        Assert.Equal((int)msContext.Options, (int)ourContext.Options);
        Assert.Equal(
            Ms.ContextOptions.Negotiate |
            Ms.ContextOptions.Signing |
            Ms.ContextOptions.Sealing,
            msContext.Options);
    }

    [Theory]
    [InlineData(0)]
    [InlineData((int)(Ms.ContextOptions.Negotiate | Ms.ContextOptions.SimpleBind))]
    public void ValidateCredentials_explicit_edge_options_agree(int rawOptions)
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        var upn = $"{_data.UserName}@{DomainSuffix()}";

        Assert.Equal(
            CredentialValidationOutcome(() => msContext.ValidateCredentials(
                upn, _data.UserPassword, (Ms.ContextOptions)rawOptions)),
            CredentialValidationOutcome(() => ourContext.ValidateCredentials(
                upn, _data.UserPassword, (Ours.ContextOptions)rawOptions)));
    }

    private static string CredentialValidationOutcome(Func<bool> validation)
    {
        try
        {
            return $"Result:{validation()}";
        }
        catch (Exception exception)
        {
            return $"Exception:{exception.GetType().Name}";
        }
    }

    private static string DomainSuffix() =>
        string.Join(".", DifferentialSettings.BaseDn
            .Split(',')
            .Select(part => part.Trim())
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part.Substring(3)));
}
