using System.Collections;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using AccountMatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public class AccountManagementPublicTypesTests
{
    private static PrincipalContext OfflineContext() =>
        new(ContextType.Domain, "dc.example.test", "DC=example,DC=test");

    [Fact]
    public void Computer_principal_exposes_a_mutable_service_principal_name_collection()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context);
        var values = computer.ServicePrincipalNames;

        values.Add("HOST/server.example.test");
        values.Insert(0, "RestrictedKrbHost/server.example.test");
        IList list = values;
        var returnedIndex = list.Add("TERMSRV/server.example.test");

        Assert.Equal(2, returnedIndex);
        Assert.Equal(3, values.Count);
        Assert.Equal("RestrictedKrbHost/server.example.test", values[0]);
        Assert.False(values.IsFixedSize);
        Assert.False(values.IsReadOnly);
        Assert.False(values.IsSynchronized);
        Assert.Same(values, values.SyncRoot);
    }

    [Fact]
    public void Authenticable_principal_issue_8_values_can_be_staged_offline()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        var hours = Enumerable.Range(0, 21).Select(value => (byte)value).ToArray();

        user.AllowReversiblePasswordEncryption = true;
        user.SmartcardLogonRequired = true;
        user.PermittedLogonTimes = hours;
        user.PermittedWorkstations.Add("DESK01");
        user.PermittedWorkstations.Add("DESK02");
        user.UserCannotChangePassword = true;
        user.SetPassword("Str0ng!Passw0rd#2026");
        user.ExpirePasswordNow();
        user.RefreshExpiredPassword();

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=offline-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        user.Certificates.Add(certificate);

        Assert.True(user.AllowReversiblePasswordEncryption);
        Assert.True(user.SmartcardLogonRequired);
        Assert.Same(hours, user.PermittedLogonTimes);
        Assert.Equal(new[] { "DESK01", "DESK02" }, user.PermittedWorkstations);
        Assert.True(user.UserCannotChangePassword);
        Assert.Single(user.Certificates);
        Assert.Throws<InvalidOperationException>(() => user.ChangePassword("old", "new"));
        Assert.Throws<ArgumentNullException>(() => user.SetPassword(null!));
        Assert.Throws<ArgumentNullException>(() => user.ChangePassword(null!, "new"));
        Assert.Throws<ArgumentNullException>(() => user.ChangePassword("old", null!));
    }

    [Fact]
    public void Computer_principal_password_members_match_microsoft_offline_behavior()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context);

        Assert.False(computer.UserCannotChangePassword);
        computer.UserCannotChangePassword = true;
        Assert.True(computer.UserCannotChangePassword);
        Assert.Throws<InvalidOperationException>(() => computer.ChangePassword("old", "new"));
    }

    [Fact]
    public void Advanced_filters_are_included_in_query_by_example_ldap()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context) { SamAccountName = "server$" };
        var when = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        computer.AdvancedSearchFilter.LastLogonTime(when, AccountMatchType.GreaterThan);

        using var searcher = new PrincipalSearcher(computer);
        var ticks = when.ToFileTimeUtc();

        Assert.Equal(
            $"(&(objectCategory=computer)(sAMAccountName=server$)(|(&(&(lastLogon>={ticks})(!(lastLogon={ticks}))(lastLogon=*))(!(lastLogon=0)))(&(&(lastLogonTimestamp>={ticks})(!(lastLogonTimestamp={ticks}))(lastLogonTimestamp=*))(!(lastLogonTimestamp=0)))))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void User_principal_issue_9_surface_is_complete()
    {
        var type = typeof(UserPrincipal);
        var expectedFinderNames = new[]
        {
            nameof(UserPrincipal.FindByBadPasswordAttempt),
            nameof(UserPrincipal.FindByExpirationTime),
            nameof(UserPrincipal.FindByLockoutTime),
            nameof(UserPrincipal.FindByLogonTime),
            nameof(UserPrincipal.FindByPasswordSetTime),
        };

        Assert.NotNull(type.GetConstructor(new[]
        {
            typeof(PrincipalContext), typeof(string), typeof(string), typeof(bool),
        }));
        Assert.Equal(type, type.GetProperty(nameof(UserPrincipal.Current))!.PropertyType);

        foreach (var methodName in expectedFinderNames)
        {
            var method = type.GetMethod(methodName, new[]
            {
                typeof(PrincipalContext), typeof(DateTime), typeof(AccountMatchType),
            });
            Assert.NotNull(method);
            Assert.Equal(typeof(PrincipalSearchResult<UserPrincipal>), method!.ReturnType);
        }
    }

    [Fact]
    public void Current_fails_explicitly_when_linux_cannot_discover_a_domain_identity()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => UserPrincipal.Current);
        Assert.Contains("FindByIdentity", exception.Message);
    }

    [Fact]
    public void Date_filters_match_microsoft_default_and_last_logon_semantics()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        var when = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var ticks = when.ToFileTimeUtc();

        user.AdvancedSearchFilter.LastBadPasswordAttempt(when, AccountMatchType.LessThan);
        user.AdvancedSearchFilter.LastLogonTime(when, AccountMatchType.NotEquals);
        user.AdvancedSearchFilter.LastPasswordSetTime(when, AccountMatchType.GreaterThanOrEquals);

        using var searcher = new PrincipalSearcher(user);
        Assert.Equal(
            $"(&(objectCategory=person)(objectClass=user)(&(badPasswordTime<={ticks})(!(badPasswordTime={ticks}))(badPasswordTime=*))(|(!(lastLogon={ticks}))(&(!(lastLogonTimestamp={ticks}))(lastLogonTimestamp=*)))(pwdLastSet>={ticks}))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void Date_finders_validate_context_before_match_type()
    {
        var invalid = (AccountMatchType)int.MaxValue;
        var when = DateTime.UtcNow;

        Assert.Throws<ArgumentNullException>(
            () => UserPrincipal.FindByLogonTime(null!, when, invalid));

        using var context = OfflineContext();
        Assert.Throws<System.ComponentModel.InvalidEnumArgumentException>(
            () => UserPrincipal.FindByLogonTime(context, when, invalid));
    }

    [Fact]
    public void Every_match_type_has_the_microsoft_numeric_value()
    {
        Assert.Equal(new[] { 0, 1, 2, 3, 4, 5 },
            Enum.GetValues<AccountMatchType>().Select(value => (int)value));
    }

    [Fact]
    public void Directory_mapping_attributes_expose_the_compatible_contract()
    {
        var property = new DirectoryPropertyAttribute("extensionAttribute1")
        {
            Context = ContextType.Domain,
        };
        var objectClass = new DirectoryObjectClassAttribute("customPerson");
        var rdn = new DirectoryRdnPrefixAttribute("CN");

        Assert.Equal("extensionAttribute1", property.SchemaAttributeName);
        Assert.Null(property.Context);
        Assert.Equal("customPerson", objectClass.ObjectClass);
        Assert.Null(objectClass.Context);
        Assert.Equal("CN", rdn.RdnPrefix);
        Assert.Null(rdn.Context);
        Assert.True(typeof(DirectoryPropertyAttribute).GetCustomAttribute<AttributeUsageAttribute>()!.AllowMultiple);
    }

    [Fact]
    public void Principal_exception_hierarchy_preserves_messages_causes_and_error_codes()
    {
        var cause = new InvalidOperationException("cause");
        PrincipalException operation = new PrincipalOperationException("failed", cause, 49);

        Assert.IsAssignableFrom<SystemException>(operation);
        Assert.Equal("failed", operation.Message);
        Assert.Same(cause, operation.InnerException);
        Assert.Equal(49, Assert.IsType<PrincipalOperationException>(operation).ErrorCode);
        Assert.IsAssignableFrom<PrincipalException>(new MultipleMatchesException());
        Assert.IsAssignableFrom<PrincipalException>(new NoMatchingPrincipalException());
        Assert.IsAssignableFrom<PrincipalException>(new PasswordException());
        Assert.IsAssignableFrom<PrincipalException>(new PrincipalExistsException());
        Assert.IsAssignableFrom<PrincipalException>(new PrincipalServerDownException());
    }
}
