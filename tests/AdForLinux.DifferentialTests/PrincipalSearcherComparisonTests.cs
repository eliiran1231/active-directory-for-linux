using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Compares query-by-example searching between the real Microsoft library and
/// our clone.
/// </summary>
[Collection("differential")]
public class PrincipalSearcherComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    private sealed class MicrosoftExtensionUser : Ms.UserPrincipal
    {
        public MicrosoftExtensionUser(Ms.PrincipalContext context) : base(context) { }
        public void Write(string attribute, object? value) => ExtensionSet(attribute, value!);
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    private sealed class OurExtensionUser : Ours.UserPrincipal
    {
        public OurExtensionUser(Ours.PrincipalContext context) : base(context) { }
        public void Write(string attribute, object? value) => ExtensionSet(attribute, value);
    }

    public PrincipalSearcherComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    [Fact]
    public void FindOne_by_sam_account_name_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.UserPrincipal(msContext) { SamAccountName = _data.UserName });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.UserPrincipal(ourContext) { SamAccountName = _data.UserName });

        var ms = msSearcher.FindOne();
        var ours = ourSearcher.FindOne();

        new Comparison("PrincipalSearcher.FindOne")
            .Check("found", ms is not null, ours is not null)
            .Check("DistinguishedName", ms?.DistinguishedName, ours?.DistinguishedName)
            .Check("type is user", ms is Ms.UserPrincipal, ours is Ours.UserPrincipal)
            .Assert();

        ms?.Dispose();
        ours?.Dispose();
    }

    [Fact]
    public void FindAll_with_a_wildcard_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        // Matches the seeded user and nothing else.
        var pattern = $"{_data.UserName.Substring(0, _data.UserName.Length - 2)}*";

        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.UserPrincipal(msContext) { SamAccountName = pattern });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.UserPrincipal(ourContext) { SamAccountName = pattern });

        using var msResults = msSearcher.FindAll();
        using var ourResults = ourSearcher.FindAll();

        new Comparison($"PrincipalSearcher.FindAll for {pattern}")
            .CheckSet("DNs",
                msResults.Select(p => p.DistinguishedName),
                ourResults.Select(p => p.DistinguishedName))
            .Assert();
    }

    [Fact]
    public void FindAll_for_groups_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var pattern = $"{_data.GroupName.Substring(0, _data.GroupName.Length - 2)}*";

        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.GroupPrincipal(msContext) { SamAccountName = pattern });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.GroupPrincipal(ourContext) { SamAccountName = pattern });

        using var msResults = msSearcher.FindAll();
        using var ourResults = ourSearcher.FindAll();

        new Comparison($"group search for {pattern}")
            .CheckSet("DNs",
                msResults.Select(p => p.DistinguishedName),
                ourResults.Select(p => p.DistinguishedName))
            .Assert();
    }

    [Fact]
    public void FindOne_agrees_when_nothing_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.UserPrincipal(msContext) { SamAccountName = "no-such-user-xyz-123" });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.UserPrincipal(ourContext) { SamAccountName = "no-such-user-xyz-123" });

        new Comparison("no match")
            .Check("found", msSearcher.FindOne() is not null, ourSearcher.FindOne() is not null)
            .Assert();
    }

    [Fact]
    public void Underlying_searcher_customization_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.UserPrincipal(msContext) { SamAccountName = _data.UserName });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.UserPrincipal(ourContext) { SamAccountName = _data.UserName });

        var msUnderlying = Assert.IsType<System.DirectoryServices.DirectorySearcher>(
            msSearcher.GetUnderlyingSearcher());
        var ourUnderlying = Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(
            ourSearcher.GetUnderlyingSearcher());

        new Comparison("PrincipalSearcher underlying searcher defaults")
            .Check("type name",
                msSearcher.GetUnderlyingSearcherType().Name,
                ourSearcher.GetUnderlyingSearcherType().Name)
            .Check("PageSize", msUnderlying.PageSize, ourUnderlying.PageSize)
            .Check("ServerTimeLimit", msUnderlying.ServerTimeLimit, ourUnderlying.ServerTimeLimit)
            .Assert();

        msUnderlying.PageSize = 1;
        msUnderlying.SizeLimit = 1;
        ourUnderlying.PageSize = 1;
        ourUnderlying.SizeLimit = 1;

        using var msResults = msSearcher.FindAll();
        using var ourResults = ourSearcher.FindAll();
        new Comparison("PrincipalSearcher caller customization")
            .CheckSet("DNs",
                msResults.Select(principal => principal.DistinguishedName),
                ourResults.Select(principal => principal.DistinguishedName))
            .Check("retained PageSize", msUnderlying.PageSize, ourUnderlying.PageSize)
            .Check("retained SizeLimit", msUnderlying.SizeLimit, ourUnderlying.SizeLimit)
            .Assert();
    }

    [Fact]
    public void Replacing_query_filter_updates_context_like_microsoft()
    {
        using var firstMsContext = MicrosoftContext();
        using var secondMsContext = MicrosoftContext();
        using var firstOurContext = OurContext();
        using var secondOurContext = OurContext();
        using var msSearcher = new Ms.PrincipalSearcher(
            new Ms.UserPrincipal(firstMsContext) { SamAccountName = _data.UserName });
        using var ourSearcher = new Ours.PrincipalSearcher(
            new Ours.UserPrincipal(firstOurContext) { SamAccountName = _data.UserName });

        msSearcher.QueryFilter = new Ms.UserPrincipal(secondMsContext)
        {
            SamAccountName = _data.UserName,
        };
        ourSearcher.QueryFilter = new Ours.UserPrincipal(secondOurContext)
        {
            SamAccountName = _data.UserName,
        };

        Assert.Same(secondMsContext, msSearcher.Context);
        Assert.NotSame(firstMsContext, msSearcher.Context);
        Assert.Same(secondOurContext, ourSearcher.Context);
        Assert.NotSame(firstOurContext, ourSearcher.Context);

        new Comparison("PrincipalSearcher replacement filter context")
            .Check("uses replacement context",
                ReferenceEquals(secondMsContext, msSearcher.Context),
                ReferenceEquals(secondOurContext, ourSearcher.Context))
            .Check("retains original context",
                ReferenceEquals(firstMsContext, msSearcher.Context),
                ReferenceEquals(firstOurContext, ourSearcher.Context))
            .Assert();
    }

    [Fact]
    public void Persisted_query_filter_is_rejected_like_microsoft()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msPersisted = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourPersisted = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);
        Assert.NotNull(msPersisted);
        Assert.NotNull(ourPersisted);

        var microsoftException = Record.Exception(
            () => new Ms.PrincipalSearcher(msPersisted!));
        var ourException = Record.Exception(
            () => new Ours.PrincipalSearcher(ourPersisted!));

        Assert.NotNull(microsoftException);
        Assert.NotNull(ourException);
        Assert.Equal(microsoftException!.GetType().Name, ourException!.GetType().Name);
        Assert.IsType<ArgumentException>(microsoftException);
        Assert.IsType<ArgumentException>(ourException);
    }

    [Theory]
    [InlineData("Enabled", true)]
    [InlineData("Enabled", false)]
    [InlineData("SmartcardLogonRequired", true)]
    [InlineData("SmartcardLogonRequired", false)]
    [InlineData("DelegationPermitted", true)]
    [InlineData("DelegationPermitted", false)]
    [InlineData("PasswordNotRequired", true)]
    [InlineData("PasswordNotRequired", false)]
    [InlineData("PasswordNeverExpires", true)]
    [InlineData("PasswordNeverExpires", false)]
    [InlineData("AllowReversiblePasswordEncryption", true)]
    [InlineData("AllowReversiblePasswordEncryption", false)]
    public void User_account_control_QBE_filters_match(string property, bool value)
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var ms = new Ms.UserPrincipal(msContext);
        using var ours = new Ours.UserPrincipal(ourContext);

        switch (property)
        {
            case "Enabled": ms.Enabled = value; ours.Enabled = value; break;
            case "SmartcardLogonRequired": ms.SmartcardLogonRequired = value; ours.SmartcardLogonRequired = value; break;
            case "DelegationPermitted": ms.DelegationPermitted = value; ours.DelegationPermitted = value; break;
            case "PasswordNotRequired": ms.PasswordNotRequired = value; ours.PasswordNotRequired = value; break;
            case "PasswordNeverExpires": ms.PasswordNeverExpires = value; ours.PasswordNeverExpires = value; break;
            case "AllowReversiblePasswordEncryption":
                ms.AllowReversiblePasswordEncryption = value;
                ours.AllowReversiblePasswordEncryption = value;
                break;
            default: throw new InvalidOperationException(property);
        }

        CompareQuery($"{property}={value}", ms, ours);
    }

    [Fact]
    public void Unsupported_user_cannot_change_password_QBE_exception_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var ms = new Ms.UserPrincipal(msContext) { UserCannotChangePassword = true };
        using var ours = new Ours.UserPrincipal(ourContext) { UserCannotChangePassword = true };
        CompareQuery("UserCannotChangePassword", ms, ours);
    }

    [Theory]
    [InlineData("Local", true)]
    [InlineData("Global", true)]
    [InlineData("Universal", true)]
    [InlineData("Global", false)]
    public void Group_QBE_filters_match(string scope, bool security)
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var ms = new Ms.GroupPrincipal(msContext)
        {
            GroupScope = Enum.Parse<Ms.GroupScope>(scope),
            IsSecurityGroup = security,
        };
        using var ours = new Ours.GroupPrincipal(ourContext)
        {
            GroupScope = Enum.Parse<Ours.GroupScope>(scope),
            IsSecurityGroup = security,
        };
        CompareQuery($"GroupScope={scope}, IsSecurityGroup={security}", ms, ours);
    }

    [Fact]
    public void Account_expiration_and_null_QBE_filters_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using (var ms = new Ms.UserPrincipal(msContext) { AccountExpirationDate = _data.UserExpirationTime })
        using (var ours = new Ours.UserPrincipal(ourContext) { AccountExpirationDate = _data.UserExpirationTime })
        {
            CompareQuery("AccountExpirationDate value", ms, ours);
        }

        using (var ms = new Ms.UserPrincipal(msContext) { AccountExpirationDate = null })
        using (var ours = new Ours.UserPrincipal(ourContext) { AccountExpirationDate = null })
        {
            CompareQuery("AccountExpirationDate null", ms, ours);
        }
    }

    [Fact]
    public void Certificate_logon_workstation_and_SPN_QBE_filters_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=adfl-qbe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        using (var ms = new Ms.UserPrincipal(msContext))
        using (var ours = new Ours.UserPrincipal(ourContext))
        {
            ms.Certificates.Add(certificate);
            ours.Certificates.Add(certificate);
            CompareQuery("Certificates", ms, ours);
        }

        using (var ms = new Ms.UserPrincipal(msContext) { PermittedLogonTimes = new byte[] { 0x01, 0x80 } })
        using (var ours = new Ours.UserPrincipal(ourContext) { PermittedLogonTimes = new byte[] { 0x01, 0x80 } })
        {
            CompareQuery("PermittedLogonTimes", ms, ours);
        }

        using (var ms = new Ms.UserPrincipal(msContext))
        using (var ours = new Ours.UserPrincipal(ourContext))
        {
            ms.PermittedWorkstations.Add("DESK01");
            ms.PermittedWorkstations.Add("DESK02");
            ours.PermittedWorkstations.Add("DESK01");
            ours.PermittedWorkstations.Add("DESK02");
            CompareQuery("PermittedWorkstations", ms, ours);
        }

        using (var ms = new Ms.ComputerPrincipal(msContext))
        using (var ours = new Ours.ComputerPrincipal(ourContext))
        {
            ms.ServicePrincipalNames.Add("HOST/adfl-qbe.example.test");
            ours.ServicePrincipalNames.Add("HOST/adfl-qbe.example.test");
            CompareQuery("ServicePrincipalNames", ms, ours);
        }
    }

    [Fact]
    public void Null_and_cleared_high_value_QBE_properties_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using (var ms = new Ms.UserPrincipal(msContext))
        using (var ours = new Ours.UserPrincipal(ourContext))
        {
            Assert.Equal(
                Record.Exception(() => ms.Enabled = null)?.GetType().Name,
                Record.Exception(() => ours.Enabled = null)?.GetType().Name);
            ms.PermittedLogonTimes = null;
            ours.PermittedLogonTimes = null;
            CompareQuery("null PermittedLogonTimes", ms, ours);
        }

        using (var ms = new Ms.UserPrincipal(msContext))
        using (var ours = new Ours.UserPrincipal(ourContext))
        {
            ms.PermittedWorkstations.Add("DESK01");
            ours.PermittedWorkstations.Add("DESK01");
            ms.PermittedWorkstations.Clear();
            ours.PermittedWorkstations.Clear();
            CompareQuery("cleared PermittedWorkstations", ms, ours);
        }

        using (var ms = new Ms.ComputerPrincipal(msContext))
        using (var ours = new Ours.ComputerPrincipal(ourContext))
        {
            ms.ServicePrincipalNames.Add("HOST/temporary");
            ours.ServicePrincipalNames.Add("HOST/temporary");
            ms.ServicePrincipalNames.Clear();
            ours.ServicePrincipalNames.Clear();
            CompareQuery("cleared ServicePrincipalNames", ms, ours);
        }

        using (var ms = new Ms.GroupPrincipal(msContext))
        using (var ours = new Ours.GroupPrincipal(ourContext))
        {
            Assert.Equal(
                Record.Exception(() => ms.GroupScope = null)?.GetType().Name,
                Record.Exception(() => ours.GroupScope = null)?.GetType().Name);
            Assert.Equal(
                Record.Exception(() => ms.IsSecurityGroup = null)?.GetType().Name,
                Record.Exception(() => ours.IsSecurityGroup = null)?.GetType().Name);
        }
    }

    [Fact]
    public void Extension_QBE_converters_and_null_behavior_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        foreach (var (label, value) in new (string, object?)[]
                 {
                     ("string", "differential test user"),
                     ("bool", true),
                     ("DateTime", _data.UserExpirationTime),
                     ("collection", new object[] { "one", "two" }),
                     ("byte collection", new byte[] { 1, 2 }),
                     ("null", null),
                 })
        {
            using var ms = new MicrosoftExtensionUser(msContext);
            using var ours = new OurExtensionUser(ourContext);
            var msSetError = Record.Exception(() => ms.Write("extensionAttribute1", value));
            var ourSetError = Record.Exception(() => ours.Write("extensionAttribute1", value));
            new Comparison($"extension {label} assignment")
                .Check("exception", msSetError?.GetType().Name, ourSetError?.GetType().Name)
                .Assert();
            if (msSetError is not null || ourSetError is not null)
            {
                continue;
            }

            CompareQuery($"extension {label}", ms, ours);
        }
    }

    private static void CompareQuery(string label, Ms.Principal msFilter, Ours.Principal ourFilter)
    {
        using var msSearcher = new Ms.PrincipalSearcher(msFilter);
        using var ourSearcher = new Ours.PrincipalSearcher(ourFilter);
        string? msLdap = null;
        string? ourLdap = null;
        var msError = Record.Exception(() =>
            msLdap = Assert.IsType<System.DirectoryServices.DirectorySearcher>(
                msSearcher.GetUnderlyingSearcher()).Filter);
        var ourError = Record.Exception(() => ourLdap = ourSearcher.GetLdapFilter());

        new Comparison($"{label} QBE translation")
            .Check("exception", msError?.GetType().Name, ourError?.GetType().Name)
            .Check("LDAP filter", msLdap, ourLdap)
            .Assert();
        if (msError is not null || ourError is not null)
        {
            return;
        }

        using var msResults = msSearcher.FindAll();
        using var ourResults = ourSearcher.FindAll();
        new Comparison($"{label} QBE results")
            .CheckSet("DNs",
                msResults.Select(principal => principal.DistinguishedName),
                ourResults.Select(principal => principal.DistinguishedName))
            .Assert();
    }
}
