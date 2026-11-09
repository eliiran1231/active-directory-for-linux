using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using MatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;
using SearchScope = AdForLinux.DirectoryServices.SearchScope;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private static PrincipalContext ReferralContext(bool restricted) => restricted
        ? RestrictedKerberosContext.Create(RestrictedRecipe(), "DC=example,DC=invalid")
        : new PrincipalContext(ContextType.Domain, "directory.invalid", "DC=example,DC=invalid");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Context_search_factory_preserves_scope_projection_and_selected_referrals(bool restricted)
    {
        using var context = ReferralContext(restricted);
        using var root = context.CreateDirectoryEntry("OU=people,DC=example,DC=invalid");
        using var searcher = context.CreateSearcher(root, "(objectClass=user)", ["objectSid", "description"], SearchScope.OneLevel);
        Assert.IsType<DirectorySearcher>(searcher);
        Assert.Same(root, searcher.SearchRoot);
        Assert.Equal("(objectClass=user)", searcher.Filter);
        Assert.Equal(SearchScope.OneLevel, searcher.SearchScope);
        Assert.Equal(new[] { "objectSid", "description" }, searcher.PropertiesToLoad.Cast<string>());
        Assert.Equal(restricted ? ReferralChasingOption.None : ReferralChasingOption.External, searcher.ReferralChasing);
        using var raw = new DirectorySearcher(root);
        Assert.Equal(ReferralChasingOption.External, raw.ReferralChasing); // public default is unchanged
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public void Context_search_factory_preserves_explicit_scope_validation(bool restricted, bool explicitScope)
    {
        using var context = ReferralContext(restricted);
        using var root = context.CreateDirectoryEntry("DC=example,DC=invalid");
        using var searcher = explicitScope
            ? context.CreateSearcher(root, "(objectClass=*)", ["member"], SearchScope.Subtree)
            : context.CreateSearcher(root, "(objectClass=*)", ["member"]);
        if (explicitScope)
            Assert.Throws<ArgumentException>(() => searcher.AttributeScopeQuery = "member");
        else
        {
            searcher.AttributeScopeQuery = "member";
            Assert.Equal(SearchScope.Base, searcher.SearchScope);
        }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Exposed_principal_searcher_keeps_implicit_scope_for_attribute_query(bool restricted)
    {
        using var context = ReferralContext(restricted);
        using var query = new GroupPrincipal(context) { SamAccountName = "synthetic" };
        using var principalSearcher = new PrincipalSearcher(query);
        var searcher = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        searcher.AttributeScopeQuery = "member";
        Assert.Equal(SearchScope.Base, searcher.SearchScope);
        Assert.Same(searcher, principalSearcher.GetUnderlyingSearcher());
        Assert.Equal("member", searcher.AttributeScopeQuery);
        Assert.Equal(SearchScope.Base, searcher.SearchScope);
    }

    [Theory]
    [InlineData(false, "user", false)] [InlineData(true, "user", false)]
    [InlineData(false, "group", false)] [InlineData(true, "group", false)]
    [InlineData(false, "computer", false)] [InlineData(true, "computer", false)]
    [InlineData(false, "user", true)] [InlineData(true, "user", true)]
    [InlineData(false, "group", true)] [InlineData(true, "group", true)]
    [InlineData(false, "computer", true)] [InlineData(true, "computer", true)]
    public void Principal_search_admission_uses_context_policy_and_preserves_caller_override(bool restricted, string kind, bool callerOverride)
    {
        using var context = ReferralContext(restricted);
        using Principal query = kind switch
        {
            "user" => new UserPrincipal(context),
            "group" => new GroupPrincipal(context),
            _ => new ComputerPrincipal(context),
        };
        query.SamAccountName = "synthetic";
        using var principalSearcher = new PrincipalSearcher(query);
        var searcher = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        var expected = restricted ? ReferralChasingOption.None : ReferralChasingOption.External;
        Assert.Equal(expected, searcher.ReferralChasing);
        Assert.Equal(256, searcher.PageSize);
        Assert.Equal(TimeSpan.FromSeconds(30), searcher.ServerTimeLimit);
        if (callerOverride) searcher.ReferralChasing = ReferralChasingOption.All;
        Assert.Same(searcher, principalSearcher.GetUnderlyingSearcher());
        Assert.Equal(callerOverride ? ReferralChasingOption.All : expected, searcher.ReferralChasing);

        var admissions = new List<ReferralChasingOption>();
        var observedSearch = new InvalidOperationException("Synthetic search admission reached.");
        searcher.SearchRoot!.OperationSessionFactory = (options, count, referrals, _, _) =>
        {
            admissions.Add(referrals);
            if (admissions.Count > 1) throw observedSearch;
            Assert.Equal(1, count); // Controlled base lookup before actual search admission.
            var transport = new RecordingTransport
            {
                Reply = command => new(ResultCode.Success, "", null,
                    [new(command.BaseDn, new(StringComparer.OrdinalIgnoreCase), [])], [], [], []),
            };
            return LdapRestrictedOperation.Wrap([transport], transport, options);
        };
        Assert.Same(observedSearch, Assert.Throws<InvalidOperationException>(() => principalSearcher.FindAll()));
        Assert.Equal(new[] { expected, callerOverride ? ReferralChasingOption.All : expected }, admissions);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Date_finder_searches_inherit_context_referral_policy(bool restricted)
    {
        using var context = ReferralContext(restricted);
        var count = 0;
        context.DateFinderSearchOverride = searcher =>
        {
            count++;
            Assert.Equal(restricted ? ReferralChasingOption.None : ReferralChasingOption.External, searcher.ReferralChasing);
            Assert.Equal(500, searcher.PageSize);
            Assert.Contains("pwdLastSet", searcher.Filter);
            return new SearchResultCollection(Array.Empty<SearchResult>());
        };
        using var users = UserPrincipal.FindByPasswordSetTime(context, new DateTime(2024, 1, 1), MatchType.GreaterThan);
        using var computers = ComputerPrincipal.FindByPasswordSetTime(context, new DateTime(2024, 1, 1), MatchType.GreaterThan);
        using var accounts = AuthenticablePrincipal.FindByPasswordSetTime(context, new DateTime(2024, 1, 1), MatchType.GreaterThan);
        Assert.Empty(users); Assert.Empty(computers); Assert.Empty(accounts);
        Assert.Equal(3, count);
    }
}
