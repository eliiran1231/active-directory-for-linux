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

    public PrincipalSearcherComparisonTests(TestDataFixture data)
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
}
