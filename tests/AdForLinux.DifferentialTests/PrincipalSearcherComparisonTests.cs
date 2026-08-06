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
}
