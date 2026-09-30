using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PrincipalSearchResultLivePositionComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public PrincipalSearchResultLivePositionComparisonTests(TestDataFixture data) => _data = data;

    [Theory]
    [InlineData("before-start", false)]
    [InlineData("after-end", false)]
    [InlineData("after-reset", false)]
    [InlineData("before-start", true)]
    [InlineData("after-end", true)]
    [InlineData("after-reset", true)]
    public void FindAll_Current_matches_position_validation(string position, bool nonGeneric)
    {
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var microsoftQuery = new Ms.UserPrincipal(microsoftContext) { SamAccountName = _data.UserName };
        using var ourQuery = new Ours.UserPrincipal(ourContext) { SamAccountName = _data.UserName };
        using var microsoftSearcher = new Ms.PrincipalSearcher(microsoftQuery);
        using var ourSearcher = new Ours.PrincipalSearcher(ourQuery);
        using var microsoftResults = microsoftSearcher.FindAll();
        using var ourResults = ourSearcher.FindAll();
        using var expectedEnumerator = microsoftResults.GetEnumerator();
        using var actualEnumerator = ourResults.GetEnumerator();

        // Capture the initial state but verify a real matching row before
        // asserting parity, so an empty query cannot masquerade as this test.
        var expected = PrincipalSearchResultPositionComparisonTests.ObserveCurrent(expectedEnumerator, nonGeneric);
        var actual = PrincipalSearchResultPositionComparisonTests.ObserveCurrent(actualEnumerator, nonGeneric);
        Assert.True(expectedEnumerator.MoveNext());
        Assert.True(actualEnumerator.MoveNext());
        using var microsoftUser = expectedEnumerator.Current;
        using var ourUser = actualEnumerator.Current;
        Assert.NotNull(microsoftUser);
        Assert.NotNull(ourUser);
        Assert.Equal(_data.UserName, microsoftUser.SamAccountName);
        Assert.Equal(microsoftUser.SamAccountName, ourUser.SamAccountName);
        Assert.False(expectedEnumerator.MoveNext());
        Assert.False(actualEnumerator.MoveNext());

        if (position == "after-reset")
        {
            expectedEnumerator.Reset();
            actualEnumerator.Reset();
        }
        if (position != "before-start")
        {
            expected = PrincipalSearchResultPositionComparisonTests.ObserveCurrent(expectedEnumerator, nonGeneric);
            actual = PrincipalSearchResultPositionComparisonTests.ObserveCurrent(actualEnumerator, nonGeneric);
        }

        Assert.Equal(typeof(InvalidOperationException), expected.Error);
        Assert.Equal(expected, actual);
    }
}
