using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// These setter-only comparisons never access SearchRoot or contact a server.
public sealed class SearcherValidationContractComparisonTests
{
    [Theory]
    [InlineData("SizeLimit")]
    [InlineData("AttributeScopeQuery")]
    [InlineData("SearchScope")]
    public void Rejected_setter_matches_exception_parameter_and_preserves_state(string property)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        Action microsoftAction;
        Action ourAction;
        switch (property)
        {
            case "SizeLimit":
                microsoft.SizeLimit = ours.SizeLimit = 12;
                microsoftAction = () => microsoft.SizeLimit = -1;
                ourAction = () => ours.SizeLimit = -1;
                break;
            case "AttributeScopeQuery":
                microsoft.SearchScope = Ms.SearchScope.OneLevel;
                ours.SearchScope = Ours.SearchScope.OneLevel;
                microsoftAction = () => microsoft.AttributeScopeQuery = "member";
                ourAction = () => ours.AttributeScopeQuery = "member";
                break;
            case "SearchScope":
                microsoft.AttributeScopeQuery = ours.AttributeScopeQuery = "member";
                microsoftAction = () => microsoft.SearchScope = Ms.SearchScope.Subtree;
                ourAction = () => ours.SearchScope = Ours.SearchScope.Subtree;
                break;
            default: throw new ArgumentOutOfRangeException(nameof(property));
        }

        var expected = Record.Exception(microsoftAction);
        var actual = Record.Exception(ourAction);

        Assert.Equal(microsoft.SizeLimit, ours.SizeLimit);
        Assert.Equal(microsoft.AttributeScopeQuery, ours.AttributeScopeQuery);
        Assert.Equal((int)microsoft.SearchScope, (int)ours.SearchScope);
        var expectedArgument = Assert.IsType<ArgumentException>(expected);
        var actualArgument = Assert.IsType<ArgumentException>(actual);
        Assert.Equal(expectedArgument.ParamName, actualArgument.ParamName);
    }
}
