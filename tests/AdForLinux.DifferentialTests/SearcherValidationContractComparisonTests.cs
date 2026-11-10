using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// These setter-only comparisons never access SearchRoot or contact a server.
public sealed partial class SearcherValidationContractComparisonTests
{
    [Theory]
    [InlineData("SizeLimit")]
    [InlineData("PageSize")]
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
            case "PageSize":
                microsoft.PageSize = ours.PageSize = 12;
                microsoftAction = () => microsoft.PageSize = -1;
                ourAction = () => ours.PageSize = -1;
                break;
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

        Assert.Equal(SuiteCapture.Expected(microsoft.SizeLimit, "assert-equal-expected", 50), SuiteCapture.Expected(ours.SizeLimit, "assert-equal-actual", 50));
        Assert.Equal(SuiteCapture.Expected(microsoft.PageSize, "assert-equal-expected", 51), SuiteCapture.Expected(ours.PageSize, "assert-equal-actual", 51));
        Assert.Equal(SuiteCapture.Expected(microsoft.AttributeScopeQuery, "assert-equal-expected", 52), SuiteCapture.Expected(ours.AttributeScopeQuery, "assert-equal-actual", 52));
        Assert.Equal(SuiteCapture.Expected((int)microsoft.SearchScope, "assert-equal-expected", 53), SuiteCapture.Expected((int)ours.SearchScope, "assert-equal-actual", 53));
        var expectedArgument = Assert.IsType<ArgumentException>(expected);
        var actualArgument = Assert.IsType<ArgumentException>(actual);
        Assert.Equal(SuiteCapture.Expected(expectedArgument.ParamName, "assert-equal-expected", 56), SuiteCapture.Expected(actualArgument.ParamName, "assert-equal-actual", 56));
    }
}
