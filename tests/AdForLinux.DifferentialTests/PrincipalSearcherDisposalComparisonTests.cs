using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Public constructors only: these cases never create a context or contact AD.
public class PrincipalSearcherDisposalComparisonTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void QueryFilter_getter_matches_microsoft_after_disposal(bool dispose)
    {
        using var microsoft = new Ms.PrincipalSearcher();
        using var ours = new Ours.PrincipalSearcher();
        Assert.Null(microsoft.QueryFilter);
        Assert.Null(ours.QueryFilter);

        if (dispose)
        {
            microsoft.Dispose();
            ours.Dispose();
        }

        var expected = Record.Exception(() => { _ = microsoft.QueryFilter; });
        var actual = Record.Exception(() => { _ = ours.QueryFilter; });
        Assert.Equal(expected?.GetType(), actual?.GetType());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Null_QueryFilter_validation_precedence_matches_microsoft(bool dispose)
    {
        using var microsoft = new Ms.PrincipalSearcher();
        using var ours = new Ours.PrincipalSearcher();
        if (dispose)
        {
            microsoft.Dispose();
            ours.Dispose();
        }

        var expected = Record.Exception(() => microsoft.QueryFilter = null!);
        var actual = Record.Exception(() => ours.QueryFilter = null!);
        Assert.NotNull(expected);
        Assert.NotNull(actual);
        Assert.Equal(expected.GetType(), actual.GetType());
        Assert.Equal((expected as ArgumentException)?.ParamName,
            (actual as ArgumentException)?.ParamName);
    }

    [Theory]
    [InlineData("Context")]
    [InlineData("FindOne")]
    [InlineData("FindAll")]
    [InlineData("GetUnderlyingSearcher")]
    [InlineData("GetUnderlyingSearcherType")]
    public void Other_members_reject_disposed_searchers_like_microsoft(string member)
    {
        using var microsoft = new Ms.PrincipalSearcher();
        using var ours = new Ours.PrincipalSearcher();
        microsoft.Dispose();
        ours.Dispose();

        // These controls also ensure no context discovery can occur.
        Action expected = member switch
        {
            "Context" => () => { _ = microsoft.Context; },
            "FindOne" => () => microsoft.FindOne(),
            "FindAll" => () => microsoft.FindAll(),
            "GetUnderlyingSearcher" => () => microsoft.GetUnderlyingSearcher(),
            _ => () => microsoft.GetUnderlyingSearcherType(),
        };
        Action actual = member switch
        {
            "Context" => () => { _ = ours.Context; },
            "FindOne" => () => ours.FindOne(),
            "FindAll" => () => ours.FindAll(),
            "GetUnderlyingSearcher" => () => ours.GetUnderlyingSearcher(),
            _ => () => ours.GetUnderlyingSearcherType(),
        };
        Assert.IsType<ObjectDisposedException>(Record.Exception(expected));
        Assert.IsType<ObjectDisposedException>(Record.Exception(actual));
    }
}
