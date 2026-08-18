using System.Reflection;
using Xunit;

using MicrosoftDirectoryServices = System.DirectoryServices;
using LinuxDirectoryServices = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public class DirectorySearchOptionsComparisonTests
{
    [Theory]
    [InlineData(typeof(MicrosoftDirectoryServices.ExtendedDN), typeof(LinuxDirectoryServices.ExtendedDN))]
    [InlineData(typeof(MicrosoftDirectoryServices.PasswordEncodingMethod), typeof(LinuxDirectoryServices.PasswordEncodingMethod))]
    public void Enum_names_and_values_match_microsoft(Type microsoftType, Type ourType)
    {
        Assert.Equal(EnumValues(microsoftType), EnumValues(ourType));
    }

    [Fact]
    public void Directory_searcher_extended_dn_default_matches_microsoft()
    {
        using var microsoft = new MicrosoftDirectoryServices.DirectorySearcher();
        using var ours = new LinuxDirectoryServices.DirectorySearcher();

        Assert.Equal(microsoft.ExtendedDN.ToString(), ours.ExtendedDN.ToString());
    }

    [Fact]
    public void Virtual_list_view_constructors_match_microsoft()
    {
        var microsoftContext = new MicrosoftDirectoryServices.DirectoryVirtualListViewContext();
        var ourContext = new LinuxDirectoryServices.DirectoryVirtualListViewContext();

        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(), new LinuxDirectoryServices.DirectoryVirtualListView());
        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(20), new LinuxDirectoryServices.DirectoryVirtualListView(20));
        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(2, 3, 10), new LinuxDirectoryServices.DirectoryVirtualListView(2, 3, 10));
        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(2, 3, 10, microsoftContext), new LinuxDirectoryServices.DirectoryVirtualListView(2, 3, 10, ourContext));
        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(2, 3, "target"), new LinuxDirectoryServices.DirectoryVirtualListView(2, 3, "target"));
        AssertViewsEqual(new MicrosoftDirectoryServices.DirectoryVirtualListView(2, 3, "target", microsoftContext), new LinuxDirectoryServices.DirectoryVirtualListView(2, 3, "target", ourContext));
    }

    [Fact]
    public void Virtual_list_view_validation_and_derived_values_match_microsoft()
    {
        AssertSameException(() => new MicrosoftDirectoryServices.DirectoryVirtualListView(-1), () => new LinuxDirectoryServices.DirectoryVirtualListView(-1));
        AssertSameException(() => new MicrosoftDirectoryServices.DirectoryVirtualListView(-1, 0, 0), () => new LinuxDirectoryServices.DirectoryVirtualListView(-1, 0, 0));
        AssertSameException(() => new MicrosoftDirectoryServices.DirectoryVirtualListView(0, -1, 0), () => new LinuxDirectoryServices.DirectoryVirtualListView(0, -1, 0));
        AssertSameException(() => new MicrosoftDirectoryServices.DirectoryVirtualListView(0, 0, -1), () => new LinuxDirectoryServices.DirectoryVirtualListView(0, 0, -1));

        var microsoft = new MicrosoftDirectoryServices.DirectoryVirtualListView();
        var ours = new LinuxDirectoryServices.DirectoryVirtualListView();
        AssertSameException(() => microsoft.ApproximateTotal = -1, () => ours.ApproximateTotal = -1);
        AssertSameException(() => microsoft.TargetPercentage = -1, () => ours.TargetPercentage = -1);
        AssertSameException(() => microsoft.TargetPercentage = 101, () => ours.TargetPercentage = 101);

        microsoft.ApproximateTotal = 80;
        ours.ApproximateTotal = 80;
        microsoft.TargetPercentage = 25;
        ours.TargetPercentage = 25;
        AssertViewsEqual(microsoft, ours);

        microsoft.Offset = 40;
        ours.Offset = 40;
        AssertViewsEqual(microsoft, ours);

        microsoft.Target = null;
        ours.Target = null!;
        AssertViewsEqual(microsoft, ours);
    }

    private static string[] EnumValues(Type type) => type
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(field => $"{field.Name}={Convert.ToInt64(field.GetRawConstantValue())}")
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static void AssertViewsEqual(
        MicrosoftDirectoryServices.DirectoryVirtualListView microsoft,
        LinuxDirectoryServices.DirectoryVirtualListView ours)
    {
        Assert.Equal(microsoft.BeforeCount, ours.BeforeCount);
        Assert.Equal(microsoft.AfterCount, ours.AfterCount);
        Assert.Equal(microsoft.Offset, ours.Offset);
        Assert.Equal(microsoft.ApproximateTotal, ours.ApproximateTotal);
        Assert.Equal(microsoft.TargetPercentage, ours.TargetPercentage);
        Assert.Equal(microsoft.Target, ours.Target);
        Assert.Equal(microsoft.DirectoryVirtualListViewContext is null, ours.DirectoryVirtualListViewContext is null);
    }

    private static void AssertSameException(Action microsoftAction, Action ourAction)
    {
        var microsoftException = Record.Exception(microsoftAction);
        var ourException = Record.Exception(ourAction);

        Assert.NotNull(microsoftException);
        Assert.NotNull(ourException);
        Assert.Equal(microsoftException.GetType(), ourException.GetType());
    }
}
