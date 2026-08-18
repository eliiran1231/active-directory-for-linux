using System.Reflection;
using Xunit;

using MicrosoftDirectoryServices = System.DirectoryServices;
using LinuxDirectoryServices = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public class DirectorySearchOptionsComparisonTests
{
    [Fact]
    public void Sort_option_validation_and_state_match_microsoft()
    {
        var microsoft = new MicrosoftDirectoryServices.SortOption("cn", MicrosoftDirectoryServices.SortDirection.Descending);
        var ours = new LinuxDirectoryServices.SortOption("cn", LinuxDirectoryServices.SortDirection.Descending);

        AssertSameException(
            () => microsoft.PropertyName = null!,
            () => ours.PropertyName = null!);
        Assert.Equal(microsoft.PropertyName, ours.PropertyName);

        AssertSameException(
            () => microsoft.Direction = (MicrosoftDirectoryServices.SortDirection)int.MaxValue,
            () => ours.Direction = (LinuxDirectoryServices.SortDirection)int.MaxValue);
        Assert.Equal(microsoft.Direction.ToString(), ours.Direction.ToString());

        AssertSameException(
            () => new MicrosoftDirectoryServices.SortOption(null!, MicrosoftDirectoryServices.SortDirection.Ascending),
            () => new LinuxDirectoryServices.SortOption(null!, LinuxDirectoryServices.SortDirection.Ascending));
        AssertSameException(
            () => new MicrosoftDirectoryServices.SortOption("cn", (MicrosoftDirectoryServices.SortDirection)(-1)),
            () => new LinuxDirectoryServices.SortOption("cn", (LinuxDirectoryServices.SortDirection)(-1)));
    }

    [Fact]
    public void Directory_synchronization_cookie_and_option_semantics_match_microsoft()
    {
        Assert.Empty(new MicrosoftDirectoryServices.DirectorySynchronization((byte[]?)null).GetDirectorySynchronizationCookie());
        Assert.Empty(new LinuxDirectoryServices.DirectorySynchronization((byte[]?)null).GetDirectorySynchronizationCookie());
        Assert.Empty(new MicrosoftDirectoryServices.DirectorySynchronization((MicrosoftDirectoryServices.DirectorySynchronization?)null).GetDirectorySynchronizationCookie());
        Assert.Empty(new LinuxDirectoryServices.DirectorySynchronization((LinuxDirectoryServices.DirectorySynchronization?)null).GetDirectorySynchronizationCookie());

        var microsoftInput = new byte[] { 1, 2, 3 };
        var ourInput = microsoftInput.ToArray();
        var microsoft = new MicrosoftDirectoryServices.DirectorySynchronization(microsoftInput);
        var ours = new LinuxDirectoryServices.DirectorySynchronization(ourInput);

        microsoftInput[0] = 9;
        ourInput[0] = 9;
        var microsoftCookie = microsoft.GetDirectorySynchronizationCookie();
        var ourCookie = ours.GetDirectorySynchronizationCookie();
        Assert.Equal(microsoftCookie, ourCookie);
        Assert.NotSame(microsoftInput, microsoftCookie);
        Assert.NotSame(ourInput, ourCookie);

        microsoftCookie[1] = 8;
        ourCookie[1] = 8;
        Assert.Equal(microsoft.GetDirectorySynchronizationCookie(), ours.GetDirectorySynchronizationCookie());
        Assert.Equal(new byte[] { 1, 2, 3 }, ours.GetDirectorySynchronizationCookie());

        microsoft.ResetDirectorySynchronizationCookie(null);
        ours.ResetDirectorySynchronizationCookie(null);
        Assert.Equal(microsoft.GetDirectorySynchronizationCookie(), ours.GetDirectorySynchronizationCookie());

        microsoft.Option = MicrosoftDirectoryServices.DirectorySynchronizationOptions.ObjectSecurity;
        ours.Option = LinuxDirectoryServices.DirectorySynchronizationOptions.ObjectSecurity;
        AssertSameException(
            () => microsoft.Option = (MicrosoftDirectoryServices.DirectorySynchronizationOptions)(-1),
            () => ours.Option = (LinuxDirectoryServices.DirectorySynchronizationOptions)(-1));
        Assert.Equal(microsoft.Option.ToString(), ours.Option.ToString());
        AssertSameException(
            () => new MicrosoftDirectoryServices.DirectorySynchronization((MicrosoftDirectoryServices.DirectorySynchronizationOptions)0x400),
            () => new LinuxDirectoryServices.DirectorySynchronization((LinuxDirectoryServices.DirectorySynchronizationOptions)0x400));
    }

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

    [Fact]
    public void Virtual_list_view_response_update_uses_the_returned_total_for_percentage()
    {
        var microsoft = new MicrosoftDirectoryServices.DirectoryVirtualListView(0, 0, 500)
        {
            ApproximateTotal = 1000,
        };
        var ours = new LinuxDirectoryServices.DirectoryVirtualListView(0, 0, 500)
        {
            ApproximateTotal = 1000,
        };

        // This is the public state transition performed by Microsoft's
        // DirectorySearcher when a VLV response returns position 2 of 13.
        microsoft.ApproximateTotal = 13;
        microsoft.Offset = 2;
        microsoft.DirectoryVirtualListViewContext = new MicrosoftDirectoryServices.DirectoryVirtualListViewContext();
        ours.Update(offset: 2, approximateTotal: 13, contextId: null);

        AssertViewsEqual(microsoft, ours);
        Assert.Equal(15, ours.TargetPercentage);
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
        Assert.Equal(
            (microsoftException as ArgumentException)?.ParamName,
            (ourException as ArgumentException)?.ParamName);
    }
}
