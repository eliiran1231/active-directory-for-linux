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
        Assert.Equal(SuiteCapture.Expected(microsoft.PropertyName, "assert-equal-expected", 20), SuiteCapture.Expected(ours.PropertyName, "assert-equal-actual", 20));

        AssertSameException(
            () => microsoft.Direction = (MicrosoftDirectoryServices.SortDirection)int.MaxValue,
            () => ours.Direction = (LinuxDirectoryServices.SortDirection)int.MaxValue);
        Assert.Equal(SuiteCapture.Expected(microsoft.Direction.ToString(), "assert-equal-expected", 25), SuiteCapture.Expected(ours.Direction.ToString(), "assert-equal-actual", 25));

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
        Assert.Equal(SuiteCapture.Expected(microsoftCookie, "assert-equal-expected", 52), SuiteCapture.Expected(ourCookie, "assert-equal-actual", 52));
        Assert.NotSame(microsoftInput, microsoftCookie);
        Assert.NotSame(ourInput, ourCookie);

        microsoftCookie[1] = 8;
        ourCookie[1] = 8;
        Assert.Equal(SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-expected", 58), SuiteCapture.Expected(ours.GetDirectorySynchronizationCookie(), "assert-equal-actual", 58));
        Assert.Equal(SuiteCapture.Expected(new byte[] { 1, 2, 3 }, "assert-equal-expected", 59), SuiteCapture.Expected(ours.GetDirectorySynchronizationCookie(), "assert-equal-actual", 59));

        microsoft.ResetDirectorySynchronizationCookie(null);
        ours.ResetDirectorySynchronizationCookie(null);
        Assert.Equal(SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-expected", 63), SuiteCapture.Expected(ours.GetDirectorySynchronizationCookie(), "assert-equal-actual", 63));

        microsoft.Option = MicrosoftDirectoryServices.DirectorySynchronizationOptions.ObjectSecurity;
        ours.Option = LinuxDirectoryServices.DirectorySynchronizationOptions.ObjectSecurity;
        AssertSameException(
            () => microsoft.Option = (MicrosoftDirectoryServices.DirectorySynchronizationOptions)(-1),
            () => ours.Option = (LinuxDirectoryServices.DirectorySynchronizationOptions)(-1));
        Assert.Equal(SuiteCapture.Expected(microsoft.Option.ToString(), "assert-equal-expected", 70), SuiteCapture.Expected(ours.Option.ToString(), "assert-equal-actual", 70));
        AssertSameException(
            () => new MicrosoftDirectoryServices.DirectorySynchronization((MicrosoftDirectoryServices.DirectorySynchronizationOptions)0x400),
            () => new LinuxDirectoryServices.DirectorySynchronization((LinuxDirectoryServices.DirectorySynchronizationOptions)0x400));
    }

    [Theory]
    [InlineData(typeof(MicrosoftDirectoryServices.ExtendedDN), typeof(LinuxDirectoryServices.ExtendedDN))]
    [InlineData(typeof(MicrosoftDirectoryServices.PasswordEncodingMethod), typeof(LinuxDirectoryServices.PasswordEncodingMethod))]
    public void Enum_names_and_values_match_microsoft(Type microsoftType, Type ourType)
    {
        Assert.Equal(SuiteCapture.Expected(EnumValues(microsoftType), "assert-equal-expected", 81), SuiteCapture.Expected(EnumValues(ourType), "assert-equal-actual", 81));
    }

    [Fact]
    public void Directory_searcher_extended_dn_default_matches_microsoft()
    {
        using var microsoft = new MicrosoftDirectoryServices.DirectorySearcher();
        using var ours = new LinuxDirectoryServices.DirectorySearcher();

        Assert.Equal(SuiteCapture.Expected(microsoft.ExtendedDN.ToString(), "assert-equal-expected", 90), SuiteCapture.Expected(ours.ExtendedDN.ToString(), "assert-equal-actual", 90));
    }

    [Fact]
    public void Directory_searcher_filter_setter_state_matches_microsoft()
    {
        using var microsoft = new MicrosoftDirectoryServices.DirectorySearcher();
        using var ours = new LinuxDirectoryServices.DirectorySearcher();

        foreach (var filter in new string?[] { "(objectClass=person)", null, string.Empty })
        {
            microsoft.Filter = filter;
            ours.Filter = filter;

            Assert.Equal(SuiteCapture.Expected(microsoft.Filter, "assert-equal-expected", 104), SuiteCapture.Expected(ours.Filter, "assert-equal-actual", 104));
        }
    }

    [Fact]
    public void Directory_searcher_extended_dn_validation_matches_microsoft()
    {
        using var microsoft = new MicrosoftDirectoryServices.DirectorySearcher();
        using var ours = new LinuxDirectoryServices.DirectorySearcher();

        foreach (var value in new[] { -1, 0, 1 })
        {
            microsoft.ExtendedDN = (MicrosoftDirectoryServices.ExtendedDN)value;
            ours.ExtendedDN = (LinuxDirectoryServices.ExtendedDN)value;

            Assert.Equal(SuiteCapture.Expected(microsoft.ExtendedDN.ToString(), "assert-equal-expected", 119), SuiteCapture.Expected(ours.ExtendedDN.ToString(), "assert-equal-actual", 119));
        }

        foreach (var value in new[] { int.MinValue, -2, 2, int.MaxValue })
        {
            AssertSameException(
                () => microsoft.ExtendedDN = (MicrosoftDirectoryServices.ExtendedDN)value,
                () => ours.ExtendedDN = (LinuxDirectoryServices.ExtendedDN)value);
            Assert.Equal(SuiteCapture.Expected(microsoft.ExtendedDN.ToString(), "assert-equal-expected", 127), SuiteCapture.Expected(ours.ExtendedDN.ToString(), "assert-equal-actual", 127));
        }
    }

    [Fact]
    public void Directory_searcher_security_mask_validation_matches_microsoft()
    {
        using var microsoft = new MicrosoftDirectoryServices.DirectorySearcher();
        using var ours = new LinuxDirectoryServices.DirectorySearcher();

        for (var value = 0; value <= 15; value++)
        {
            microsoft.SecurityMasks = (MicrosoftDirectoryServices.SecurityMasks)value;
            ours.SecurityMasks = (LinuxDirectoryServices.SecurityMasks)value;

            Assert.Equal(SuiteCapture.Expected((int)microsoft.SecurityMasks, "assert-equal-expected", 142), SuiteCapture.Expected((int)ours.SecurityMasks, "assert-equal-actual", 142));
        }

        // Microsoft's range check has no lower-bound guard; preserve that
        // observable setter behavior even though negative masks are not useful.
        microsoft.SecurityMasks = (MicrosoftDirectoryServices.SecurityMasks)(-1);
        ours.SecurityMasks = (LinuxDirectoryServices.SecurityMasks)(-1);
        Assert.Equal(SuiteCapture.Expected((int)microsoft.SecurityMasks, "assert-equal-expected", 149), SuiteCapture.Expected((int)ours.SecurityMasks, "assert-equal-actual", 149));

        foreach (var value in new[] { 16, int.MaxValue })
        {
            AssertSameException(
                () => microsoft.SecurityMasks = (MicrosoftDirectoryServices.SecurityMasks)value,
                () => ours.SecurityMasks = (LinuxDirectoryServices.SecurityMasks)value);
            Assert.Equal(SuiteCapture.Expected((int)microsoft.SecurityMasks, "assert-equal-expected", 156), SuiteCapture.Expected((int)ours.SecurityMasks, "assert-equal-actual", 156));
        }
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

        // Replay every public setter used by the Microsoft 9.0.0
        // DirectorySearcher.VirtualListView response getter. The final
        // percentage assignment rounds Offset again (2 of 13 becomes 1).
        // CompatibilityVlvResponseComparisonTests independently verifies
        // this transition using real sorted AD search responses.
        // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs
        microsoft.Offset = 2;
        microsoft.ApproximateTotal = 13;
        microsoft.DirectoryVirtualListViewContext = new MicrosoftDirectoryServices.DirectoryVirtualListViewContext();
        microsoft.TargetPercentage = (int)((double)microsoft.Offset / microsoft.ApproximateTotal * 100);
        ours.Update(offset: 2, approximateTotal: 13, contextId: null);

        AssertViewsEqual(microsoft, ours);
        Assert.Equal(SuiteCapture.Expected(15, "assert-equal-expected", 228), SuiteCapture.Expected(ours.TargetPercentage, "assert-equal-actual", 228));
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
        Assert.Equal(SuiteCapture.Expected(microsoft.BeforeCount, "assert-equal-expected", 241), SuiteCapture.Expected(ours.BeforeCount, "assert-equal-actual", 241));
        Assert.Equal(SuiteCapture.Expected(microsoft.AfterCount, "assert-equal-expected", 242), SuiteCapture.Expected(ours.AfterCount, "assert-equal-actual", 242));
        Assert.Equal(SuiteCapture.Expected(microsoft.Offset, "assert-equal-expected", 243), SuiteCapture.Expected(ours.Offset, "assert-equal-actual", 243));
        Assert.Equal(SuiteCapture.Expected(microsoft.ApproximateTotal, "assert-equal-expected", 244), SuiteCapture.Expected(ours.ApproximateTotal, "assert-equal-actual", 244));
        Assert.Equal(SuiteCapture.Expected(microsoft.TargetPercentage, "assert-equal-expected", 245), SuiteCapture.Expected(ours.TargetPercentage, "assert-equal-actual", 245));
        Assert.Equal(SuiteCapture.Expected(microsoft.Target, "assert-equal-expected", 246), SuiteCapture.Expected(ours.Target, "assert-equal-actual", 246));
        Assert.Equal(SuiteCapture.Expected(microsoft.DirectoryVirtualListViewContext is null, "assert-equal-expected", 247), SuiteCapture.Expected(ours.DirectoryVirtualListViewContext is null, "assert-equal-actual", 247));
    }

    private static void AssertSameException(Action microsoftAction, Action ourAction)
    {
        var microsoftException = Record.Exception(microsoftAction);
        var ourException = Record.Exception(ourAction);

        Assert.NotNull(microsoftException);
        Assert.NotNull(ourException);
        Assert.Equal(SuiteCapture.Expected(microsoftException.GetType(), "assert-equal-expected", 257), SuiteCapture.Expected(ourException.GetType(), "assert-equal-actual", 257));
        Assert.Equal(
            SuiteCapture.Expected((microsoftException as ArgumentException)?.ParamName, "assert-equal-expected", 258),
            SuiteCapture.Expected((ourException as ArgumentException)?.ParamName, "assert-equal-actual", 258));
    }
}
