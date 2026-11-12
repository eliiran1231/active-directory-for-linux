using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyNamesOnlyComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public PropertyNamesOnlyComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    [Fact]
    public void PropertyNamesOnly_result_shape_matches_microsoft()
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        {
            Filter = "(objectClass=*)",
            SearchScope = Ms.SearchScope.Base,
            PropertyNamesOnly = true,
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            Filter = "(objectClass=*)",
            SearchScope = Ours.SearchScope.Base,
            PropertyNamesOnly = true,
        };

        microsoftSearcher.PropertiesToLoad.AddRange(new[] { "displayName", "description" });
        ourSearcher.PropertiesToLoad.AddRange(new[] { "displayName", "description" });

        var microsoft = Assert.IsType<Ms.SearchResult>(microsoftSearcher.FindOne());
        var ours = Assert.IsType<Ours.SearchResult>(ourSearcher.FindOne());
        var microsoftShape = Snapshot(microsoft.Properties);
        var ourShape = Snapshot(ours.Properties);

        Assert.Equal(SuiteCapture.Expected(microsoftShape.Keys, "assert-equal-expected", 51), SuiteCapture.Expected(ourShape.Keys, "assert-equal-actual", 51));
        foreach (var propertyName in microsoftShape.Keys)
        {
            Assert.Equal(SuiteCapture.Expected(microsoftShape[propertyName], "assert-equal-expected", 54), SuiteCapture.Expected(ourShape[propertyName], "assert-equal-actual", 54));
        }

        Assert.Equal(SuiteCapture.Expected(0, "assert-equal-expected", 57), SuiteCapture.Expected(ourShape["displayname"], "assert-equal-actual", 57));
        Assert.Equal(SuiteCapture.Expected(0, "assert-equal-expected", 58), SuiteCapture.Expected(ourShape["description"], "assert-equal-actual", 58));
    }

    [Fact]
    public void PropertyNamesOnly_does_not_include_absent_requested_attributes()
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UnsetUserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UnsetUserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        {
            Filter = "(objectClass=*)",
            SearchScope = Ms.SearchScope.Base,
            PropertyNamesOnly = true,
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            Filter = "(objectClass=*)",
            SearchScope = Ours.SearchScope.Base,
            PropertyNamesOnly = true,
        };

        microsoftSearcher.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "description" });
        ourSearcher.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "description" });

        var microsoft = Assert.IsType<Ms.SearchResult>(microsoftSearcher.FindOne());
        var ours = Assert.IsType<Ours.SearchResult>(ourSearcher.FindOne());
        var microsoftShape = Snapshot(microsoft.Properties);
        var ourShape = Snapshot(ours.Properties);

        Assert.Equal(SuiteCapture.Expected(microsoftShape.Keys, "assert-equal-expected", 95), SuiteCapture.Expected(ourShape.Keys, "assert-equal-actual", 95));
        foreach (var propertyName in microsoftShape.Keys)
        {
            Assert.Equal(SuiteCapture.Expected(microsoftShape[propertyName], "assert-equal-expected", 98), SuiteCapture.Expected(ourShape[propertyName], "assert-equal-actual", 98));
        }

        Assert.Equal(SuiteCapture.Expected(0, "assert-equal-expected", 101), SuiteCapture.Expected(ourShape["samaccountname"], "assert-equal-actual", 101));
        Assert.False(ours.Properties.Contains("description"));
    }

    private static SortedDictionary<string, int> Snapshot(Ms.ResultPropertyCollection properties) =>
        new(
            properties.PropertyNames.Cast<string>().ToDictionary(
                name => name,
                name => properties[name].Count,
                StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

    private static SortedDictionary<string, int> Snapshot(Ours.ResultPropertyCollection properties) =>
        new(
            properties.PropertyNames.Cast<string>().ToDictionary(
                name => name,
                name => properties[name].Count,
                StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);
}
