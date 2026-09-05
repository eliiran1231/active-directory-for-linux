using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyNamesOnlyComparisonTests
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

        Assert.Equal(microsoftShape.Keys, ourShape.Keys);
        foreach (var propertyName in microsoftShape.Keys)
        {
            Assert.Equal(microsoftShape[propertyName], ourShape[propertyName]);
        }
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
