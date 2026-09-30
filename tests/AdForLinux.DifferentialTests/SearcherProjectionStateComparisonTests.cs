using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class SearcherProjectionStateComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public SearcherProjectionStateComparisonTests(TestDataFixture data) => _data = data;

    [Theory]
    [InlineData(false, "cn")]
    [InlineData(true, "cn")]
    [InlineData(false, "lowercase-adspath")]
    [InlineData(true, "lowercase-adspath")]
    [InlineData(false, "canonical-ADsPath")] // Already included: no extra property.
    [InlineData(true, "canonical-ADsPath")]
    [InlineData(false, "all-properties")] // Empty projection must stay empty.
    [InlineData(true, "all-properties")]
    public void Executing_search_matches_properties_to_load_state(bool findAll, string projection)
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoft = new Ms.DirectorySearcher(microsoftRoot, "(objectClass=*)")
        {
            SearchScope = Ms.SearchScope.Base,
        };
        using var ours = new Ours.DirectorySearcher(ourRoot, "(objectClass=*)")
        {
            SearchScope = Ours.SearchScope.Base,
        };
        var attributes = projection switch
        {
            "cn" => new[] { "cn" },
            "lowercase-adspath" => new[] { "cn", "adspath" },
            "canonical-ADsPath" => new[] { "cn", "ADsPath" },
            "all-properties" => Array.Empty<string>(),
            _ => throw new ArgumentOutOfRangeException(nameof(projection)),
        };
        microsoft.PropertiesToLoad.AddRange(attributes);
        ours.PropertiesToLoad.AddRange(attributes);
        Assert.Equal(microsoft.PropertiesToLoad.Cast<string>(), ours.PropertiesToLoad.Cast<string>());

        var expected = new List<string>();
        var actual = new List<string>();
        // Repeat on the same instances to cover both insertion and deduplication.
        for (var run = 0; run < 2; run++)
        {
            if (findAll)
            {
                using var microsoftResults = microsoft.FindAll();
                using var ourResults = ours.FindAll();
                Assert.Single(microsoftResults.Cast<Ms.SearchResult>());
                Assert.Single(ourResults.Cast<Ours.SearchResult>());
                expected.Add($"run {run}, PropertiesLoaded: {string.Join(",", microsoftResults.PropertiesLoaded)}");
                actual.Add($"run {run}, PropertiesLoaded: {string.Join(",", ourResults.PropertiesLoaded)}");
            }
            else
            {
                Assert.NotNull(microsoft.FindOne());
                Assert.NotNull(ours.FindOne());
            }

            expected.Add($"run {run}, PropertiesToLoad: {string.Join(",", microsoft.PropertiesToLoad.Cast<string>())}");
            actual.Add($"run {run}, PropertiesToLoad: {string.Join(",", ours.PropertiesToLoad.Cast<string>())}");
        }

        // Preserve order and casing: Microsoft's Contains("ADsPath") check is
        // case-sensitive even though LDAP attribute names are case-insensitive.
        Assert.Equal(expected, actual);
    }
}
