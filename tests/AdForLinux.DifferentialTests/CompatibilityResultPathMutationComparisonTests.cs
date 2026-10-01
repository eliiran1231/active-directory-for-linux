using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityResultPathMutationComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    // Public IDictionary mutation is already part of the result-property
    // surface. Microsoft derives Path from ADsPath on every access; the clone
    // captures Path when constructing the result. Use real search results to
    // test the composed contract without fabricating private result fields.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResult.cs
    [Theory]
    [InlineData("redirect")]
    [InlineData("remove")]
    [InlineData("null")]
    [InlineData("wrong-type")]
    [InlineData("empty-values")]
    [InlineData("same-value")]
    public void Result_path_and_entry_factory_observe_property_mutation_like_microsoft(string mutation)
    {
        using var expectedRoot = MicrosoftEntry(data.UserDn);
        using var actualRoot = OurEntry(data.UserDn);
        using var expectedOtherRoot = MicrosoftEntry(data.UnsetUserDn);
        using var actualOtherRoot = OurEntry(data.UnsetUserDn);
        using var expectedSearcher = new Ms.DirectorySearcher(expectedRoot) { SearchScope = Ms.SearchScope.Base };
        using var actualSearcher = new Ours.DirectorySearcher(actualRoot) { SearchScope = Ours.SearchScope.Base };
        using var expectedOtherSearcher = new Ms.DirectorySearcher(expectedOtherRoot) { SearchScope = Ms.SearchScope.Base };
        using var actualOtherSearcher = new Ours.DirectorySearcher(actualOtherRoot) { SearchScope = Ours.SearchScope.Base };
        var expected = Assert.IsType<Ms.SearchResult>(expectedSearcher.FindOne());
        var actual = Assert.IsType<Ours.SearchResult>(actualSearcher.FindOne());
        var expectedOther = Assert.IsType<Ms.SearchResult>(expectedOtherSearcher.FindOne());
        var actualOther = Assert.IsType<Ours.SearchResult>(actualOtherSearcher.FindOne());
        Assert.Equal(data.UserName, expected.Properties["sAMAccountName"][0]);
        Assert.Equal(data.UserName, actual.Properties["sAMAccountName"][0]);
        Assert.Equal(data.UnsetUserName, expectedOther.Properties["sAMAccountName"][0]);
        Assert.Equal(data.UnsetUserName, actualOther.Properties["sAMAccountName"][0]);
        IDictionary expectedProperties = expected.Properties;
        IDictionary actualProperties = actual.Properties;
        var expectedOriginal = expectedProperties["adspath"];
        var actualOriginal = actualProperties["adspath"];
        Assert.NotNull(expectedOriginal);
        Assert.NotNull(actualOriginal);
        var comparison = new Comparison($"SearchResult ADsPath mutation: {mutation}");
        Check("initial");

        if (mutation == "remove")
        {
            expectedProperties.Remove("adspath");
            actualProperties.Remove("adspath");
        }
        else
        {
            expectedProperties["adspath"] = mutation switch
            {
                "redirect" => expectedOther.Properties["ADsPath"],
                "null" => null,
                "wrong-type" => "not a result-value collection",
                "empty-values" => expected.Properties["absent-compatibility-property"],
                _ => expectedOriginal,
            };
            actualProperties["adspath"] = mutation switch
            {
                "redirect" => actualOther.Properties["ADsPath"],
                "null" => null,
                "wrong-type" => "not a result-value collection",
                "empty-values" => actual.Properties["absent-compatibility-property"],
                _ => actualOriginal,
            };
        }
        Check("after mutation");
        expectedProperties["adspath"] = expectedOriginal;
        actualProperties["adspath"] = actualOriginal;
        Check("after repair");
        comparison.Assert();

        void Check(string label)
        {
            // Merely constructing the entries does not bind. Never call a
            // directory operation through a locally replaced or invalid path.
            comparison.Check($"{label}: Path", Observe(() => expected.Path), Observe(() => actual.Path))
                .Check($"{label}: GetDirectoryEntry.Path", Observe(() =>
                {
                    using var entry = expected.GetDirectoryEntry();
                    return entry.Path;
                }), Observe(() =>
                {
                    using var entry = actual.GetDirectoryEntry();
                    return entry.Path;
                }));
        }
    }

    [Theory]
    [InlineData("FindOne", "path")]
    [InlineData("FindAll", "path")]
    [InlineData("FindOne", "authentication")]
    [InlineData("FindAll", "authentication")]
    public void Entry_factory_retains_search_time_root_state_like_microsoft(string query, string change)
    {
        using var expectedRoot = MicrosoftEntry(data.UserDn);
        using var actualRoot = OurEntry(data.UserDn);
        using var expectedSearcher = new Ms.DirectorySearcher(expectedRoot) { SearchScope = Ms.SearchScope.Base };
        using var actualSearcher = new Ours.DirectorySearcher(actualRoot) { SearchScope = Ours.SearchScope.Base };
        Ms.SearchResult expected;
        Ours.SearchResult actual;
        if (query == "FindOne")
        {
            expected = Assert.IsType<Ms.SearchResult>(expectedSearcher.FindOne());
            actual = Assert.IsType<Ours.SearchResult>(actualSearcher.FindOne());
        }
        else
        {
            using var expectedResults = expectedSearcher.FindAll();
            using var actualResults = actualSearcher.FindAll();
            expected = Assert.Single(expectedResults.Cast<Ms.SearchResult>());
            actual = Assert.Single(actualResults.Cast<Ours.SearchResult>());
        }
        Assert.Equal(data.UserName, expected.Properties["sAMAccountName"][0]);
        Assert.Equal(data.UserName, actual.Properties["sAMAccountName"][0]);
        if (change == "path")
        {
            // A different authority makes unintended reuse of the mutable root
            // visible. Never bind it or the entries returned below.
            expectedRoot.Path = actualRoot.Path = "LDAP://snapshot.invalid/DC=placeholder,DC=invalid";
        }
        else
        {
            expectedRoot.AuthenticationType = Ms.AuthenticationTypes.Anonymous;
            actualRoot.AuthenticationType = Ours.AuthenticationTypes.Anonymous;
        }
        using var expectedEntry = expected.GetDirectoryEntry();
        using var actualEntry = actual.GetDirectoryEntry();
        new Comparison($"{query} GetDirectoryEntry after root {change} change")
            .Check("result path", expected.Path, actual.Path)
            .Check("new entry path", expectedEntry.Path, actualEntry.Path)
            .Check("new entry authentication", (int)expectedEntry.AuthenticationType, (int)actualEntry.AuthenticationType)
            .Assert();
    }

    private static (string? Error, string? Parameter, string? Path) Observe(Func<string> read)
    {
        try { return (null, null, read()); }
        catch (Exception error) { return (error.GetType().Name, (error as ArgumentException)?.ParamName, null); }
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
