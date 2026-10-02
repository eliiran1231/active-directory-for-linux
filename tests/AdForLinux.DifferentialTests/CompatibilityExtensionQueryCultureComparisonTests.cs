using System.Globalization;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Translation only: no FindAll/FindOne/Save and no fixture writes. Context and
// native searcher initialization can bind, so run only in the disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityExtensionQueryCultureComparisonTests
{
    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    private sealed class MicrosoftUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        public void Write(object value) => ExtensionSet("description", value);
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    private sealed class OurUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        public void Write(object value) => ExtensionSet("description", value);
    }

    [Theory]
    [InlineData("decimal", "en-US")]
    [InlineData("decimal", "fr-FR")]
    [InlineData("double", "en-US")]
    [InlineData("double", "fr-FR")]
    [InlineData("decimal-array", "en-US")]
    [InlineData("decimal-array", "fr-FR")]
    public void Extension_numeric_filter_uses_same_culture_and_conversion_time_as_microsoft(string kind, string culture)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var microsoft = new MicrosoftUser(expectedContext);
        using var ours = new OurUser(actualContext);
        using var expectedSearcher = new Ms.PrincipalSearcher(microsoft);
        using var actualSearcher = new Ours.PrincipalSearcher(ours);
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            microsoft.Write(Value(kind));
            ours.Write(Value(kind));

            // Render once, then change only the ambient culture and request the
            // underlying filter again. This also detects premature conversion
            // when ExtensionSet records the value, or stale filter reuse.
            var expectedInitial = MicrosoftFilter(expectedSearcher);
            var actualInitial = OurFilter(actualSearcher);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            var expectedRefreshed = MicrosoftFilter(expectedSearcher);
            var actualRefreshed = OurFilter(actualSearcher);
            Assert.NotNull(expectedInitial);
            Assert.NotNull(expectedRefreshed);
            Assert.Contains("description", expectedInitial);
            Assert.Contains("description", expectedRefreshed);
            // Require the oracle to exercise numeric culture conversion, not
            // merely return the same nonempty default filter twice.
            if (culture == "fr-FR") Assert.NotEqual(expectedInitial, expectedRefreshed);
            else Assert.Equal(expectedInitial, expectedRefreshed);
            Assert.Equal(new[] { expectedInitial, expectedRefreshed },
                new[] { actualInitial, actualRefreshed });
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    private static object Value(string kind) => kind switch
    {
        "decimal" => 1234.50m,
        "double" => 1234.5d,
        _ => new object[] { 1234.50m, -0.25m },
    };

    // Pin the oracle to its public native-searcher surface rather than
    // reproducing ExtensionTypeConverter's current-culture ToString logic.
    // Source: dotnet/runtime v9.0.0 AD/ADStoreCtx_Query.cs,
    // ExtensionCacheConverter -> ExtensionTypeConverter.
    private static string? MicrosoftFilter(Ms.PrincipalSearcher searcher) =>
        Assert.IsType<System.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;

    private static string? OurFilter(Ours.PrincipalSearcher searcher) =>
        Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;
}
