using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Native-searcher initialization can bind. Use only the isolated Windows lab;
// these cases render queries and never call Find, Save, or directory mutation.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityAdvancedExtensionQueryComparisonTests
{
    // Principal.AdvancedFilterSet wraps scalars in object[], and preserves an
    // object[] input. ExtensionCacheConverter then translates each element by
    // its runtime type, even when the caller supplied different type metadata.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs
    // Blob: 3b5fb29cf5c85fac7f259dd5702bbd64065d3619
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    // Blob: a6f44f8f185ddfcf025a93e654316b981a329e6c
    [Theory]
    [InlineData("boolean-true")]
    [InlineData("boolean-false")]
    [InlineData("date-declared-date")]
    [InlineData("date-declared-object")]
    [InlineData("string-array")]
    [InlineData("integer-array-range")]
    [InlineData("scalar-string")]
    [InlineData("byte-array")]
    [InlineData("value-type-array")]
    [InlineData("array-list")]
    public void Custom_advanced_filter_conversion_and_replacement_match_microsoft(string scenario)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var microsoft = new Ms.UserPrincipal(expectedContext);
        using var ours = new Ours.UserPrincipal(actualContext);
        var expectedFilters = new MicrosoftFilters(microsoft);
        var actualFilters = new OurFilters(ours);
        using var expectedSearcher = new Ms.PrincipalSearcher(microsoft);
        using var actualSearcher = new Ours.PrincipalSearcher(ours);
        var (attribute, value, declaredType, range) = Input(scenario);
        var comparison = new Comparison($"AdvancedFilterSet conversion: {scenario}");

        // A derived AdvancedFilters can configure its owning principal through
        // the protected API. Query generation observes its shared extension
        // cache without needing private-state access or a custom AD schema.
        var expectedSetError = Record.Exception(() => expectedFilters.Set(attribute, value, declaredType,
            range ? Ms.MatchType.GreaterThanOrEquals : Ms.MatchType.Equals));
        var actualSetError = Record.Exception(() => actualFilters.Set(attribute, value, declaredType,
            range ? Ours.MatchType.GreaterThanOrEquals : Ours.MatchType.Equals));
        Assert.Null(expectedSetError);
        CompareError(comparison, "initial setter", expectedSetError, actualSetError);
        var expectedInitial = MicrosoftFilter(expectedSearcher);
        string? actualInitial = null;
        var actualBuildError = Record.Exception(() => actualInitial = OurFilter(actualSearcher));
        Assert.False(string.IsNullOrEmpty(expectedInitial));
        Assert.Contains(attribute, expectedInitial);
        CompareError(comparison, "initial translation", null, actualBuildError);
        comparison.Check("initial filter", expectedInitial, actualInitial);

        const string replacement = "advanced-recovery";
        expectedSetError = Record.Exception(() => expectedFilters.Set(attribute, replacement, typeof(string), Ms.MatchType.Equals));
        actualSetError = Record.Exception(() => actualFilters.Set(attribute, replacement, typeof(string), Ours.MatchType.Equals));
        Assert.Null(expectedSetError);
        CompareError(comparison, "replacement setter", expectedSetError, actualSetError);
        var expectedReplacement = MicrosoftFilter(expectedSearcher);
        string? actualReplacement = null;
        actualBuildError = Record.Exception(() => actualReplacement = OurFilter(actualSearcher));
        Assert.False(string.IsNullOrEmpty(expectedReplacement));
        Assert.Contains(replacement, expectedReplacement);
        Assert.NotEqual(expectedInitial, expectedReplacement);
        CompareError(comparison, "replacement translation", null, actualBuildError);
        comparison.Check("replacement filter", expectedReplacement, actualReplacement).Assert();
    }

    private static (string Attribute, object Value, Type DeclaredType, bool Range) Input(string scenario) => scenario switch
    {
        "boolean-true" => ("msNPAllowDialin", true, typeof(bool), false),
        "boolean-false" => ("msNPAllowDialin", false, typeof(bool), false),
        "date-declared-date" => ("accountExpires", UtcDate(), typeof(DateTime), false),
        // Generic extension helpers commonly declare object while carrying a
        // DateTime value. UTC isolates metadata handling from timezone effects.
        "date-declared-object" => ("accountExpires", UtcDate(), typeof(object), false),
        "string-array" => ("otherTelephone", new object[] { "555-0101", "555-0102" }, typeof(string), false),
        "integer-array-range" => ("badPwdCount", new object[] { 2, 5 }, typeof(int), true),
        "scalar-string" => ("description", "initial-control", typeof(string), false),
        // These collections are wrapped as a single object by Microsoft's
        // AdvancedFilterSet (only object[] is passed through). Its extension
        // converter stringifies that element; the clone recursively expands it.
        "byte-array" => ("description", new byte[] { 1, 2 }, typeof(byte[]), false),
        "value-type-array" => ("description", new int[] { 2, 5 }, typeof(int[]), false),
        "array-list" => ("description", new System.Collections.ArrayList { "one", "two" }, typeof(object), false),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
    };

    private static DateTime UtcDate() => new(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    private static string? MicrosoftFilter(Ms.PrincipalSearcher searcher) =>
        Assert.IsType<System.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;

    private static string? OurFilter(Ours.PrincipalSearcher searcher) =>
        Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;

    private static void CompareError(Comparison comparison, string label, Exception? expected, Exception? actual) => comparison
        .Check($"{label}: exception", expected?.GetType().Name, actual?.GetType().Name)
        .Check($"{label}: parameter", (expected as ArgumentException)?.ParamName, (actual as ArgumentException)?.ParamName);

    private sealed class MicrosoftFilters(Ms.Principal principal) : Ms.AdvancedFilters(principal)
    {
        public void Set(string attribute, object value, Type declaredType, Ms.MatchType match) =>
            AdvancedFilterSet(attribute, value, declaredType, match);
    }

    private sealed class OurFilters(Ours.Principal principal) : Ours.AdvancedFilters(principal)
    {
        public void Set(string attribute, object value, Type declaredType, Ours.MatchType match) =>
            AdvancedFilterSet(attribute, value, declaredType, match);
    }
}
