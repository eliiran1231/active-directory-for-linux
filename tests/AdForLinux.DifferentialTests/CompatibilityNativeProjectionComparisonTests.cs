using System.Collections.Specialized;
using System.Text.Json;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Native-searcher initialization can bind. Verified disposable lab only;
// no Find, Save, or CommitChanges is performed.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityNativeProjectionComparisonTests
{
    // PushFilterToNativeSearcher calls BuildPropertySet on every access. That
    // helper appends mapped attributes to the caller-visible StringCollection;
    // it neither clears caller attributes nor removes existing duplicates.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Native_projection_tracks_repeated_access_and_filter_type_like_microsoft(bool replaceWithGroup)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expectedFilter = new Ms.UserPrincipal(expectedContext);
        using var actualFilter = new Ours.UserPrincipal(actualContext);
        using var microsoft = new Ms.PrincipalSearcher(expectedFilter);
        using var ours = new Ours.PrincipalSearcher(actualFilter);
        var expectedNative = Assert.IsType<MsDirectory.DirectorySearcher>(microsoft.GetUnderlyingSearcher());
        var actualNative = Assert.IsType<OurDirectory.DirectorySearcher>(ours.GetUnderlyingSearcher());
        Assert.NotEmpty(expectedNative.PropertiesToLoad.Cast<string>());
        var comparison = new Comparison($"Native projection: replaceWithGroup={replaceWithGroup}")
            .Check("initial projection", Snapshot(expectedNative.PropertiesToLoad), Snapshot(actualNative.PropertiesToLoad));

        expectedNative.PropertiesToLoad.Clear();
        actualNative.PropertiesToLoad.Clear();
        expectedNative.PropertiesToLoad.Add("description");
        actualNative.PropertiesToLoad.Add("description");
        for (var read = 0; read < 2; read++)
        {
            var expectedCountBeforeRead = expectedNative.PropertiesToLoad.Count;
            Assert.Same(expectedNative, microsoft.GetUnderlyingSearcher());
            comparison.Check($"read {read}: native identity", true, ReferenceEquals(actualNative, ours.GetUnderlyingSearcher()));
            Assert.Contains("description", expectedNative.PropertiesToLoad.Cast<string>());
            Assert.True(expectedNative.PropertiesToLoad.Count > expectedCountBeforeRead);
            comparison.Check($"read {read}: projection", Snapshot(expectedNative.PropertiesToLoad), Snapshot(actualNative.PropertiesToLoad));
        }

        using Ms.Principal expectedReplacement = replaceWithGroup
            ? new Ms.GroupPrincipal(expectedContext) : new Ms.UserPrincipal(expectedContext);
        using Ours.Principal actualReplacement = replaceWithGroup
            ? new Ours.GroupPrincipal(actualContext) : new Ours.UserPrincipal(actualContext);
        microsoft.QueryFilter = expectedReplacement;
        ours.QueryFilter = actualReplacement;
        var expectedCountBeforeReplacement = expectedNative.PropertiesToLoad.Count;
        Assert.Same(expectedNative, microsoft.GetUnderlyingSearcher());
        comparison.Check("replacement native identity", true, ReferenceEquals(actualNative, ours.GetUnderlyingSearcher()));
        Assert.True(expectedNative.PropertiesToLoad.Count > expectedCountBeforeReplacement);
        Assert.Contains("description", expectedNative.PropertiesToLoad.Cast<string>());
        comparison.Check("replacement projection", Snapshot(expectedNative.PropertiesToLoad), Snapshot(actualNative.PropertiesToLoad))
            .Check("replacement filter", expectedNative.Filter, actualNative.Filter)
            .Assert();
    }

    // Attribute order is irrelevant; multiplicity is observable collection
    // state. A set comparison would hide repeated-access accumulation.
    private static string Snapshot(StringCollection values) =>
        JsonSerializer.Serialize(values.Cast<string>().OrderBy(value => value, StringComparer.Ordinal).ToArray());
}
