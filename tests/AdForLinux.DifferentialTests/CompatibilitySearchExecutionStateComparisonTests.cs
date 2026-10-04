using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// All searches are bounded to a known fixture DN or a proven missing DN.
// Source-supported candidates; execute only in an authorized disposable lab.
// The shared fixture creates and deletes AD objects; these test bodies only read.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySearchExecutionStateComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    // Microsoft truncates TotalSeconds to an integer in SetSearchPreferences.
    // The clone's paged budget instead stops before sending a subsecond request.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs
    [Fact]
    public void Fractional_server_limit_preserves_paged_results_like_microsoft()
    {
        using var expectedRoot = MicrosoftEntry(data.UserDn);
        using var actualRoot = OurEntry(data.UserDn);
        using var expected = new Ms.DirectorySearcher(expectedRoot) { SearchScope = Ms.SearchScope.Base };
        using var actual = new Ours.DirectorySearcher(actualRoot) { SearchScope = Ours.SearchScope.Base };
        expected.PropertiesToLoad.Add("distinguishedName");
        actual.PropertiesToLoad.Add("distinguishedName");

        // Establish working paging and fractional timeout independently before
        // combining them. A connectivity/setup failure is never a gap result.
        expected.PageSize = actual.PageSize = 1;
        expected.ServerTimeLimit = actual.ServerTimeLimit = TimeSpan.Zero;
        AssertKnown(Read(expected));
        AssertKnown(Read(actual));
        expected.PageSize = actual.PageSize = 0;
        expected.ServerTimeLimit = actual.ServerTimeLimit = TimeSpan.FromMilliseconds(500);
        AssertKnown(Read(expected));
        AssertKnown(Read(actual));

        expected.PageSize = actual.PageSize = 1;
        var left = Read(expected);
        var right = Read(actual);
        AssertKnown(left);
        new Comparison("Paged search with fractional server time limit")
            .Check("row count", left.Length, right.Length)
            .CheckSet("distinguished names", left, right)
            .Check("retained server limit", expected.ServerTimeLimit, actual.ServerTimeLimit)
            .Check("retained page size", expected.PageSize, actual.PageSize)
            .Assert();
    }

    // Microsoft binds the root before adding ADsPath to the public projection.
    // The clone builds the request before its target DN is validated.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Missing_root_failure_preserves_projection_like_microsoft(bool findAll)
    {
        using var expectedRoot = MicrosoftEntry(data.UserDn);
        using var actualRoot = OurEntry(data.UserDn);
        using var expected = new Ms.DirectorySearcher(expectedRoot) { SearchScope = Ms.SearchScope.Base };
        using var actual = new Ours.DirectorySearcher(actualRoot) { SearchScope = Ours.SearchScope.Base };
        expected.PropertiesToLoad.Add("distinguishedName");
        actual.PropertiesToLoad.Add("distinguishedName");
        AssertKnown(Read(expected, findAll));
        AssertKnown(Read(actual, findAll));

        var missingDn = $"CN=compat-projection-missing-{Guid.NewGuid():N},{DifferentialSettings.UsersContainer}";
        using var expectedMissing = MicrosoftEntry(missingDn);
        using var actualMissing = OurEntry(missingDn);
        AssertMissing(Record.Exception(() => expectedMissing.RefreshCache()));
        AssertMissing(Record.Exception(() => actualMissing.RefreshCache()));
        expected.SearchRoot = expectedMissing;
        actual.SearchRoot = actualMissing;
        expected.PropertiesToLoad.Clear();
        actual.PropertiesToLoad.Clear();
        expected.PropertiesToLoad.Add("distinguishedName");
        actual.PropertiesToLoad.Add("distinguishedName");
        var leftError = Record.Exception(() => Read(expected, findAll));
        var rightError = Record.Exception(() => Read(actual, findAll));
        var leftProjection = expected.PropertiesToLoad.Cast<string>().ToArray();
        var rightProjection = actual.PropertiesToLoad.Cast<string>().ToArray();
        AssertMissing(leftError);
        AssertMissing(rightError);

        // Recover before comparing captured state so a mismatch cannot hide a
        // broken root-replacement path. Neither missing wrapper is mutated.
        expected.SearchRoot = expectedRoot;
        actual.SearchRoot = actualRoot;
        AssertKnown(Read(expected, findAll));
        AssertKnown(Read(actual, findAll));
        Assert.Contains("ADsPath", expected.PropertiesToLoad.Cast<string>());
        Assert.Contains("ADsPath", actual.PropertiesToLoad.Cast<string>());
        new Comparison($"Projection after missing-root failure: findAll={findAll}")
            .Check("failure type", leftError!.GetType().Name, rightError!.GetType().Name)
            .Check("projection after failure", string.Join("|", leftProjection), string.Join("|", rightProjection))
            .Check("projection after recovery", string.Join("|", expected.PropertiesToLoad.Cast<string>()),
                string.Join("|", actual.PropertiesToLoad.Cast<string>()))
            .Assert();
    }

    private void AssertKnown(string[] names) => Assert.Equal(data.UserDn, Assert.Single(names), ignoreCase: true);

    private static void AssertMissing(Exception? error)
    {
        var failure = Assert.IsAssignableFrom<COMException>(error);
        Assert.Equal(unchecked((int)0x80072030), failure.ErrorCode);
    }

    private static string[] Read(Ms.DirectorySearcher searcher, bool findAll = true)
    {
        if (!findAll)
        {
            var result = searcher.FindOne();
            return result is null ? [] : [(string)result.Properties["distinguishedName"][0]!];
        }
        using var results = searcher.FindAll();
        return results.Cast<Ms.SearchResult>().Select(result => (string)result.Properties["distinguishedName"][0]!).ToArray();
    }

    private static string[] Read(Ours.DirectorySearcher searcher, bool findAll = true)
    {
        if (!findAll)
        {
            var result = searcher.FindOne();
            return result is null ? [] : [(string)result.Properties["distinguishedName"][0]!];
        }
        using var results = searcher.FindAll();
        return results.Cast<Ours.SearchResult>().Select(result => (string)result.Properties["distinguishedName"][0]!).ToArray();
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
