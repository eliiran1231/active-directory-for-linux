using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// TestDataFixture writes to AD. Run only in the verified disposable differential lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySearchResultCopyComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public CompatibilitySearchResultCopyComparisonTests(TestDataFixture data) => _data = data;

    public static IEnumerable<object[]> CopyCases()
    {
        foreach (var count in new[] { 0, 1, 2 })
        {
            foreach (var typed in new[] { false, true })
            {
                foreach (var shape in new[]
                {
                    "null", "negative-index", "min-index", "end-index", "past-end-index",
                    "max-index", "short-destination", "exact-fit", "offset-fit", "zero-length",
                })
                    yield return new object[] { count, typed, shape };
            }

            foreach (var shape in new[]
            {
                "object-array", "string-array", "value-array", "rank-two", "positive-lower-bound",
                "negative-lower-bound",
            })
                yield return new object[] { count, false, shape };
        }
    }

    [Theory]
    [MemberData(nameof(CopyCases))]
    public void CopyTo_validation_and_destination_state_match_microsoft(int count, bool typed, string shape)
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        // Names come from the fixture's GUID-suffixed ASCII identifiers. Empty
        // results use an impossible conjunction, not a guessed absent account.
        var filter = count switch
        {
            0 => "(&(objectClass=*)(!(objectClass=*)))",
            1 => $"(sAMAccountName={_data.UserName})",
            _ => $"(|(sAMAccountName={_data.UserName})(sAMAccountName={_data.UnsetUserName}))",
        };
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        {
            Filter = filter, SearchScope = Ms.SearchScope.OneLevel, CacheResults = true,
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            Filter = filter, SearchScope = Ours.SearchScope.OneLevel, CacheResults = true,
        };
        using var microsoft = microsoftSearcher.FindAll();
        using var ours = ourSearcher.FindAll();
        // Materialize first: these cases isolate copy contracts from paging,
        // streaming and network errors. Do not treat two empty queries as parity.
        Assert.Equal(count, microsoft.Count);
        Assert.Equal(count, ours.Count);
        var expectedRows = Enumerable.Range(0, count).Select(i => (object)microsoft[i]).ToArray();
        var actualRows = Enumerable.Range(0, count).Select(i => (object)ours[i]).ToArray();
        Assert.Equal(
            expectedRows.Cast<Ms.SearchResult>().Select(row => row.Properties["samaccountname"][0]?.ToString()).Order(),
            actualRows.Cast<Ours.SearchResult>().Select(row => row.Properties["samaccountname"][0]?.ToString()).Order());

        var expectedDestination = Destination(typeof(Ms.SearchResult), count, shape);
        var actualDestination = Destination(typeof(Ours.SearchResult), count, shape);
        var index = shape switch
        {
            "negative-index" => -1,
            "min-index" => int.MinValue,
            "end-index" => expectedDestination!.Length,
            "past-end-index" => expectedDestination!.Length + 1,
            "max-index" => int.MaxValue,
            "offset-fit" => 1,
            "positive-lower-bound" => 1,
            "negative-lower-bound" => -1,
            _ => 0,
        };
        var expectedError = Record.Exception(() =>
        {
            if (typed) microsoft.CopyTo((Ms.SearchResult[])expectedDestination!, index);
            else ((ICollection)microsoft).CopyTo(expectedDestination!, index);
        });
        var actualError = Record.Exception(() =>
        {
            if (typed) ours.CopyTo((Ours.SearchResult[])actualDestination!, index);
            else ((ICollection)ours).CopyTo(actualDestination!, index);
        });

        // Normalize by reference position within each source, not Path: both
        // APIs must copy the same objects, and server ordering may differ.
        // Keep mutation and exception observations together so a capacity error
        // cannot hide partial writes by a manual per-element copy loop.
        var expected = Observe(expectedError, expectedDestination, expectedRows);
        var actual = Observe(actualError, actualDestination, actualRows);
        Assert.Equal(expected, actual);
    }

    private static Array? Destination(Type resultType, int count, string shape) => shape switch
    {
        "null" => null,
        "short-destination" => Array.CreateInstance(resultType, Math.Max(0, count - 1)),
        "exact-fit" => Array.CreateInstance(resultType, count),
        "offset-fit" => Array.CreateInstance(resultType, count + 2),
        "zero-length" => Array.CreateInstance(resultType, 0),
        "object-array" => Enumerable.Repeat<object>("untouched", count + 2).ToArray(),
        "string-array" => Enumerable.Repeat("untouched", count + 2).ToArray(),
        "value-array" => Enumerable.Repeat(42, count + 2).ToArray(),
        "rank-two" => new object[2, 2],
        "positive-lower-bound" => Array.CreateInstance(typeof(object), new[] { count + 2 }, new[] { 1 }),
        "negative-lower-bound" => Array.CreateInstance(typeof(object), new[] { count + 2 }, new[] { -1 }),
        _ => Array.CreateInstance(resultType, count + 2),
    };

    private static string[] Observe(Exception? error, Array? destination, object[] source)
    {
        var observation = new List<string>
        {
            $"exception={error?.GetType().FullName ?? "none"}",
            $"parameter={(error as ArgumentException)?.ParamName ?? "none"}",
        };
        if (destination is null) observation.Add("destination=null");
        else
        {
            foreach (var value in destination)
            {
                if (value is null) observation.Add("null");
                else
                {
                    var sourceIndex = Array.FindIndex(source, row => ReferenceEquals(row, value));
                    observation.Add(sourceIndex >= 0 ? $"source[{sourceIndex}]" : $"other:{value}");
                }
            }
        }
        return observation.ToArray();
    }
}
