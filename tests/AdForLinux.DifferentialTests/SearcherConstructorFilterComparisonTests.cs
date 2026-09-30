using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Reading Filter does not bind SearchRoot or require a directory server.
public sealed class SearcherConstructorFilterComparisonTests
{
    public static IEnumerable<object?[]> ConstructorCases()
    {
        foreach (var overload in new[] { "filter", "filter-properties", "filter-properties-scope",
                     "root-filter", "root-filter-properties", "root-filter-properties-scope" })
        foreach (var filter in new[] { null, "", "(objectClass=person)" })
            yield return new object?[] { overload, filter };
    }

    [Theory]
    [MemberData(nameof(ConstructorCases))]
    public void Constructor_filter_and_subsequent_setter_match_microsoft(string overload, string? filter)
    {
        using var microsoft = CreateMicrosoft(overload, filter);
        using var ours = CreateOurs(overload, filter);

        // Microsoft assigns the constructor argument directly, whereas its
        // property setter normalizes null/empty. Capture both states so the
        // first mismatch does not prevent exercising the setter transition.
        var expectedInitial = microsoft.Filter;
        var actualInitial = ours.Filter;
        microsoft.Filter = ours.Filter = "(cn=example)";
        microsoft.Filter = filter;
        ours.Filter = filter;

        Assert.Equal(
            new[] { expectedInitial, microsoft.Filter },
            new[] { actualInitial, ours.Filter });
    }

    private static Ms.DirectorySearcher CreateMicrosoft(string overload, string? filter) => overload switch
    {
        "filter" => new(filter),
        "filter-properties" => new(filter, new[] { "cn" }),
        "filter-properties-scope" => new(filter, new[] { "cn" }, Ms.SearchScope.OneLevel),
        "root-filter" => new((Ms.DirectoryEntry?)null, filter),
        "root-filter-properties" => new(null, filter, new[] { "cn" }),
        "root-filter-properties-scope" => new(null, filter, new[] { "cn" }, Ms.SearchScope.OneLevel),
        _ => throw new ArgumentOutOfRangeException(nameof(overload)),
    };

    private static Ours.DirectorySearcher CreateOurs(string overload, string? filter) => overload switch
    {
        "filter" => new(filter),
        "filter-properties" => new(filter, new[] { "cn" }),
        "filter-properties-scope" => new(filter, new[] { "cn" }, Ours.SearchScope.OneLevel),
        "root-filter" => new((Ours.DirectoryEntry?)null, filter),
        "root-filter-properties" => new(null, filter, new[] { "cn" }),
        "root-filter-properties-scope" => new(null, filter, new[] { "cn" }, Ours.SearchScope.OneLevel),
        _ => throw new ArgumentOutOfRangeException(nameof(overload)),
    };
}
