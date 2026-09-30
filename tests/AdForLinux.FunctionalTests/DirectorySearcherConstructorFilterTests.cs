using System.Reflection;
using AdForLinux.DirectoryServices;
using Xunit;
using SearchRequest = System.DirectoryServices.Protocols.SearchRequest;

namespace AdForLinux.FunctionalTests;

public class DirectorySearcherConstructorFilterTests
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
    public void Request_uses_effective_filter_without_changing_constructor_value(string overload, string? filter)
    {
        using var root = new DirectoryEntry("LDAP://localhost/DC=example,DC=com");
        using var searcher = overload switch
        {
            "filter" => new DirectorySearcher(filter),
            "filter-properties" => new DirectorySearcher(filter, new[] { "cn" }),
            "filter-properties-scope" => new DirectorySearcher(filter, new[] { "cn" }, SearchScope.OneLevel),
            "root-filter" => new DirectorySearcher(root, filter),
            "root-filter-properties" => new DirectorySearcher(root, filter, new[] { "cn" }),
            "root-filter-properties-scope" => new DirectorySearcher(root, filter, new[] { "cn" }, SearchScope.OneLevel),
            _ => throw new ArgumentOutOfRangeException(nameof(overload)),
        };
        searcher.SearchRoot = root;
        Assert.Equal(filter, searcher.Filter);

        // Exercise the request path shared by FindOne/FindAll without requiring AD.
        var buildRequest = typeof(DirectorySearcher).GetMethod(
            "BuildRequest", BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null)!;
        var request = Assert.IsType<SearchRequest>(buildRequest.Invoke(searcher, null));

        Assert.Equal(string.IsNullOrEmpty(filter) ? "(objectClass=*)" : filter, request.Filter);
        Assert.Equal(filter, searcher.Filter);
    }
}
