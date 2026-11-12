using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// The shared fixture creates/deletes AD objects; use a verified disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySearchResultLifecycleComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;
    public CompatibilitySearchResultLifecycleComparisonTests(TestDataFixture data) => _data = data;

    public static IEnumerable<object[]> IdentityCases()
    {
        foreach (var materialized in new[] { false, true })
            foreach (var operation in new[]
            {
                "repeated-enumeration", "enumeration-vs-indexer", "contains-enumerated",
                "contains-indexed", "index-of-enumerated", "index-of-indexed",
            })
                yield return new object[] { materialized, operation };
    }

    [Theory]
    [MemberData(nameof(IdentityCases))]
    public void Enumeration_and_materialized_lookup_identity_match_microsoft(bool materializeFirst, string operation)
    {
        WithResults((microsoft, ours) =>
        {
            if (materializeFirst)
            {
                Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 35), SuiteCapture.Expected(microsoft.Count, "assert-equal-actual", 35));
                Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 36), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 36));
            }
            var expectedFirst = microsoft.Cast<Ms.SearchResult>().ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            var actualFirst = ours.Cast<Ours.SearchResult>().ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            var expectedSecond = microsoft.Cast<Ms.SearchResult>().ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            var actualSecond = ours.Cast<Ours.SearchResult>().ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 42), SuiteCapture.Expected(microsoft.Count, "assert-equal-actual", 42));
            Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 43), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 43));
            var expectedIndexed = Enumerable.Range(0, microsoft.Count).Select(i => microsoft[i])
                .ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            var actualIndexed = Enumerable.Range(0, ours.Count).Select(i => ours[i])
                .ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
            var keys = expectedIndexed.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray();
            Assert.Equal(SuiteCapture.Expected(keys, "assert-equal-expected", 49), SuiteCapture.Expected(actualIndexed.Keys.Order(StringComparer.OrdinalIgnoreCase), "assert-equal-actual", 49), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(SuiteCapture.Expected(keys, "assert-equal-expected", 50), SuiteCapture.Expected(expectedFirst.Keys.Order(StringComparer.OrdinalIgnoreCase), "assert-equal-actual", 50), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(SuiteCapture.Expected(keys, "assert-equal-expected", 51), SuiteCapture.Expected(expectedSecond.Keys.Order(StringComparer.OrdinalIgnoreCase), "assert-equal-actual", 51), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(SuiteCapture.Expected(keys, "assert-equal-expected", 52), SuiteCapture.Expected(actualFirst.Keys.Order(StringComparer.OrdinalIgnoreCase), "assert-equal-actual", 52), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(SuiteCapture.Expected(keys, "assert-equal-expected", 53), SuiteCapture.Expected(actualSecond.Keys.Order(StringComparer.OrdinalIgnoreCase), "assert-equal-actual", 53), StringComparer.OrdinalIgnoreCase);

            foreach (var key in keys)
            {
                // Compare reference relationships within each implementation.
                // LDAP result order and wrappers from different APIs need not match.
                var expected = operation switch
                {
                    "repeated-enumeration" => ReferenceEquals(expectedFirst[key], expectedSecond[key]),
                    "enumeration-vs-indexer" => ReferenceEquals(expectedFirst[key], expectedIndexed[key]),
                    "contains-enumerated" => microsoft.Contains(expectedFirst[key]),
                    "contains-indexed" => microsoft.Contains(expectedIndexed[key]),
                    "index-of-enumerated" => microsoft.IndexOf(expectedFirst[key]) >= 0,
                    _ => microsoft.IndexOf(expectedIndexed[key]) is var i && i >= 0 &&
                        ReferenceEquals(expectedIndexed[key], microsoft[i]),
                };
                var actual = operation switch
                {
                    "repeated-enumeration" => ReferenceEquals(actualFirst[key], actualSecond[key]),
                    "enumeration-vs-indexer" => ReferenceEquals(actualFirst[key], actualIndexed[key]),
                    "contains-enumerated" => ours.Contains(actualFirst[key]),
                    "contains-indexed" => ours.Contains(actualIndexed[key]),
                    "index-of-enumerated" => ours.IndexOf(actualFirst[key]) >= 0,
                    _ => ours.IndexOf(actualIndexed[key]) is var i && i >= 0 &&
                        ReferenceEquals(actualIndexed[key], ours[i]),
                };
                Assert.Equal(SuiteCapture.Expected(expected, "assert-equal-expected", 79), SuiteCapture.Expected(actual, "assert-equal-actual", 79));
            }
        });
    }

    public static IEnumerable<object[]> DisposedCases()
    {
        foreach (var materialized in new[] { false, true })
            foreach (var operation in new[]
            {
                "count", "index-zero", "index-negative", "contains-null", "index-of-null",
                "typed-copy", "collection-copy", "enumerate", "dispose-again",
            })
                yield return new object[] { materialized, operation };
    }

    [Theory]
    [MemberData(nameof(DisposedCases))]
    public void Disposed_collection_access_matches_microsoft(bool materialized, string operation)
    {
        WithResults((microsoft, ours) =>
        {
            if (materialized)
            {
                Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 103), SuiteCapture.Expected(microsoft.Count, "assert-equal-actual", 103));
                Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 104), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 104));
            }
            microsoft.Dispose();
            ours.Dispose();
            Assert.Equal(SuiteCapture.Expected(Observe(() => ReadMicrosoft(microsoft, operation)), "assert-equal-expected", 108),
                SuiteCapture.Expected(Observe(() => ReadOurs(ours, operation)), "assert-equal-actual", 108));
        });
    }

    private static string ReadMicrosoft(Ms.SearchResultCollection results, string operation)
    {
        switch (operation)
        {
            case "count": return results.Count.ToString();
            case "index-zero": return results[0] is null ? "null" : "row";
            case "index-negative": return Key(results[-1]);
            case "contains-null": return results.Contains(null!).ToString();
            case "index-of-null": return results.IndexOf(null!).ToString();
            case "typed-copy":
            case "collection-copy":
                var destination = new Ms.SearchResult[2];
                if (operation == "typed-copy") results.CopyTo(destination, 0);
                else ((ICollection)results).CopyTo(destination, 0);
                return string.Join("|", destination.Select(row => row is null ? "null" : Key(row)).Order());
            case "enumerate": return string.Join("|", results.Cast<Ms.SearchResult>().Select(Key).Order());
            default: results.Dispose(); return "disposed";
        }
    }

    private static string ReadOurs(Ours.SearchResultCollection results, string operation)
    {
        switch (operation)
        {
            case "count": return results.Count.ToString();
            case "index-zero": return results[0] is null ? "null" : "row";
            case "index-negative": return Key(results[-1]);
            case "contains-null": return results.Contains(null!).ToString();
            case "index-of-null": return results.IndexOf(null!).ToString();
            case "typed-copy":
            case "collection-copy":
                var destination = new Ours.SearchResult[2];
                if (operation == "typed-copy") results.CopyTo(destination, 0);
                else ((ICollection)results).CopyTo(destination, 0);
                return string.Join("|", destination.Select(row => row is null ? "null" : Key(row)).Order());
            case "enumerate": return string.Join("|", results.Cast<Ours.SearchResult>().Select(Key).Order());
            default: results.Dispose(); return "disposed";
        }
    }

    private static string Observe(Func<string> read)
    {
        try { return $"value:{read()}"; }
        catch (Exception error)
        {
            return $"error:{error.GetType().FullName};parameter:{(error as ArgumentException)?.ParamName}";
        }
    }

    private static string Key(Ms.SearchResult row) => ((string)row.Properties["distinguishedName"][0]!).ToUpperInvariant();
    private static string Key(Ours.SearchResult row) => ((string)row.Properties["distinguishedName"][0]!).ToUpperInvariant();

    private void WithResults(Action<Ms.SearchResultCollection, Ours.SearchResultCollection> action)
    {
        using var microsoftRoot = new Ms.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        var filter = $"(|(sAMAccountName={_data.UserName})(sAMAccountName={_data.UnsetUserName}))";
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        { Filter = filter, SearchScope = Ms.SearchScope.OneLevel, CacheResults = true };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        { Filter = filter, SearchScope = Ours.SearchScope.OneLevel, CacheResults = true };
        // Validate both query shapes in separate collections so the actual
        // unmaterialized disposal case does not inadvertently read Count first.
        using (var expectedProbe = microsoftSearcher.FindAll())
        using (var actualProbe = ourSearcher.FindAll())
        {
            var expectedKeys = new[] { _data.UserDn.ToUpperInvariant(), _data.UnsetUserDn.ToUpperInvariant() }.Order().ToArray();
            Assert.Equal(SuiteCapture.Expected(expectedKeys, "assert-equal-expected", 182), SuiteCapture.Expected(expectedProbe.Cast<Ms.SearchResult>().Select(Key).Order(), "assert-equal-actual", 182));
            Assert.Equal(SuiteCapture.Expected(expectedKeys, "assert-equal-expected", 183), SuiteCapture.Expected(actualProbe.Cast<Ours.SearchResult>().Select(Key).Order(), "assert-equal-actual", 183));
        }
        using var microsoft = microsoftSearcher.FindAll();
        using var ours = ourSearcher.FindAll();
        action(microsoft, ours);
    }
}
