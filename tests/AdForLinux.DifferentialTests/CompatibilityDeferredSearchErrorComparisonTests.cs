using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityDeferredSearchErrorComparisonTests : IClassFixture<TestDataFixture>
{
    private const string EmptyFilter = "(&(objectClass=*)(!(objectClass=*)))";
    private readonly TestDataFixture _data;

    public CompatibilityDeferredSearchErrorComparisonTests(TestDataFixture data) => _data = data;

    public static IEnumerable<object[]> SearchModes()
    {
        foreach (var filter in new[] { "(|invalid)", "(&(cn=broken)", "(cn=broken))", EmptyFilter })
        {
            yield return new object[] { filter, true, false };
            yield return new object[] { filter, false, false };
            yield return new object[] { filter, false, true };
        }
    }

    [Theory]
    [MemberData(nameof(SearchModes))]
    public void Filter_error_stage_contract_and_same_searcher_recovery_match_microsoft(
        string filter, bool cache, bool asynchronous)
    {
        // The known fixture object limits even unexpectedly accepted filters to
        // one entry. The valid empty control distinguishes deferred validation
        // from environmental failures, without searching unrelated accounts.
        using var expectedRoot = new Ms.DirectoryEntry(DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actualRoot = new Ours.DirectoryEntry(DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        // Fail on setup connectivity before attributing any difference to a filter.
        Assert.Equal(_data.UserName, expectedRoot.Properties["sAMAccountName"].Value);
        Assert.Equal(_data.UserName, actualRoot.Properties["sAMAccountName"].Value);
        using var expected = new Ms.DirectorySearcher(expectedRoot, filter)
        {
            SearchScope = Ms.SearchScope.Base, CacheResults = cache, Asynchronous = asynchronous,
        };
        using var actual = new Ours.DirectorySearcher(actualRoot, filter)
        {
            SearchScope = Ours.SearchScope.Base, CacheResults = cache, Asynchronous = asynchronous,
        };

        var left = Observe(() => expected.FindAll());
        var right = Observe(() => actual.FindAll());
        expected.Filter = actual.Filter = EmptyFilter;
        var leftRecovery = Observe(() => expected.FindAll());
        var rightRecovery = Observe(() => actual.FindAll());
        var comparison = new Comparison($"Filter={filter}, cache={cache}, async={asynchronous}");
        Compare(comparison, "initial", left, right);
        Compare(comparison, "recovery", leftRecovery, rightRecovery);
        comparison.Assert();
        // A failing connection or unsupported option must not pass just because
        // both sides failed similarly. The recovery must execute an empty search.
        Assert.True(leftRecovery.Completed, "Microsoft recovery did not complete: " + leftRecovery);
        Assert.Equal(0, leftRecovery.Rows);
        if (filter == EmptyFilter)
        {
            Assert.True(left.Completed, "Microsoft valid empty control failed: " + left);
            Assert.Equal(0, left.Rows);
        }
    }

    private sealed record Observation(string Stage, string? ExceptionType, int? HResult,
        string? Parameter, int Rows, bool Completed);

    private static Observation Observe(Func<IEnumerable> findAll)
    {
        IEnumerable? results = null;
        IEnumerator? iterator = null;
        var stage = "FindAll";
        var rows = 0;
        var error = Record.Exception(() =>
        {
            results = findAll();
            stage = "GetEnumerator";
            iterator = results.GetEnumerator();
            stage = "first MoveNext";
            while (iterator.MoveNext())
            {
                stage = "Current";
                _ = iterator.Current;
                rows++;
                stage = "subsequent MoveNext";
            }
            stage = "complete";
        });
        try
        {
            return new Observation(stage, error?.GetType().Name, error?.HResult,
                (error as ArgumentException)?.ParamName, rows, error is null);
        }
        finally
        {
            (iterator as IDisposable)?.Dispose();
            (results as IDisposable)?.Dispose();
        }
    }

    private static void Compare(Comparison comparison, string prefix, Observation expected, Observation actual) => comparison
        .Check($"{prefix}: stage", expected.Stage, actual.Stage)
        .Check($"{prefix}: exception", expected.ExceptionType, actual.ExceptionType)
        .Check($"{prefix}: HResult", expected.HResult, actual.HResult)
        .Check($"{prefix}: parameter", expected.Parameter, actual.Parameter)
        .Check($"{prefix}: rows", expected.Rows, actual.Rows)
        .Check($"{prefix}: completed", expected.Completed, actual.Completed);
}
