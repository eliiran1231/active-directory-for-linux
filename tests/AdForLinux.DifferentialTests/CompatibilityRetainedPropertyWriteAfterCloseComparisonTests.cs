using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Fixture setup/cleanup requires a separately authorized disposable AD lab.
// The writes below remain cached: no CommitChanges or Save is performed.
// The retained-wrapper case is a source-derived hypothesis until run against
// the pinned Microsoft package in that lab.
[Collection("differential")]
[Trait("Category", "RetainedPropertyWriteAfterCloseLive")]
public sealed class CompatibilityRetainedPropertyWriteAfterCloseComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData("retained-without-close")]
    [InlineData("retained-after-close")]
    [InlineData("fresh-after-close")]
    public void Cached_write_through_retained_or_fresh_wrapper_matches_after_close(string scenario)
    {
        const string seeded = "differential test user";
        const string pending = "pending retained wrapper comparison";
        using var expected = new Ms.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        Assert.True(expected.UsePropertyCache);
        Assert.True(actual.UsePropertyCache);
        var leftProperties = expected.Properties;
        var rightProperties = actual.Properties;
        var leftRetained = leftProperties["description"];
        var rightRetained = rightProperties["description"];
        Assert.Equal(seeded, Assert.IsType<string>(leftRetained.Value));
        Assert.Equal(seeded, Assert.IsType<string>(rightRetained.Value));
        Assert.Equal(data.UserDn, Assert.IsType<string>(leftProperties["distinguishedName"].Value),
            StringComparer.OrdinalIgnoreCase);
        Assert.Equal(data.UserDn, Assert.IsType<string>(rightProperties["distinguishedName"].Value),
            StringComparer.OrdinalIgnoreCase);

        var close = scenario != "retained-without-close";
        if (close)
        {
            expected.Close();
            actual.Close();
        }

        // In the retained-after-close case, do not obtain or load a new wrapper
        // before the write: that would alter the cache transition under test.
        var leftWriter = scenario == "fresh-after-close" ? expected.Properties["description"] : leftRetained;
        var rightWriter = scenario == "fresh-after-close" ? actual.Properties["description"] : rightRetained;
        Assert.Equal(seeded, Assert.IsType<string>(leftWriter.Value));
        Assert.Equal(seeded, Assert.IsType<string>(rightWriter.Value));
        Assert.True(expected.UsePropertyCache);
        Assert.True(actual.UsePropertyCache);
        var leftError = Record.Exception(() => leftWriter.Value = pending);
        var rightError = Record.Exception(() => rightWriter.Value = pending);
        Assert.Null(leftError);
        Assert.Equal(pending, Assert.IsType<string>(leftWriter.Value));

        var leftCurrentProperties = expected.Properties;
        var rightCurrentProperties = actual.Properties;
        var leftCurrent = leftCurrentProperties["description"];
        var rightCurrent = rightCurrentProperties["description"];
        new Comparison($"Retained property write across Close: {scenario}")
            .Check("setter error", leftError?.GetType(), rightError?.GetType())
            .Check("writer value", leftWriter.Value, rightWriter.Value)
            .Check("current wrapper value", leftCurrent.Value, rightCurrent.Value)
            .Check("retained wrapper value", leftRetained.Value, rightRetained.Value)
            .Check("property collection retained", ReferenceEquals(leftProperties, leftCurrentProperties),
                ReferenceEquals(rightProperties, rightCurrentProperties))
            .Check("current wrapper is retained wrapper", ReferenceEquals(leftRetained, leftCurrent),
                ReferenceEquals(rightRetained, rightCurrent))
            .Check("current wrapper is writer", ReferenceEquals(leftWriter, leftCurrent),
                ReferenceEquals(rightWriter, rightCurrent))
            .Check("repeated current lookup identity", ReferenceEquals(leftCurrent, expected.Properties["description"]),
                ReferenceEquals(rightCurrent, actual.Properties["description"]))
            .Assert();
    }
}
