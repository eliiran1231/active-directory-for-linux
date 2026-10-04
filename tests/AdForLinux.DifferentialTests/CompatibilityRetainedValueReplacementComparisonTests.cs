using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// The fixture needs a verified disposable AD lab. All test writes stay in
// fresh caches with UsePropertyCache=true; no CommitChanges or Save occurs.
[Collection("differential")]
[Trait("Category", "RetainedValueReplacementLive")]
public sealed class CompatibilityRetainedValueReplacementComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData("scalar", false)]
    [InlineData("scalar", true)]
    [InlineData("array", false)]
    [InlineData("array", true)]
    [InlineData("null", false)]
    [InlineData("null", true)]
    public void Whole_value_replacement_preserves_matching_local_state_after_owner_disposal(string replacement, bool dispose)
    {
        using var expected = new Ms.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        Assert.True(expected.UsePropertyCache);
        Assert.True(actual.UsePropertyCache);
        var left = expected.Properties["description"];
        var right = actual.Properties["description"];
        Assert.NotEmpty(left);
        Assert.Equal(left.Cast<object?>().ToArray(), right.Cast<object?>().ToArray());

        if (dispose)
        {
            expected.Dispose();
            actual.Dispose();
        }

        var leftError = Record.Exception(() => left.Value = Replacement(replacement));
        var rightError = Record.Exception(() => right.Value = Replacement(replacement));
        if (dispose) Assert.IsType<ObjectDisposedException>(leftError);
        else Assert.Null(leftError);

        var comparison = new Comparison($"Retained property replacement: {replacement}, disposed={dispose}")
            .Check("setter error", leftError?.GetType(), rightError?.GetType())
            .Check("disposed object", (leftError as ObjectDisposedException)?.ObjectName,
                (rightError as ObjectDisposedException)?.ObjectName)
            .Check("local count after attempt", left.Count, right.Count);
        // Read the retained wrappers only; a fresh entry.Properties lookup
        // would instead test rebinding and could hide the partial mutation.
        comparison.Check("local contents after attempt", string.Join("|", left.Cast<object?>()),
            string.Join("|", right.Cast<object?>()))
            .Check("Value is null", left.Value is null, right.Value is null)
            .Check("Value is array", left.Value is object[], right.Value is object[])
            .Assert();
    }

    private static object? Replacement(string kind) => kind switch
    {
        "scalar" => "pending-scalar",
        "array" => new object[] { "pending-first", "pending-second" },
        "null" => null,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}
