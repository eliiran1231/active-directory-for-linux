using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Owner disposal precedes every operation that might otherwise bind.
[Trait("Category", "DisposedPropertyContainsOffline")]
public sealed class CompatibilityDisposedPropertyContainsComparisonTests
{
    [Theory]
    [InlineData("contains-null")]
    [InlineData("contains-name")]
    [InlineData("indexer-null")]
    public void Disposed_owner_and_null_name_validation_have_matching_precedence(string operation)
    {
        using var expected = new Ms.DirectoryEntry();
        using var actual = new Ours.DirectoryEntry();
        var left = expected.Properties;
        var right = actual.Properties;
        expected.Dispose();
        actual.Dispose();
        var leftError = Record.Exception(() =>
        {
            if (operation == "indexer-null") _ = left[null!];
            else _ = left.Contains(operation == "contains-null" ? null! : "description");
        });
        var rightError = Record.Exception(() =>
        {
            if (operation == "indexer-null") _ = right[null!];
            else _ = right.Contains(operation == "contains-null" ? null! : "description");
        });
        // These are local validation outcomes, not failed connection attempts.
        if (operation == "indexer-null") Assert.IsType<ArgumentNullException>(leftError);
        else Assert.IsType<ObjectDisposedException>(leftError);
        new Comparison($"Disposed property name validation: {operation}")
            .Check("exception", leftError?.GetType(), rightError?.GetType())
            .Check("parameter", (leftError as ArgumentException)?.ParamName, (rightError as ArgumentException)?.ParamName)
            .Check("disposed object", (leftError as ObjectDisposedException)?.ObjectName,
                (rightError as ObjectDisposedException)?.ObjectName)
            .Assert();
    }
}
