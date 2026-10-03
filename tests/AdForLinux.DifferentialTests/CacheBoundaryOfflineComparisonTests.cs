using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CacheBoundaryOffline")]
public sealed class CacheBoundaryOfflineComparisonTests
{
    [Fact]
    public void Property_names_enumerator_still_requires_a_live_owner_control()
    {
        using var expected = new Ms.DirectoryEntry();
        using var actual = new Ours.DirectoryEntry();
        expected.Dispose();
        actual.Dispose();
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => expected.Properties.PropertyNames.GetEnumerator()));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => actual.Properties.PropertyNames.GetEnumerator()));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Values_enumerator_creation_and_reset_defer_binding(bool reset)
    {
        using var expected = new Ms.DirectoryEntry();
        using var actual = new Ours.DirectoryEntry();
        expected.Dispose();
        actual.Dispose();
        IEnumerator? left = null, right = null;
        var leftError = Record.Exception(() =>
        {
            left = expected.Properties.Values.GetEnumerator();
            if (reset) left.Reset();
        });
        var rightError = Record.Exception(() =>
        {
            right = actual.Properties.Values.GetEnumerator();
            if (reset) right.Reset();
        });
        try
        {
            Assert.Null(leftError); // Oracle control: no default-domain discovery.
            new Comparison("Values cursor creation after owner disposal")
                .Check("exception", leftError?.GetType().Name, rightError?.GetType().Name)
                .Assert();
        }
        finally
        {
            (left as IDisposable)?.Dispose();
            (right as IDisposable)?.Dispose();
        }
    }
}
