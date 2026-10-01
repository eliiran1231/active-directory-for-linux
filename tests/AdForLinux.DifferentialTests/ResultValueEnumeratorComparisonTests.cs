using System.Collections;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class ResultValueEnumeratorComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false, "before")]
    [InlineData(false, "positioned")]
    [InlineData(false, "finished")]
    [InlineData(true, "before")]
    [InlineData(true, "positioned")]
    [InlineData(true, "finished")]
    public void Current_position_validation_matches(bool throughInterface, string position)
    {
        var (microsoft, ours) = CreateEnumerators(throughInterface);
        try
        {
            Position(microsoft, position);
            Position(ours, position);
            Compare(Observe(() => microsoft.Current), Observe(() => ours.Current));
        }
        finally
        {
            (microsoft as IDisposable)?.Dispose();
            (ours as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [InlineData(false, "before")]
    [InlineData(false, "positioned")]
    [InlineData(false, "finished")]
    [InlineData(true, "before")]
    [InlineData(true, "positioned")]
    [InlineData(true, "finished")]
    public void Reset_restarts_traversal_like_microsoft(bool throughInterface, string position)
    {
        var (microsoft, ours) = CreateEnumerators(throughInterface);
        try
        {
            Position(microsoft, position);
            Position(ours, position);
            var expected = ResetAndRead(microsoft);
            var actual = ResetAndRead(ours);
            Compare(expected, actual);
        }
        finally
        {
            (microsoft as IDisposable)?.Dispose();
            (ours as IDisposable)?.Dispose();
        }
    }

    private static (IEnumerator Microsoft, IEnumerator Ours) CreateEnumerators(bool throughInterface)
    {
        object[] values = { "first", "second" };
        // Invoke the normal decoder-facing constructor, as in the existing
        // deferred-error tests. No private fields or uninitialized objects.
        var constructor = typeof(Ms.ResultPropertyValueCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(object[]) }, null);
        Assert.NotNull(constructor);
        var microsoft = Assert.IsType<Ms.ResultPropertyValueCollection>(constructor.Invoke(new object[] { values }));
        var ours = new Ours.ResultPropertyValueCollection(values);
        // Keep concrete call sites: casting both to IEnumerable would hide the
        // clone's public GetEnumerator method and miss this incompatibility.
        return throughInterface
            ? (((IEnumerable)microsoft).GetEnumerator(), ((IEnumerable)ours).GetEnumerator())
            : (microsoft.GetEnumerator(), ours.GetEnumerator());
    }

    private static void Position(IEnumerator enumerator, string position)
    {
        if (position == "before") return;
        Assert.True(enumerator.MoveNext());
        Assert.Equal("first", enumerator.Current);
        if (position == "positioned") return;
        Assert.True(enumerator.MoveNext());
        Assert.Equal("second", enumerator.Current);
        Assert.False(enumerator.MoveNext());
    }

    private static string ResetAndRead(IEnumerator enumerator)
    {
        var reset = Observe(() => { enumerator.Reset(); return "reset"; });
        var current = Observe(() => enumerator.Current);
        var values = new List<object?>();
        while (enumerator.MoveNext()) values.Add(enumerator.Current);
        return $"{reset}; Current={current}; remaining={string.Join(",", values)}";
    }

    private static string Observe(Func<object?> action)
    {
        try { return $"value:{action() ?? "<null>"}"; }
        catch (Exception error) { return $"error:{error.GetType().FullName}"; }
    }

    private void Compare(string expected, string actual)
    {
        output.WriteLine($"Microsoft: {expected}");
        output.WriteLine($"AdForLinux: {actual}");
        Assert.Equal(expected, actual);
    }
}
