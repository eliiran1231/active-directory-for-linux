using System.Collections;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;
#if !RECORDED_MICROSOFT_ORACLE
using Ms = System.DirectoryServices;
#endif
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
        var caseId = $"{GetType().FullName}.{nameof(Current_position_validation_matches)}(throughInterface: {throughInterface}, position: \"{position}\")";
#if RECORDED_MICROSOFT_ORACLE
        var ours = CreateOurEnumerator(throughInterface);
#else
        var (microsoft, ours) = CreateEnumerators(throughInterface);
#endif
        try
        {
            Position(ours, position);
#if RECORDED_MICROSOFT_ORACLE
            var expected = RecordedMicrosoftOracle.Read(caseId);
#else
            Position(microsoft, position);
            var expected = Observe(() => microsoft.Current);
#endif
            Compare(caseId, expected, Observe(() => ours.Current));
        }
        finally
        {
#if !RECORDED_MICROSOFT_ORACLE
            (microsoft as IDisposable)?.Dispose();
#endif
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
        var caseId = $"{GetType().FullName}.{nameof(Reset_restarts_traversal_like_microsoft)}(throughInterface: {throughInterface}, position: \"{position}\")";
#if RECORDED_MICROSOFT_ORACLE
        var ours = CreateOurEnumerator(throughInterface);
#else
        var (microsoft, ours) = CreateEnumerators(throughInterface);
#endif
        try
        {
            Position(ours, position);
#if RECORDED_MICROSOFT_ORACLE
            var expected = RecordedMicrosoftOracle.Read(caseId);
#else
            Position(microsoft, position);
            var expected = ResetAndRead(microsoft);
#endif
            var actual = ResetAndRead(ours);
            Compare(caseId, expected, actual);
        }
        finally
        {
#if !RECORDED_MICROSOFT_ORACLE
            (microsoft as IDisposable)?.Dispose();
#endif
            (ours as IDisposable)?.Dispose();
        }
    }

    private static IEnumerator CreateOurEnumerator(bool throughInterface)
    {
        var ours = new Ours.ResultPropertyValueCollection(new object[] { "first", "second" });
        return throughInterface ? ((IEnumerable)ours).GetEnumerator() : ours.GetEnumerator();
    }

#if !RECORDED_MICROSOFT_ORACLE
    private static (IEnumerator Microsoft, IEnumerator Ours) CreateEnumerators(bool throughInterface)
    {
        object[] values = { "first", "second" };
        // Invoke the normal decoder-facing constructor, as in the existing
        // deferred-error tests. No private fields or uninitialized objects.
        var constructor = typeof(Ms.ResultPropertyValueCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(object[]) }, null);
        Assert.NotNull(constructor);
        var microsoft = Assert.IsType<Ms.ResultPropertyValueCollection>(constructor.Invoke(new object[] { values }));
        // Keep concrete call sites: casting both to IEnumerable would hide the
        // clone's public GetEnumerator method and miss this incompatibility.
        return throughInterface
            ? (((IEnumerable)microsoft).GetEnumerator(), CreateOurEnumerator(true))
            : (microsoft.GetEnumerator(), CreateOurEnumerator(false));
    }

#endif

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

    private void Compare(string caseId, string expected, string actual)
    {
        output.WriteLine($"Microsoft: {expected}");
        output.WriteLine($"AdForLinux: {actual}");
#if !RECORDED_MICROSOFT_ORACLE
        DifferentialRecording.Write(output, caseId, expected, actual);
#endif
        Assert.Equal(expected, actual);
    }
}
