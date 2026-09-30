using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public sealed class PrincipalValueCollectionOfflineComparisonTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void Non_generic_add_return_value_matches_microsoft(int initialCount)
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.PrincipalValueCollection<string>();
        for (var i = 0; i < initialCount; i++)
        {
            microsoft.Add($"HOST/existing-{i}");
            ours.Add($"HOST/existing-{i}");
        }

        var expected = ((IList)microsoft).Add("HOST/new");
        var actual = ((IList)ours).Add("HOST/new");

        Assert.Equal(microsoft.ToArray(), ours.ToArray());
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("before-first")]
    [InlineData("after-last")]
    [InlineData("after-reset")]
    [InlineData("positioned")]
    public void Generic_enumerator_current_matches_microsoft(string position)
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.PrincipalValueCollection<string>();
        microsoft.Add("HOST/first");
        ours.Add("HOST/first");
        using var expected = microsoft.GetEnumerator();
        using var actual = ours.GetEnumerator();

        Position(expected, position);
        Position(actual, position);
        string? expectedValue = null;
        string? actualValue = null;
        var expectedError = Record.Exception(() => { expectedValue = expected.Current; });
        var actualError = Record.Exception(() => { actualValue = actual.Current; });

        Assert.Equal(expectedError?.GetType(), actualError?.GetType());
        Assert.Equal(expectedValue, actualValue);
    }

    [Theory]
    [InlineData("Current")]
    [InlineData("MoveNext")]
    [InlineData("Reset")]
    public void Disposed_enumerator_operations_match_microsoft(string operation)
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.PrincipalValueCollection<string>();
        microsoft.Add("HOST/first");
        ours.Add("HOST/first");
        using var expected = microsoft.GetEnumerator();
        using var actual = ours.GetEnumerator();
        Assert.True(expected.MoveNext());
        Assert.True(actual.MoveNext());
        expected.Dispose();
        actual.Dispose();

        var expectedError = Record.Exception(() => Exercise(expected, operation));
        var actualError = Record.Exception(() => Exercise(actual, operation));

        Assert.IsType<ObjectDisposedException>(expectedError);
        Assert.Equal(expectedError?.GetType(), actualError?.GetType());
    }

    private static void Position(IEnumerator<string> enumerator, string position)
    {
        switch (position)
        {
            case "before-first": break;
            case "positioned": Assert.True(enumerator.MoveNext()); break;
            case "after-last":
                Assert.True(enumerator.MoveNext());
                Assert.False(enumerator.MoveNext());
                break;
            case "after-reset":
                Assert.True(enumerator.MoveNext());
                enumerator.Reset();
                break;
            default: throw new ArgumentOutOfRangeException(nameof(position));
        }
    }

    private static void Exercise(IEnumerator<string> enumerator, string operation)
    {
        switch (operation)
        {
            case "Current": _ = enumerator.Current; break;
            case "MoveNext": enumerator.MoveNext(); break;
            case "Reset": enumerator.Reset(); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static Ms.PrincipalValueCollection<string> CreateMicrosoft()
    {
        // Invoke the normal empty constructor; no uninitialized objects or
        // private-field edits. All behavior under test uses the public API.
        // This isolates the collection from PrincipalContext's AD discovery.
        var constructor = typeof(Ms.PrincipalValueCollection<string>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<string>>(constructor.Invoke(null));
    }
}
