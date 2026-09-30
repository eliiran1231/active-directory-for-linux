using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public sealed class PrincipalSearchResultPositionComparisonTests
{
    [Theory]
    [InlineData("before-start", false, false)]
    [InlineData("after-end", false, false)]
    [InlineData("after-reset", false, false)]
    [InlineData("before-start", true, false)]
    [InlineData("after-end", true, false)]
    [InlineData("after-reset", true, false)]
    [InlineData("before-start", false, true)] // Array-backed empty results are controls.
    [InlineData("after-end", false, true)]
    [InlineData("after-reset", false, true)]
    [InlineData("before-start", true, true)]
    [InlineData("after-end", true, true)]
    [InlineData("after-reset", true, true)]
    public void Empty_result_Current_matches_position_validation(
        string position, bool nonGeneric, bool arrayBacked)
    {
        using var microsoft = CreateMicrosoftEmptyResult();
        // FindAll and GetMembers build List<Principal> results. Other paths use
        // Array.Empty<Principal>; the public contract should not depend on storage.
        using var ours = new Ours.PrincipalSearchResult<Ours.Principal>(arrayBacked
            ? Array.Empty<Ours.Principal>()
            : new List<Ours.Principal>());
        using var expectedEnumerator = microsoft.GetEnumerator();
        using var actualEnumerator = ours.GetEnumerator();
        PositionEmpty(expectedEnumerator, position);
        PositionEmpty(actualEnumerator, position);

        var expected = ObserveCurrent(expectedEnumerator, nonGeneric);
        var actual = ObserveCurrent(actualEnumerator, nonGeneric);

        Assert.Equal(typeof(InvalidOperationException), expected.Error);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Empty_list_result_traversal_reset_and_disposal_match()
    {
        using var microsoft = CreateMicrosoftEmptyResult();
        using var ours = new Ours.PrincipalSearchResult<Ours.Principal>(new List<Ours.Principal>());
        using var expected = microsoft.GetEnumerator();
        using var actual = ours.GetEnumerator();

        // Control: ordinary traversal, reset, and disposal still work alike.
        Assert.False(expected.MoveNext());
        Assert.False(actual.MoveNext());
        Assert.Equal(expected.MoveNext(), actual.MoveNext());
        expected.Reset();
        actual.Reset();
        Assert.Equal(expected.MoveNext(), actual.MoveNext());
        expected.Dispose();
        actual.Dispose();
        Assert.Equal(ObserveCurrent(expected, false), ObserveCurrent(actual, false));
        Assert.Equal(ObserveCurrent(expected, true), ObserveCurrent(actual, true));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => expected.MoveNext()));
        Assert.IsType<ObjectDisposedException>(Record.Exception(() => actual.MoveNext()));
    }

    private static void PositionEmpty(IEnumerator enumerator, string position)
    {
        if (position == "before-start") return;
        Assert.False(enumerator.MoveNext());
        if (position == "after-reset") enumerator.Reset();
    }

    internal static (Type? Error, bool ReturnedNull) ObserveCurrent<T>(
        IEnumerator<T> enumerator, bool nonGeneric)
    {
        var returnedNull = false;
        var error = Record.Exception(() =>
        {
            object? current = nonGeneric ? ((IEnumerator)enumerator).Current : enumerator.Current;
            returnedNull = current is null;
        });
        return (error?.GetType(), returnedNull);
    }

    private static Ms.PrincipalSearchResult<Ms.Principal> CreateMicrosoftEmptyResult()
    {
        // Same normal EmptySet fixture as LifecycleComparisonTests. Reflection
        // is limited to constructors; no uninitialized objects or field edits.
        var assembly = typeof(Ms.Principal).Assembly;
        var resultSetType = assembly.GetType(
            "System.DirectoryServices.AccountManagement.ResultSet", throwOnError: true)!;
        var emptySetType = assembly.GetType(
            "System.DirectoryServices.AccountManagement.EmptySet", throwOnError: true)!;
        var emptySet = Activator.CreateInstance(emptySetType, nonPublic: true)!;
        var constructor = typeof(Ms.PrincipalSearchResult<Ms.Principal>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { resultSetType }, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalSearchResult<Ms.Principal>>(
            constructor.Invoke(new[] { emptySet }));
    }
}
