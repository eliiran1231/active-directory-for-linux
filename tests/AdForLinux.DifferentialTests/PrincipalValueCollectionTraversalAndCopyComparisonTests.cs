using System.Collections;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// No AD required. Reflection invokes only the normal Microsoft constructor;
// every operation being compared is public.
public sealed class PrincipalValueCollectionTraversalAndCopyComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("clear", false)]
    [InlineData("clear", true)]
    [InlineData("remove-current", false)]
    [InlineData("remove-current", true)]
    [InlineData("append-after-end", false)]
    [InlineData("append-after-end", true)]
    [InlineData("append-while-positioned", false)] // Cached Current control.
    [InlineData("append-while-positioned", true)]
    public void Current_after_count_changes_matches_microsoft(string mutation, bool nonGeneric)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        Assert.Equal(ObserveCurrent(microsoft, mutation, nonGeneric),
            ObserveCurrent(ours, mutation, nonGeneric));
    }

    private string ObserveCurrent(IList<string> values, string mutation, bool nonGeneric)
    {
        values.Add("first");
        values.Add("second");
        using var enumerator = values.GetEnumerator();
        Assert.True(enumerator.MoveNext());
        if (mutation is "remove-current" or "append-after-end")
            Assert.True(enumerator.MoveNext());
        if (mutation == "append-after-end")
            Assert.False(enumerator.MoveNext());

        // Current does not check the mutation timestamp in Microsoft's
        // implementation. Do not call MoveNext/Reset after changing the list.
        switch (mutation)
        {
            case "clear": values.Clear(); break;
            case "remove-current": values.RemoveAt(1); break;
            case "append-after-end":
            case "append-while-positioned": values.Add("third"); break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        object? current = null;
        var error = Record.Exception(() => current = nonGeneric
            ? ((IEnumerator)enumerator).Current : enumerator.Current);
        var observation = $"{Describe(error)}; Current={current ?? "<null>"}; Count={values.Count}";
        output.WriteLine($"{values.GetType().Namespace}: {observation}");
        return observation;
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(2, false)]
    [InlineData(2, true)]
    [InlineData(3, false)] // Exact boundary already handled by the clone.
    [InlineData(3, true)]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(1, false)] // Valid copy control.
    [InlineData(1, true)]
    public void Copy_destination_bounds_match_microsoft(int index, bool generic)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        Assert.Equal(ObserveBounds(microsoft, index, generic), ObserveBounds(ours, index, generic));
    }

    private string ObserveBounds(IList<string> values, int index, bool generic)
    {
        values.Add("first");
        values.Add("second");
        var target = new[] { "untouched", "untouched", "untouched" };
        var error = Record.Exception(() =>
        {
            if (generic) values.CopyTo(target, index);
            else ((ICollection)values).CopyTo(target, index);
        });
        var observation = $"{Describe(error)}; Destination=[{string.Join(",", target)}]";
        output.WriteLine($"{values.GetType().Namespace}: {observation}");
        Assert.Equal(new[] { "first", "second" }, values.ToArray());
        return observation;
    }

    private static string Describe(Exception? error) => error is null
        ? "accepted"
        : $"{error.GetType().FullName}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";

    private static Ms.PrincipalValueCollection<T> CreateMicrosoft<T>()
    {
        var constructor = typeof(Ms.PrincipalValueCollection<T>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<T>>(constructor.Invoke(null));
    }
}
