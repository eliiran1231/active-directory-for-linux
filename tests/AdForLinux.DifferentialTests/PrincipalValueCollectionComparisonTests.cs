using System.Collections;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// No AD fixture: only construction uses reflection because neither library exposes
// a public collection constructor. All operations under comparison are public APIs.
public sealed class PrincipalValueCollectionComparisonTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void Non_generic_Add_return_value_matches_microsoft(int initialCount)
    {
        var microsoft = MicrosoftCollection();
        var ours = OurCollection();
        for (var i = 0; i < initialCount; i++)
        {
            microsoft.Add($"HOST/{i}");
            ours.Add($"HOST/{i}");
        }

        var microsoftResult = ((IList)microsoft).Add("HOST/new");
        var ourResult = ((IList)ours).Add("HOST/new");

        Assert.Equal(microsoft.ToArray(), ours.ToArray());
        // Microsoft's IList.Add returns the new Count, even though the usual
        // IList convention (and our implementation) returns the zero-based index.
        new Comparison("PrincipalValueCollection<string>.IList.Add")
            .Check("return value", microsoftResult, ourResult)
            .Check("Count", microsoft.Count, ours.Count)
            .Assert();
    }

    [Theory]
    [InlineData("before-first", false)]
    [InlineData("before-first", true)]
    [InlineData("on-item", false)]
    [InlineData("on-item", true)]
    [InlineData("after-last", false)]
    [InlineData("after-last", true)]
    public void Enumerator_Current_position_validation_matches_microsoft(string position, bool nonGeneric)
    {
        var microsoft = MicrosoftCollection();
        var ours = OurCollection();
        microsoft.Add("HOST/first");
        ours.Add("HOST/first");
        using var microsoftEnumerator = microsoft.GetEnumerator();
        using var ourEnumerator = ours.GetEnumerator();

        if (position != "before-first")
        {
            Assert.True(microsoftEnumerator.MoveNext());
            Assert.True(ourEnumerator.MoveNext());
        }
        if (position == "after-last")
        {
            Assert.False(microsoftEnumerator.MoveNext());
            Assert.False(ourEnumerator.MoveNext());
        }

        new Comparison($"PrincipalValueCollection enumerator Current: {position}, nonGeneric={nonGeneric}")
            .Check("Current", Observe(() => Current(microsoftEnumerator, nonGeneric)),
                Observe(() => Current(ourEnumerator, nonGeneric)))
            .Assert();
    }

    [Theory]
    [InlineData("Current")]
    [InlineData("IEnumerator.Current")]
    [InlineData("MoveNext")]
    [InlineData("Reset")]
    public void Disposed_enumerator_rejects_operations_like_microsoft(string operation)
    {
        var microsoft = MicrosoftCollection();
        var ours = OurCollection();
        microsoft.Add("HOST/first");
        ours.Add("HOST/first");
        using var microsoftEnumerator = microsoft.GetEnumerator();
        using var ourEnumerator = ours.GetEnumerator();
        Assert.True(microsoftEnumerator.MoveNext());
        Assert.True(ourEnumerator.MoveNext());
        microsoftEnumerator.Dispose();
        ourEnumerator.Dispose();

        new Comparison($"Disposed PrincipalValueCollection enumerator: {operation}")
            .Check("operation", Observe(() => UseEnumerator(microsoftEnumerator, operation)),
                Observe(() => UseEnumerator(ourEnumerator, operation)))
            .Assert();
    }

    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(0, 0, true)]
    [InlineData(2, 2, false)]
    [InlineData(2, 2, true)]
    [InlineData(2, 1, false)]
    [InlineData(2, 1, true)]
    public void Empty_collection_CopyTo_at_array_boundary_matches_microsoft(
        int length, int index, bool nonGeneric)
    {
        var microsoft = MicrosoftCollection();
        var ours = OurCollection();
        var microsoftArray = Enumerable.Repeat("untouched", length).ToArray();
        var ourArray = microsoftArray.ToArray();

        var microsoftResult = Observe(() => Copy(microsoft, microsoftArray, index, nonGeneric));
        var ourResult = Observe(() => Copy(ours, ourArray, index, nonGeneric));

        Assert.Equal(microsoftArray, ourArray);
        new Comparison($"Empty PrincipalValueCollection.CopyTo: length={length}, index={index}, nonGeneric={nonGeneric}")
            .Check("operation", microsoftResult, ourResult)
            .Assert();
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(1, false)]
    [InlineData(1, true)]
    [InlineData(0, false)]
    [InlineData(0, true)]
    public void Null_indexer_assignment_validation_order_matches_microsoft(int index, bool nonGeneric)
    {
        var microsoft = MicrosoftCollection();
        var ours = OurCollection();
        microsoft.Add("HOST/first");
        ours.Add("HOST/first");

        var microsoftResult = Observe(() => SetNull(microsoft, index, nonGeneric));
        var ourResult = Observe(() => SetNull(ours, index, nonGeneric));

        Assert.Equal(new[] { "HOST/first" }, microsoft.ToArray());
        Assert.Equal(microsoft.ToArray(), ours.ToArray());
        new Comparison($"PrincipalValueCollection null assignment: index={index}, nonGeneric={nonGeneric}")
            .Check("operation", microsoftResult, ourResult)
            .Assert();
    }

    private static Ms.PrincipalValueCollection<string> MicrosoftCollection() =>
        (Ms.PrincipalValueCollection<string>)Activator.CreateInstance(
            typeof(Ms.PrincipalValueCollection<string>), nonPublic: true)!;

    private static Ours.PrincipalValueCollection<string> OurCollection() =>
        (Ours.PrincipalValueCollection<string>)Activator.CreateInstance(
            typeof(Ours.PrincipalValueCollection<string>), nonPublic: true)!;

    private static object? Current(IEnumerator<string> enumerator, bool nonGeneric) =>
        nonGeneric ? ((IEnumerator)enumerator).Current : enumerator.Current;

    private static object? UseEnumerator(IEnumerator<string> enumerator, string operation)
    {
        switch (operation)
        {
            case "Current": return enumerator.Current;
            case "IEnumerator.Current": return ((IEnumerator)enumerator).Current;
            case "MoveNext": return enumerator.MoveNext();
            case "Reset": ((IEnumerator)enumerator).Reset(); return null;
            default: throw new ArgumentException("Unknown operation", nameof(operation));
        }
    }

    private static object? Copy(ICollection<string> collection, string[] array, int index, bool nonGeneric)
    {
        if (nonGeneric)
            ((ICollection)collection).CopyTo(array, index);
        else
            collection.CopyTo(array, index);
        return null;
    }

    private static object? SetNull(IList<string> collection, int index, bool nonGeneric)
    {
        if (nonGeneric)
            ((IList)collection)[index] = null;
        else
            collection[index] = null!;
        return null;
    }

    private static Outcome Observe(Func<object?> action)
    {
        try
        {
            return new Outcome(action(), null, null);
        }
        catch (Exception exception)
        {
            return new Outcome(null, exception.GetType().FullName,
                (exception as ArgumentException)?.ParamName);
        }
    }

    private sealed record Outcome(object? Value, string? ExceptionType, string? ParamName);
}
