using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class SchemaNameCollectionComparisonTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)] // Controls: a nonempty append already replaces the array.
    [InlineData(true, true)]
    public void AddRange_detaches_existing_enumerator_before_later_indexer_write(bool collectionOverload, bool nonempty)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        using var ourSourceEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.Add("user");
        ours.Add("user");
        var expected = microsoft.GetEnumerator();
        var actual = ours.GetEnumerator();
        try
        {
            var additions = nonempty ? new[] { "group" } : Array.Empty<string>();
            if (collectionOverload)
            {
                var source = CreateMicrosoftCollection();
                source.AddRange(additions);
                var ourSource = ourSourceEntry.Children.SchemaFilter;
                ourSource.AddRange(additions);
                microsoft.AddRange(source);
                ours.AddRange(ourSource);
            }
            else
            {
                microsoft.AddRange(additions);
                ours.AddRange(additions);
            }

            microsoft[0] = "computer";
            ours[0] = "computer";
            Assert.Equal(SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-expected", 46), SuiteCapture.Expected(Snapshot(ours), "assert-equal-actual", 46));
            // The delegate-backed reference fixture exposes the array captured
            // by enumeration. This does not model live ADSI array marshaling.
            Assert.Equal(SuiteCapture.Expected(ReadRemaining(expected), "assert-equal-expected", 49), SuiteCapture.Expected(ReadRemaining(actual), "assert-equal-actual", 49));
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [InlineData("empty", "int")]
    [InlineData("null", "int")]
    [InlineData("string", "int")]
    [InlineData("null-then-string", "int")]
    [InlineData("string", "string")]
    [InlineData("null-then-string", "object")]
    public void CopyTo_element_conversion_and_partial_writes_match(string payload, string destinationType)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        string?[] values = payload switch
        {
            "empty" => Array.Empty<string?>(),
            "null" => new string?[] { null },
            "string" => new[] { "user" },
            _ => new[] { null, "user" },
        };
        microsoft.AddRange(values);
        ours.AddRange(values);
        Array Destination() => destinationType switch
        {
            "int" => new[] { 17, 18, 19, 20 },
            "string" => new[] { "a", "b", "c", "d" },
            _ => new object[] { "a", "b", "c", "d" },
        };
        var expectedArray = Destination();
        var actualArray = Destination();
        var expectedError = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedArray, 1));
        var actualError = Record.Exception(() => ((ICollection)ours).CopyTo(actualArray, 1));

        // Capture the destination even on failure so an exception mismatch
        // cannot hide any difference in writes performed before rejection.
        Assert.Equal(SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-expected", 92), SuiteCapture.Expected(Snapshot(ours), "assert-equal-actual", 92));
        var expected = (expectedError?.GetType().FullName,
            (expectedError as ArgumentException)?.ParamName, string.Join("|", expectedArray.Cast<object>()));
        var actual = (actualError?.GetType().FullName,
            (actualError as ArgumentException)?.ParamName, string.Join("|", actualArray.Cast<object>()));
        Assert.Equal(SuiteCapture.Expected(expected, "assert-equal-expected", 97), SuiteCapture.Expected(actual, "assert-equal-actual", 97));
    }

    [Fact]
    public void Add_contains_index_of_remove_and_indexer_assignment_match()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        Assert.Equal(SuiteCapture.Expected(ExerciseCollection(microsoft), "assert-equal-expected", 107), SuiteCapture.Expected(ExerciseCollection(ours), "assert-equal-actual", 107));
    }

    [Fact]
    public void Null_entries_and_casing_differences_match()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        Assert.Equal(SuiteCapture.Expected(ExerciseNullAndCasing(microsoft), "assert-equal-expected", 117), SuiteCapture.Expected(ExerciseNullAndCasing(ours), "assert-equal-actual", 117));
    }

    [Fact]
    public void Removing_a_missing_value_throws_the_same_exception()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        AssertSameException(
            () => microsoft.Remove("missing"),
            () => ours.Remove("missing"));
    }

    [Theory]
    [InlineData("add")]
    [InlineData("replace")]
    [InlineData("remove")]
    [InlineData("clear")]
    public void Existing_enumerator_remains_usable_after_collection_mutation(string mutation)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        var expected = EnumerateAcrossMutation(microsoft, mutation);
        var actual = EnumerateAcrossMutation(ours, mutation);

        // Structural changes replace Microsoft's backing array; the enumerator
        // retains the old array. Indexer assignment instead updates that array
        // in place in this delegate-backed fixture. Neither invalidates it.
        Assert.Equal(SuiteCapture.Expected(mutation == "replace" ? "user|computer" : "user|group", "assert-equal-expected", 149), SuiteCapture.Expected(expected.OldValues, "assert-equal-actual", 149));
        Assert.Null(expected.ExceptionType);
        Assert.Equal(SuiteCapture.Expected(expected, "assert-equal-expected", 151), SuiteCapture.Expected(actual, "assert-equal-actual", 151));
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(1, false)]
    [InlineData(-1, true)]
    [InlineData(1, true)]
    public void Invalid_indexer_access_matches_exception_and_preserves_contents(int index, bool write)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.Add("user");
        ours.Add("user");

        var expected = Record.Exception(() => AccessIndexer(microsoft, index, write));
        var actual = Record.Exception(() => AccessIndexer(ours, index, write));

        Assert.Equal(SuiteCapture.Expected("user", "assert-equal-expected", 170), SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-actual", 170));
        Assert.Equal(SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-expected", 171), SuiteCapture.Expected(Snapshot(ours), "assert-equal-actual", 171));
        Assert.IsType<IndexOutOfRangeException>(expected);
        Assert.NotNull(actual);
        Assert.Equal(SuiteCapture.Expected(expected.GetType(), "assert-equal-expected", 174), SuiteCapture.Expected(actual.GetType(), "assert-equal-actual", 174));
    }

    private static void AccessIndexer(IList collection, int index, bool write)
    {
        if (write)
            collection[index] = "computer";
        else
            _ = collection[index];
    }

    private static EnumerationResult EnumerateAcrossMutation(IList collection, string mutation)
    {
        collection.Add("user");
        collection.Add("group");
        var enumerator = collection.GetEnumerator();
        Assert.True(enumerator.MoveNext());
        var values = new List<string> { (string)enumerator.Current };

        switch (mutation)
        {
            case "add": collection.Add("computer"); break;
            case "replace": collection[1] = "computer"; break;
            case "remove": collection.RemoveAt(1); break;
            case "clear": collection.Clear(); break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var exception = Record.Exception(() =>
        {
            while (enumerator.MoveNext())
                values.Add((string)enumerator.Current);
        });
        return new EnumerationResult(string.Join("|", values), Snapshot(collection), exception?.GetType());
    }

    private sealed record EnumerationResult(string OldValues, string NewValues, Type? ExceptionType);

    [Theory]
    [InlineData("add", false)]
    [InlineData("add", true)]
    [InlineData("remove", false)]
    [InlineData("remove", true)]
    [InlineData("clear", false)]
    [InlineData("clear", true)]
    public void Enumerator_keeps_its_snapshot_after_structural_mutation(string mutation, bool started)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.AddRange(new[] { "user", "group", "computer" });
        ours.AddRange(new[] { "user", "group", "computer" });
        var microsoftEnumerator = microsoft.GetEnumerator();
        var ourEnumerator = ours.GetEnumerator();

        try
        {
            if (started)
            {
                Assert.True(microsoftEnumerator.MoveNext());
                Assert.True(ourEnumerator.MoveNext());
                Assert.Equal(SuiteCapture.Expected(microsoftEnumerator.Current, "assert-equal-expected", 235), SuiteCapture.Expected(ourEnumerator.Current, "assert-equal-actual", 235));
            }

            Mutate(microsoft, mutation);
            Mutate(ours, mutation);
            Assert.Equal(SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-expected", 240), SuiteCapture.Expected(Snapshot(ours), "assert-equal-actual", 240));

            // Microsoft enumerates the array captured by GetEnumerator. A live
            // List<T> enumerator instead throws as soon as the collection changes.
            new Comparison($"SchemaNameCollection enumerator: {mutation}, started={started}")
                .Check("remaining values", ReadRemaining(microsoftEnumerator), ReadRemaining(ourEnumerator))
                .Assert();
        }
        finally
        {
            (microsoftEnumerator as IDisposable)?.Dispose();
            (ourEnumerator as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(1, false)]
    [InlineData(1, true)]
    public void Invalid_indexer_exception_type_matches_microsoft(int index, bool write)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.Add("user");
        ours.Add("user");

        var microsoftException = Record.Exception(() => AccessIndex(microsoft, index, write));
        var ourException = Record.Exception(() => AccessIndex(ours, index, write));

        Assert.Equal(SuiteCapture.Expected("user", "assert-equal-expected", 271), SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-actual", 271));
        Assert.Equal(SuiteCapture.Expected(Snapshot(microsoft), "assert-equal-expected", 272), SuiteCapture.Expected(Snapshot(ours), "assert-equal-actual", 272));
        new Comparison($"SchemaNameCollection indexer: index={index}, write={write}")
            .Check("exception type", microsoftException?.GetType().FullName, ourException?.GetType().FullName)
            .Check("parameter", (microsoftException as ArgumentException)?.ParamName,
                (ourException as ArgumentException)?.ParamName)
            .Assert();
    }

    private static void AccessIndex(IList collection, int index, bool write)
    {
        if (write)
            collection[index] = "group";
        else
            _ = collection[index];
    }

    private static void Mutate(IList collection, string mutation)
    {
        switch (mutation)
        {
            case "add": collection.Add("organizationalUnit"); break;
            case "remove": collection.RemoveAt(1); break;
            case "clear": collection.Clear(); break;
            default: throw new ArgumentException("Unknown mutation", nameof(mutation));
        }
    }

    private static SnapshotEnumerationResult ReadRemaining(IEnumerator enumerator)
    {
        var values = new List<string>();
        var exception = Record.Exception(() =>
        {
            while (enumerator.MoveNext())
                values.Add((string)enumerator.Current);
        });
        return new SnapshotEnumerationResult(string.Join("|", values), exception?.GetType().FullName);
    }

    private sealed record SnapshotEnumerationResult(string Values, string? ExceptionType);

    private static Ms.SchemaNameCollection CreateMicrosoftCollection()
    {
        // Microsoft's public collection can only be obtained from a bound ADSI
        // container. Supplying its internal getter/setter delegates lets these
        // collection-only differential tests run without an AD dependency.
        var constructor = Assert.Single(typeof(Ms.SchemaNameCollection).GetConstructors(
            BindingFlags.Instance | BindingFlags.NonPublic));
        var parameterTypes = constructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray();
        var state = new MicrosoftCollectionState();
        var getter = Delegate.CreateDelegate(parameterTypes[0], state, nameof(MicrosoftCollectionState.GetValue));
        var setter = Delegate.CreateDelegate(parameterTypes[1], state, nameof(MicrosoftCollectionState.SetValue));
        return (Ms.SchemaNameCollection)constructor.Invoke(new object[] { getter, setter });
    }

    private static Ours.DirectoryEntry OurEntry() => new();

    private static CollectionResult ExerciseCollection(Ms.SchemaNameCollection collection)
    {
        var firstIndex = collection.Add("user");
        var secondIndex = collection.Add("group");
        var containsUser = collection.Contains("user");
        var userIndex = collection.IndexOf("user");
        collection[secondIndex] = "computer";
        var assignedValue = collection[secondIndex];
        collection.Remove("user");
        return new(firstIndex, secondIndex, containsUser, userIndex, assignedValue, Snapshot(collection));
    }

    private static CollectionResult ExerciseCollection(Ours.SchemaNameCollection collection)
    {
        var firstIndex = collection.Add("user");
        var secondIndex = collection.Add("group");
        var containsUser = collection.Contains("user");
        var userIndex = collection.IndexOf("user");
        collection[secondIndex] = "computer";
        var assignedValue = collection[secondIndex];
        collection.Remove("user");
        return new(firstIndex, secondIndex, containsUser, userIndex, assignedValue, Snapshot(collection));
    }

    private static NullAndCasingResult ExerciseNullAndCasing(Ms.SchemaNameCollection collection)
    {
        collection.Add("user");
        var nullIndex = collection.Add(null);
        collection.Add("USER");
        collection[0] = null;
        return new(
            nullIndex,
            collection.Contains(null),
            collection.IndexOf(null),
            collection.Contains("user"),
            collection.Contains("USER"),
            collection.IndexOf("USER"),
            Snapshot(collection));
    }

    private static NullAndCasingResult ExerciseNullAndCasing(Ours.SchemaNameCollection collection)
    {
        collection.Add("user");
        var nullIndex = collection.Add(null);
        collection.Add("USER");
        collection[0] = null;
        return new(
            nullIndex,
            collection.Contains(null),
            collection.IndexOf(null),
            collection.Contains("user"),
            collection.Contains("USER"),
            collection.IndexOf("USER"),
            Snapshot(collection));
    }

    private static string Snapshot(IEnumerable collection) =>
        string.Join("|", collection.Cast<string?>().Select(value => value ?? "(null)"));

    private static void AssertSameException(Action microsoftAction, Action ourAction)
    {
        var microsoftException = Record.Exception(microsoftAction);
        var ourException = Record.Exception(ourAction);

        Assert.NotNull(microsoftException);
        Assert.NotNull(ourException);
        Assert.Equal(SuiteCapture.Expected(microsoftException.GetType(), "assert-equal-expected", 394), SuiteCapture.Expected(ourException.GetType(), "assert-equal-actual", 394));
        Assert.Equal(
            SuiteCapture.Expected((microsoftException as ArgumentException)?.ParamName, "assert-equal-expected", 395),
            SuiteCapture.Expected((ourException as ArgumentException)?.ParamName, "assert-equal-actual", 395));
    }

    private sealed record CollectionResult(
        int FirstIndex,
        int SecondIndex,
        bool ContainsUser,
        int UserIndex,
        string? AssignedValue,
        string Values);

    private sealed record NullAndCasingResult(
        int NullIndex,
        bool ContainsNull,
        int NullPosition,
        bool ContainsLowerCase,
        bool ContainsUpperCase,
        int UpperCasePosition,
        string Values);

    private sealed class MicrosoftCollectionState
    {
        private object? _value;

        public object? GetValue() => _value;

        public void SetValue(object? value) => _value = value;
    }
}
