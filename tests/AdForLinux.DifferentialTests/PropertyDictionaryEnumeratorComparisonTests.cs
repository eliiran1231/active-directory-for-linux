using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class PropertyDictionaryEnumeratorComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _fixture;

    public PropertyDictionaryEnumeratorComparisonTests(TestDataFixture fixture) => _fixture = fixture;

    public static IEnumerable<object[]> UnpositionedReads =>
        from position in new[] { "before-start", "after-end", "after-reset" }
        from accessor in new[] { "Current", "Entry", "Key", "Value" }
        select new object[] { position, accessor };

    [Theory]
    [MemberData(nameof(UnpositionedReads))]
    public void Unpositioned_dictionary_enumerator_read_matches_microsoft(string position, string accessor)
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        var expected = microsoft.Properties.GetEnumerator();
        var actual = ours.Properties.GetEnumerator();
        try
        {
            Position(expected, position);
            Position(actual, position);
            var expectedError = Record.Exception(() => Read(expected, accessor));
            var actualError = Record.Exception(() => Read(actual, accessor));

            Assert.IsType<InvalidOperationException>(expectedError);
            new Comparison($"PropertyCollection enumerator {position}.{accessor}")
                .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
                .Assert();
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [InlineData("Current")]
    [InlineData("Entry")]
    [InlineData("Value")]
    public void Positioned_reads_return_property_wrappers_with_matching_identity(string accessor)
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        var expectedProperties = microsoft.Properties;
        var actualProperties = ours.Properties;
        var expected = expectedProperties.GetEnumerator();
        var actual = actualProperties.GetEnumerator();
        try
        {
            // Directory attribute order is unspecified: locate the same seeded
            // attribute on both sides instead of comparing their first items.
            MoveToDescription(expected);
            MoveToDescription(actual);
            var expectedFirst = (Ms.PropertyValueCollection)Read(expected, accessor)!;
            var actualFirst = (Ours.PropertyValueCollection)Read(actual, accessor)!;
            var expectedSecond = (Ms.PropertyValueCollection)Read(expected, accessor)!;
            var actualSecond = (Ours.PropertyValueCollection)Read(actual, accessor)!;

            new Comparison($"PropertyCollection positioned {accessor}")
                .Check("property name", expectedFirst.PropertyName, actualFirst.PropertyName)
                .Check("value", expectedFirst.Value, actualFirst.Value)
                .Check("repeated read reuses wrapper", ReferenceEquals(expectedFirst, expectedSecond),
                    ReferenceEquals(actualFirst, actualSecond))
                .Check("read reuses indexer cache", ReferenceEquals(expectedFirst, expectedProperties["description"]),
                    ReferenceEquals(actualFirst, actualProperties["description"]))
                .Assert();
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
    }

    [Fact]
    public void Pending_attribute_addition_does_not_change_an_existing_enumeration()
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        Assert.True(microsoft.UsePropertyCache);
        Assert.True(ours.UsePropertyCache);
        Assert.False(microsoft.Properties.Contains("info"));
        Assert.False(ours.Properties.Contains("info"));
        var expected = microsoft.Properties.GetEnumerator();
        var actual = ours.Properties.GetEnumerator();
        try
        {
            // These writes stay in the entry's cache. Never CommitChanges:
            // the fixture's persisted user must remain unchanged.
            microsoft.Properties["info"].Value = "pending enumeration comparison";
            ours.Properties["info"].Value = "pending enumeration comparison";
            var expectedNames = new List<string>();
            var actualNames = new List<string>();
            var expectedError = Record.Exception(() => ReadNames(expected, expectedNames));
            var actualError = Record.Exception(() => ReadNames(actual, actualNames));
            Assert.Null(expectedError);
            Assert.NotEmpty(expectedNames);
            Assert.DoesNotContain("info", expectedNames);

            new Comparison("property enumeration across an uncommitted new attribute")
                .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
                .CheckSet("enumerated names", expectedNames, actualNames)
                .Assert();
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
    }

    [Fact]
    public void Positioned_keys_and_values_are_a_control()
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        var expected = microsoft.Properties.GetEnumerator();
        var actual = ours.Properties.GetEnumerator();
        try
        {
            MoveToDescription(expected);
            MoveToDescription(actual);
            Assert.Equal(expected.Key, actual.Key);
            Assert.Equal(Assert.IsType<Ms.PropertyValueCollection>(expected.Value).Value,
                Assert.IsType<Ours.PropertyValueCollection>(actual.Value).Value);
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
    }

    private static void Position(IDictionaryEnumerator enumerator, string position)
    {
        switch (position)
        {
            case "before-start": break;
            case "after-end":
                while (enumerator.MoveNext()) { }
                break;
            case "after-reset":
                Assert.True(enumerator.MoveNext());
                enumerator.Reset();
                break;
            default: throw new ArgumentOutOfRangeException(nameof(position));
        }
    }

    private static object? Read(IDictionaryEnumerator enumerator, string accessor) => accessor switch
    {
        "Current" => enumerator.Current,
        "Entry" => enumerator.Entry.Value,
        "Key" => enumerator.Key,
        "Value" => enumerator.Value,
        _ => throw new ArgumentOutOfRangeException(nameof(accessor)),
    };

    private static void MoveToDescription(IDictionaryEnumerator enumerator)
    {
        while (enumerator.MoveNext())
            if (string.Equals((string)enumerator.Key, "description", StringComparison.OrdinalIgnoreCase))
                return;
        Assert.Fail("The seeded user's description attribute was not enumerated.");
    }

    private static void ReadNames(IDictionaryEnumerator enumerator, List<string> names)
    {
        while (enumerator.MoveNext())
            names.Add((string)enumerator.Key);
    }

    private Ms.DirectoryEntry MicrosoftEntry() => new(DifferentialSettings.PathFor(_fixture.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private Ours.DirectoryEntry OurEntry() => new(DifferentialSettings.PathFor(_fixture.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
