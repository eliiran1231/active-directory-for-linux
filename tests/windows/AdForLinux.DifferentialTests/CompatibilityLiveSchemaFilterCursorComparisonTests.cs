using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Reads a configured container and changes only its local enumeration filter.
// No child enumeration, directory mutation, or CommitChanges occurs. Binding
// still requires an authorized disposable AD lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityLiveSchemaFilterCursorComparisonTests
{
    // The existing delegate-backed SchemaNameCollection tests intentionally do
    // not model ADSI Filter array marshaling. This public bound-container path
    // compares an earlier captured array with later native filter assignments.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SchemaNameCollection.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntries.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Retained_schema_cursor_after_live_filter_replacement_matches(bool replaceArray)
    {
        using var expectedParent = new Ms.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actualParent = new Ours.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        // Establish an actual usable binding before accessing the filter.
        Assert.Equal(SuiteCapture.Expected(DifferentialSettings.UsersContainer, "assert-equal-expected", 30),
            SuiteCapture.Expected(Assert.IsType<string>(expectedParent.Properties["distinguishedName"].Value), "assert-equal-actual", 30), ignoreCase: true);
        Assert.Equal(SuiteCapture.Expected(DifferentialSettings.UsersContainer, "assert-equal-expected", 32),
            SuiteCapture.Expected(Assert.IsType<string>(actualParent.Properties["distinguishedName"].Value), "assert-equal-actual", 32), ignoreCase: true);
        var expected = expectedParent.Children.SchemaFilter;
        var actual = actualParent.Children.SchemaFilter;
        expected.Clear();
        actual.Clear();
        expected.AddRange(new[] { "user", "group" });
        actual.AddRange(new[] { "user", "group" });
        Assert.Equal(SuiteCapture.Expected(new[] { "user", "group" }, "assert-equal-expected", 40), SuiteCapture.Expected(expected.Cast<string>().ToArray(), "assert-equal-actual", 40));
        Assert.Equal(SuiteCapture.Expected(new[] { "user", "group" }, "assert-equal-expected", 41), SuiteCapture.Expected(actual.Cast<string>().ToArray(), "assert-equal-actual", 41));
        var leftCursor = expected.GetEnumerator();
        var rightCursor = actual.GetEnumerator();
        try
        {
            if (replaceArray)
            {
                // Structural replacement leaves the earlier captured array
                // untouched in both implementations; this is the control.
                expected.Clear();
                actual.Clear();
                expected.AddRange(new[] { "user", "computer" });
                actual.AddRange(new[] { "user", "computer" });
            }
            else
            {
                expected[1] = "computer";
                actual[1] = "computer";
            }

            Assert.Equal(SuiteCapture.Expected(new[] { "user", "computer" }, "assert-equal-expected", 61), SuiteCapture.Expected(expected.Cast<string>().ToArray(), "assert-equal-actual", 61));
            Assert.Equal(SuiteCapture.Expected(new[] { "user", "computer" }, "assert-equal-expected", 62), SuiteCapture.Expected(actual.Cast<string>().ToArray(), "assert-equal-actual", 62));
            // Independently reacquired wrappers establish that the mutation
            // reached the parent's filter, not just the supplied wrapper.
            Assert.Equal(SuiteCapture.Expected(new[] { "user", "computer" }, "assert-equal-expected", 65), SuiteCapture.Expected(expectedParent.Children.SchemaFilter.Cast<string>().ToArray(), "assert-equal-actual", 65));
            Assert.Equal(SuiteCapture.Expected(new[] { "user", "computer" }, "assert-equal-expected", 66), SuiteCapture.Expected(actualParent.Children.SchemaFilter.Cast<string>().ToArray(), "assert-equal-actual", 66));
            var left = ReadRemaining(leftCursor);
            var right = ReadRemaining(rightCursor);
            Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 69), SuiteCapture.Expected(left.Length, "assert-equal-actual", 69));
            Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 70), SuiteCapture.Expected(right.Length, "assert-equal-actual", 70));
            if (replaceArray)
            {
                Assert.Equal(SuiteCapture.Expected(new[] { "user", "group" }, "assert-equal-expected", 73), SuiteCapture.Expected(left, "assert-equal-actual", 73));
                Assert.Equal(SuiteCapture.Expected(new[] { "user", "group" }, "assert-equal-expected", 74), SuiteCapture.Expected(right, "assert-equal-actual", 74));
            }
            // Do not prescribe the Microsoft indexer case from assumptions
            // about COM marshaling; its actual captured values are the oracle.
            Assert.Equal(SuiteCapture.Expected(left, "assert-equal-expected", 78), SuiteCapture.Expected(right, "assert-equal-actual", 78));
        }
        finally
        {
            try { (leftCursor as IDisposable)?.Dispose(); }
            finally { (rightCursor as IDisposable)?.Dispose(); }
        }
    }

    private static string[] ReadRemaining(IEnumerator cursor)
    {
        var values = new List<string>();
        while (cursor.MoveNext()) values.Add(Assert.IsType<string>(cursor.Current));
        return values.ToArray();
    }
}
