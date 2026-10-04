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
        Assert.Equal(DifferentialSettings.UsersContainer,
            Assert.IsType<string>(expectedParent.Properties["distinguishedName"].Value), ignoreCase: true);
        Assert.Equal(DifferentialSettings.UsersContainer,
            Assert.IsType<string>(actualParent.Properties["distinguishedName"].Value), ignoreCase: true);
        var expected = expectedParent.Children.SchemaFilter;
        var actual = actualParent.Children.SchemaFilter;
        expected.Clear();
        actual.Clear();
        expected.AddRange(new[] { "user", "group" });
        actual.AddRange(new[] { "user", "group" });
        Assert.Equal(new[] { "user", "group" }, expected.Cast<string>().ToArray());
        Assert.Equal(new[] { "user", "group" }, actual.Cast<string>().ToArray());
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

            Assert.Equal(new[] { "user", "computer" }, expected.Cast<string>().ToArray());
            Assert.Equal(new[] { "user", "computer" }, actual.Cast<string>().ToArray());
            // Independently reacquired wrappers establish that the mutation
            // reached the parent's filter, not just the supplied wrapper.
            Assert.Equal(new[] { "user", "computer" }, expectedParent.Children.SchemaFilter.Cast<string>().ToArray());
            Assert.Equal(new[] { "user", "computer" }, actualParent.Children.SchemaFilter.Cast<string>().ToArray());
            var left = ReadRemaining(leftCursor);
            var right = ReadRemaining(rightCursor);
            Assert.Equal(2, left.Length);
            Assert.Equal(2, right.Length);
            if (replaceArray)
            {
                Assert.Equal(new[] { "user", "group" }, left);
                Assert.Equal(new[] { "user", "group" }, right);
            }
            // Do not prescribe the Microsoft indexer case from assumptions
            // about COM marshaling; its actual captured values are the oracle.
            Assert.Equal(left, right);
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
