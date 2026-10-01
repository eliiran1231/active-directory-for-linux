using System.Collections;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyValueCacheComparisonTests(TestDataFixture data, ITestOutputHelper output)
    : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData(false, "before")]
    [InlineData(false, "finished")]
    [InlineData(false, "reset")]
    [InlineData(false, "mutate-before-start")]
    [InlineData(true, "before")] // Controls: the inherited IEnumerable path.
    [InlineData(true, "finished")]
    [InlineData(true, "reset")]
    [InlineData(true, "mutate-before-start")]
    public void Property_value_enumerator_position_reset_and_capture_match(bool throughInterface, string operation)
    {
        using var microsoft = MicrosoftEntry(data.UserDn);
        using var ours = OurEntry(data.UserDn);
        var expectedValues = microsoft.Properties["description"];
        var actualValues = ours.Properties["description"];
        expectedValues.Value = new object[] { "first", "second" };
        actualValues.Value = new object[] { "first", "second" };
        // Keep concrete call sites: casting both to IEnumerable would hide the
        // clone's public LINQ-based GetEnumerator implementation.
        var expected = throughInterface
            ? ((IEnumerable)expectedValues).GetEnumerator() : expectedValues.GetEnumerator();
        var actual = throughInterface
            ? ((IEnumerable)actualValues).GetEnumerator() : actualValues.GetEnumerator();
        try
        {
            Compare(
                Exercise(expected, operation, () => expectedValues.Add("third")),
                Exercise(actual, operation, () => actualValues.Add("third")));
        }
        finally
        {
            (expected as IDisposable)?.Dispose();
            (actual as IDisposable)?.Dispose();
        }
        // UsePropertyCache defaults to true; these mutations are never committed.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)] // Control: the collection overload uses the right parameter name.
    public void Null_AddRange_argument_matches_exception_and_preserves_cache(bool collectionOverload)
    {
        using var microsoft = MicrosoftEntry(data.UserDn);
        using var ours = OurEntry(data.UserDn);
        var expected = microsoft.Properties["description"];
        var actual = ours.Properties["description"];
        expected.Value = actual.Value = "sentinel";
        var expectedError = Record.Exception(() =>
        {
            if (collectionOverload) expected.AddRange((Ms.PropertyValueCollection)null!);
            else expected.AddRange((object[])null!);
        });
        var actualError = Record.Exception(() =>
        {
            if (collectionOverload) actual.AddRange((Ours.PropertyValueCollection)null!);
            else actual.AddRange((object[])null!);
        });
        Assert.Equal("sentinel", expected.Value);
        Assert.Equal(expected.Value, actual.Value);
        Compare(Describe(expectedError), Describe(actualError));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)] // Control: explicit Clear stages deletion in both libraries.
    public void Failed_array_replacement_matches_subsequent_commit(bool invalidReplacement)
    {
        // Use separate disposable entries, both seeded through Microsoft, so a
        // cached mutation in one library cannot affect the other's starting state.
        using var parent = MicrosoftEntry(DifferentialSettings.UsersContainer);
        var created = new List<Ms.DirectoryEntry>();
        try
        {
            for (var i = 0; i < 2; i++)
            {
                var name = $"pvc-{Guid.NewGuid():N}"[..19];
                var entry = parent.Children.Add($"CN={name}", "user");
                created.Add(entry);
                entry.Properties["sAMAccountName"].Value = name;
                entry.Properties["userAccountControl"].Value = 0x202; // Normal, disabled account.
                entry.Properties["description"].Value = "persisted-before-failure";
                entry.CommitChanges();
            }

            using var microsoft = new Ms.DirectoryEntry(created[0].Path,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
            using var ours = new Ours.DirectoryEntry(created[1].Path,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.OurAuthenticationTypes);
            var expectedValues = microsoft.Properties["description"];
            var actualValues = ours.Properties["description"];
            Assert.Equal("persisted-before-failure", expectedValues.Value);
            Assert.Equal(expectedValues.Value, actualValues.Value);

            var expectedError = Record.Exception(() =>
            {
                if (invalidReplacement) expectedValues.Value = new int[1, 1];
                else expectedValues.Clear();
            });
            var actualError = Record.Exception(() =>
            {
                if (invalidReplacement) actualValues.Value = new int[1, 1];
                else actualValues.Clear();
            });
            if (invalidReplacement) Assert.NotNull(expectedError);
            var expectedCommit = Record.Exception(microsoft.CommitChanges);
            var actualCommit = Record.Exception(ours.CommitChanges);
            // Read both persisted results through the reference library using
            // fresh entries; neither writer's property cache is an oracle.
            using var expectedRead = new Ms.DirectoryEntry(created[0].Path,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
            using var actualRead = new Ms.DirectoryEntry(created[1].Path,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
            Compare(
                $"setter={Describe(expectedError)}; count={expectedValues.Count}; commit={Describe(expectedCommit)}; persisted={expectedRead.Properties["description"].Value ?? "<null>"}",
                $"setter={Describe(actualError)}; count={actualValues.Count}; commit={Describe(actualCommit)}; persisted={actualRead.Properties["description"].Value ?? "<null>"}");
        }
        finally
        {
            // Try every cleanup even if one removal fails. Report cleanup errors
            // rather than silently leaving temporary objects behind.
            var errors = new List<Exception>();
            foreach (var entry in created)
            {
                try { parent.Children.Remove(entry); }
                catch (Exception error) { errors.Add(error); }
                finally { entry.Dispose(); }
            }
            if (errors.Count != 0) throw new AggregateException("Temporary user cleanup failed.", errors);
        }
    }

    private static string Exercise(IEnumerator enumerator, string operation, Action mutate)
    {
        if (operation == "finished")
            while (enumerator.MoveNext()) { }
        if (operation == "reset")
        {
            Assert.True(enumerator.MoveNext());
            Assert.Equal("first", enumerator.Current);
            var reset = Observe(() => { enumerator.Reset(); return "reset"; });
            var current = Observe(() => enumerator.Current);
            return $"{reset}; current={current}; next={Observe(() => enumerator.MoveNext())}; value={Observe(() => enumerator.Current)}";
        }
        if (operation == "mutate-before-start")
        {
            mutate();
            return Observe(() => enumerator.MoveNext());
        }
        return Observe(() => enumerator.Current);
    }

    private static string Observe(Func<object?> action)
    {
        try { return $"value:{action() ?? "<null>"}"; }
        catch (Exception error) { return Describe(error); }
    }

    private static string Describe(Exception? error) => error is null ? "success"
        : $"{error.GetType().FullName}; parameter={(error as ArgumentException)?.ParamName ?? "<null>"}";

    private void Compare(string expected, string actual)
    {
        output.WriteLine($"Microsoft: {expected}");
        output.WriteLine($"AdForLinux: {actual}");
        Assert.Equal(expected, actual);
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) => new(
        DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) => new(
        DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
