using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// This fixture and these tests write to AD. Use only a verified disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityChildEnumeratorComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    public static IEnumerable<object[]> LifecycleCases()
    {
        foreach (var count in new[] { 0, 3 })
        foreach (var position in count == 0 ? new[] { "before", "exhausted" } : new[] { "before", "partial", "exhausted" })
        foreach (var operation in new[] { "Current", "Reset" })
            yield return new object[] { count, position, operation };
    }

    [Theory]
    [MemberData(nameof(LifecycleCases))]
    public void Child_enumerator_position_and_reset_match_microsoft(int count, string position, string operation)
    {
        using var parent = OpenMicrosoft(DifferentialSettings.UsersContainer);
        // A private subtree avoids depending on unrelated directory contents or
        // LDAP result ordering. The existing fixture supplies a unique prefix.
        var rdn = $"CN={data.UserName}-enum-{Guid.NewGuid():N}";
        using var microsoftRoot = parent.Children.Add(rdn, "container");
        var committed = false;
        try
        {
            microsoftRoot.CommitChanges();
            committed = true;
            for (var i = 0; i < count; i++)
            {
                using var child = microsoftRoot.Children.Add($"CN=child-{i}", "container");
                child.CommitChanges();
            }
            using var ourRoot = new Ours.DirectoryEntry(
                DifferentialSettings.PathFor($"{rdn},{DifferentialSettings.UsersContainer}"),
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
            var microsoft = microsoftRoot.Children.GetEnumerator();
            var ours = ourRoot.Children.GetEnumerator();
            // Keep returned entries alive until the enumerators have finished:
            // disposing Current during positioning could change the experiment.
            var entries = new HashSet<IDisposable>(ReferenceEqualityComparer.Instance);
            try
            {
                var comparison = new Comparison($"DirectoryEntries count={count}, position={position}, operation={operation}");
                Position(microsoft, position, count, entries);
                Position(ours, position, count, entries);
                comparison.Check("Current at initial position", Current(microsoft, entries), Current(ours, entries));
                if (operation == "Reset")
                {
                    Reset(comparison, "first reset", microsoft, ours);
                    comparison.Check("Current after reset", Current(microsoft, entries), Current(ours, entries));
                    var expected = ReadRemaining(microsoft, entries);
                    var actual = ReadRemaining(ours, entries);
                    // The Microsoft oracle must actually replay the seeded rows;
                    // a pair of empty or failed enumerations is not parity.
                    Assert.Equal(count, expected.Count);
                    comparison.Check("replayed names", expected.Names, actual.Names)
                        .Check("replayed count", expected.Count, actual.Count)
                        .Check("replay exception", expected.Error, actual.Error);
                    Reset(comparison, "second reset", microsoft, ours);
                    expected = ReadRemaining(microsoft, entries);
                    actual = ReadRemaining(ours, entries);
                    comparison.Check("second replay names", expected.Names, actual.Names)
                        .Check("second replay count", expected.Count, actual.Count)
                        .Check("second replay exception", expected.Error, actual.Error);
                }
                else
                {
                    // Repeated Current must not advance; normalize to validity,
                    // since the two providers need not order children identically.
                    comparison.Check("Current repeated", Current(microsoft, entries), Current(ours, entries));
                    var expected = ReadRemaining(microsoft, entries);
                    var actual = ReadRemaining(ours, entries);
                    comparison.Check("remaining count", expected.Count, actual.Count)
                        .Check("remaining exception", expected.Error, actual.Error);
                    // With partial traversal, the skipped child can differ by
                    // provider order; compare names only for complete traversal.
                    if (position == "before")
                        comparison.Check("all names", expected.Names, actual.Names);
                }
                comparison.Check("Current after exhaustion", Current(microsoft, entries), Current(ours, entries))
                    .Check("MoveNext after exhaustion", MoveNext(microsoft), MoveNext(ours));
                comparison.Assert();
            }
            finally
            {
                (microsoft as IDisposable)?.Dispose();
                (ours as IDisposable)?.Dispose();
                foreach (var entry in entries) entry.Dispose();
            }
        }
        finally
        {
            if (committed) microsoftRoot.DeleteTree();
        }
    }

    private static Ms.DirectoryEntry OpenMicrosoft(string dn) => new(
        DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static void Position(IEnumerator enumerator, string position, int count, HashSet<IDisposable> entries)
    {
        if (position == "partial")
        {
            Assert.True(enumerator.MoveNext());
            Track(enumerator.Current, entries);
        }
        else if (position == "exhausted")
        {
            var observed = ReadRemaining(enumerator, entries);
            Assert.Null(observed.Error);
            Assert.Equal(count, observed.Count);
        }
    }

    private static (string? Error, string? Parameter, string State) Current(IEnumerator enumerator, HashSet<IDisposable> entries)
    {
        try
        {
            var value = enumerator.Current;
            Track(value, entries);
            return (null, null, value is null ? "null" : value is Ms.DirectoryEntry or Ours.DirectoryEntry ? "entry" : "unexpected type");
        }
        catch (Exception ex) { return (ex.GetType().FullName, (ex as ArgumentException)?.ParamName, "threw"); }
    }

    private static (string? Error, bool? Value) MoveNext(IEnumerator enumerator)
    {
        try { return (null, enumerator.MoveNext()); }
        catch (Exception ex) { return (ex.GetType().FullName, null); }
    }

    private static void Reset(Comparison comparison, string label, IEnumerator microsoft, IEnumerator ours)
    {
        var expected = Record.Exception(microsoft.Reset);
        var actual = Record.Exception(ours.Reset);
        comparison.Check($"{label}: exception", expected?.GetType().FullName, actual?.GetType().FullName)
            .Check($"{label}: parameter", (expected as ArgumentException)?.ParamName, (actual as ArgumentException)?.ParamName);
    }

    private static (int Count, string Names, string? Error) ReadRemaining(IEnumerator enumerator, HashSet<IDisposable> entries)
    {
        var names = new List<string>();
        try
        {
            while (enumerator.MoveNext())
            {
                var entry = enumerator.Current;
                Track(entry, entries);
                names.Add(entry switch
                {
                    Ms.DirectoryEntry microsoft => microsoft.Name.ToUpperInvariant(),
                    Ours.DirectoryEntry ours => ours.Name.ToUpperInvariant(),
                    _ => throw new InvalidOperationException("Enumerator returned a non-entry value."),
                });
            }
            return (names.Count, string.Join("|", names.Order(StringComparer.Ordinal)), null);
        }
        catch (Exception ex) { return (names.Count, string.Join("|", names.Order(StringComparer.Ordinal)), ex.GetType().FullName); }
    }

    private static void Track(object? entry, HashSet<IDisposable> entries)
    {
        if (entry is IDisposable disposable) entries.Add(disposable);
    }
}
