using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class PrincipalValueCollectionEqualityDispatchComparisonTests
{
    [Theory]
    [InlineData("Contains", false, false)]
    [InlineData("Contains", true, false)]
    [InlineData("IndexOf", false, false)]
    [InlineData("IndexOf", true, false)]
    [InlineData("Remove", false, false)]
    [InlineData("Remove", true, false)]
    [InlineData("Contains", false, true)]
    [InlineData("Contains", true, true)]
    [InlineData("IndexOf", false, true)]
    [InlineData("IndexOf", true, true)]
    [InlineData("Remove", false, true)]
    [InlineData("Remove", true, true)]
    public void Lookup_and_removal_use_the_same_equality_dispatch(
        string operation, bool nonGeneric, bool sameInstance)
    {
        var microsoft = CreateMicrosoft<EquatableValue>();
        var ours = new Ours.PrincipalValueCollection<EquatableValue>();
        Assert.Equal(Observe(microsoft), Observe(ours));

        string Observe(IList<EquatableValue> values)
        {
            var stored = new EquatableValue("first");
            values.Add(stored);
            values.Add(new EquatableValue("second"));
            var probe = sameInstance ? stored : new EquatableValue("first");
            object? result = null;
            var error = Record.Exception(() =>
            {
                if (nonGeneric)
                {
                    var list = (IList)values;
                    switch (operation)
                    {
                        case "Contains": result = list.Contains(probe); break;
                        case "IndexOf": result = list.IndexOf(probe); break;
                        case "Remove": list.Remove(probe); break;
                    }
                }
                else
                {
                    switch (operation)
                    {
                        case "Contains": result = values.Contains(probe); break;
                        case "IndexOf": result = values.IndexOf(probe); break;
                        case "Remove": result = values.Remove(probe); break;
                    }
                }
            });
            // Project to strings: assertions must not use the equality behavior
            // under test to compare the collections themselves.
            return $"error={error?.GetType().FullName ?? "none"}; result={result}; " +
                $"remaining=[{string.Join(",", values.Select(value => value.Key))}]";
        }
    }

    // Deliberately distinguish the two legal dispatch targets. This fixture
    // tests arbitrary T, not the equality of AD's usual string-valued fields.
    private sealed class EquatableValue(string key) : IEquatable<EquatableValue>
    {
        public string Key { get; } = key;
        public bool Equals(EquatableValue? other) => other?.Key == Key;
        public override bool Equals(object? other) => ReferenceEquals(this, other);
        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Key);
    }

    private static Ms.PrincipalValueCollection<T> CreateMicrosoft<T>()
    {
        // Invoke the normal constructor, as in existing offline collection
        // fixtures. Do not fabricate an object or change its private fields.
        var constructor = typeof(Ms.PrincipalValueCollection<T>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<T>>(constructor.Invoke(null));
    }
}
