using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class PrincipalValueEnumeratorExceptionComparisonTests
{
    [Theory]
    [InlineData("Current", false)]
    [InlineData("Current", true)]
    [InlineData("MoveNext", false)]
    [InlineData("MoveNext", true)]
    [InlineData("Reset", false)]
    [InlineData("Reset", true)]
    public void Disposed_enumerator_reports_the_same_object_name(string operation, bool nonGeneric)
    {
        var constructor = typeof(Ms.PrincipalValueCollection<string>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        var microsoft = Assert.IsType<Ms.PrincipalValueCollection<string>>(constructor.Invoke(null));
        var ours = new Ours.PrincipalValueCollection<string>();
        microsoft.Add("first");
        ours.Add("first");

        var expected = Observe(microsoft);
        var actual = Observe(ours);
        // Namespace differences are intentional; internal implementation type
        // names leaking through this public exception are not normalized away.
        Assert.Equal(expected, actual?.Replace("AdForLinux.DirectoryServices", "System.DirectoryServices"));

        string? Observe(IEnumerable<string> values)
        {
            using var enumerator = values.GetEnumerator();
            Assert.True(enumerator.MoveNext());
            Assert.Equal("first", enumerator.Current);
            enumerator.Dispose();
            var error = Record.Exception(() =>
            {
                if (nonGeneric)
                {
                    var legacy = (IEnumerator)enumerator;
                    switch (operation)
                    {
                        case "Current": _ = legacy.Current; break;
                        case "MoveNext": _ = legacy.MoveNext(); break;
                        case "Reset": legacy.Reset(); break;
                    }
                }
                else
                {
                    switch (operation)
                    {
                        case "Current": _ = enumerator.Current; break;
                        case "MoveNext": _ = enumerator.MoveNext(); break;
                        case "Reset": enumerator.Reset(); break;
                    }
                }
            });
            return Assert.IsType<ObjectDisposedException>(error).ObjectName;
        }
    }
}
