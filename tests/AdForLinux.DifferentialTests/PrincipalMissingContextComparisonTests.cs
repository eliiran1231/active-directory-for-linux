using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Normal protected constructors model a custom principal before ContextRaw is
// assigned. No fabricated contexts, private-field changes, or AD are involved.
public sealed class PrincipalMissingContextComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }

    [Theory]
    [InlineData(false)]
    [InlineData(true)] // Control: disposal takes precedence over missing context.
    public void ContextType_without_context_matches_microsoft(bool disposed)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        Assert.Null(microsoft.Context);
        Assert.Null(ours.Context);
        if (disposed)
        {
            microsoft.Dispose();
            ours.Dispose();
        }

        var expected = Record.Exception(() => _ = microsoft.ContextType);
        var actual = Record.Exception(() => _ = ours.ContextType);

        Assert.NotNull(expected);
        Assert.Equal(expected.GetType(), actual?.GetType());
    }

    [Theory]
    [InlineData("Description")]
    [InlineData("DisplayName")]
    [InlineData("UserPrincipalName")]
    [InlineData("SamAccountName")]
    public void Setting_property_without_context_matches_rejection_and_retained_value(string property)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        var microsoftProperty = typeof(Ms.Principal).GetProperty(property)!;
        var ourProperty = typeof(Ours.Principal).GetProperty(property)!;
        // Delegates exercise the setters directly, preserving the original
        // exception rather than wrapping it in TargetInvocationException.
        var microsoftSetter = (Action<string>)microsoftProperty.SetMethod!
            .CreateDelegate(typeof(Action<string>), microsoft);
        var ourSetter = (Action<string>)ourProperty.SetMethod!
            .CreateDelegate(typeof(Action<string>), ours);
        var microsoftGetter = (Func<string?>)microsoftProperty.GetMethod!
            .CreateDelegate(typeof(Func<string?>), microsoft);
        var ourGetter = (Func<string?>)ourProperty.GetMethod!
            .CreateDelegate(typeof(Func<string?>), ours);
        var expected = Record.Exception(() => microsoftSetter("staged-value"));
        var actual = Record.Exception(() => ourSetter("staged-value"));

        Assert.Equal(
            (SetterError: expected?.GetType(), After: Observe(microsoftGetter)),
            (SetterError: actual?.GetType(), After: Observe(ourGetter)));
    }

    private static (Type? Error, string? Value) Observe(Func<string?> getter)
    {
        string? value = null;
        var error = Record.Exception(() => { value = getter(); });
        return (error?.GetType(), value);
    }
}
