using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Obtaining Microsoft's Options binds the entry, so even the disposed-wrapper
// comparisons belong to the live suite. No password operation or quota change
// is invoked; only per-entry provider configuration is exercised.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityEntryOptionsLifecycleComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    public static IEnumerable<object[]> DisposedOperations()
    {
        foreach (var property in new[] { "PageSize", "Referral", "SecurityMasks", "PasswordEncoding", "PasswordPort" })
        {
            yield return new object[] { property, "get" };
            yield return new object[] { property, "valid-set" };
            // PasswordPort has no managed range check. Do not invent an invalid
            // port contract; the other four have source-defined local guards.
            if (property != "PasswordPort") yield return new object[] { property, "invalid-set" };
        }
    }

    [Theory]
    [MemberData(nameof(DisposedOperations))]
    public void Retained_options_after_entry_disposal_match_microsoft(string property, string operation)
    {
        using var expectedEntry = MicrosoftEntry();
        using var actualEntry = OurEntry();
        var expected = Assert.IsType<Ms.DirectoryEntryConfiguration>(expectedEntry.Options);
        var actual = actualEntry.Options;
        // Establish that both entries resolve before testing lifecycle behavior.
        Assert.Equal(data.UserName, expectedEntry.Properties["sAMAccountName"].Value);
        Assert.Equal(data.UserName, actualEntry.Properties["sAMAccountName"].Value);
        expectedEntry.Dispose();
        actualEntry.Dispose();

        var comparison = new Comparison($"Retained entry options: {property}, {operation}");
        Compare(comparison, "disposed operation", Observe(expected, property, operation), Observe(actual, property, operation));
        // Repeat against the same retained wrapper, to expose any state change
        // caused by a successful clone setter despite a rejected oracle setter.
        Compare(comparison, "read after operation", Observe(expected, property, "get"), Observe(actual, property, "get"));
        comparison.Assert();
    }

    [Theory]
    [InlineData("PageSize", 17)]
    [InlineData("SecurityMasks", 3)]
    public void Retained_options_rebind_after_close_like_microsoft(string property, int value)
    {
        using var expectedEntry = MicrosoftEntry();
        using var actualEntry = OurEntry();
        var expected = Assert.IsType<Ms.DirectoryEntryConfiguration>(expectedEntry.Options);
        var actual = actualEntry.Options;
        Set(expected, property, value);
        Set(actual, property, value);
        var comparison = new Comparison($"Entry options after Close: {property}");
        Compare(comparison, "before close", Observe(expected, property, "get"), Observe(actual, property, "get"));
        expectedEntry.Close();
        actualEntry.Close();
        // Microsoft stores options on the provider handle; the clone stores
        // fields on the configuration wrapper. Read through the retained object
        // first, then through Entry.Options, without assuming which is retained.
        Compare(comparison, "retained after close", Observe(expected, property, "get"), Observe(actual, property, "get"));
        Compare(comparison, "entry options after close", Observe(expectedEntry.Options!, property, "get"),
            Observe(actualEntry.Options, property, "get"));
        comparison.Assert();
    }

    private Ms.DirectoryEntry MicrosoftEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private Ours.DirectoryEntry OurEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);

    private sealed record Observation(string? Error, string? Parameter, int? Value);

    private static Observation Observe(object options, string property, string operation)
    {
        try
        {
            if (operation != "get")
            {
                var value = operation == "invalid-set"
                    ? property switch { "SecurityMasks" => 16, "PasswordEncoding" => 2, _ => -1 }
                    : property switch { "PageSize" => 17, "Referral" => 0, "SecurityMasks" => 3, "PasswordEncoding" => 1, _ => 1636 };
                Set(options, property, value);
                return new Observation(null, null, null);
            }
            return new Observation(null, null, Convert.ToInt32(options.GetType().GetProperty(property)!.GetValue(options)));
        }
        catch (Exception error)
        {
            var cause = error is TargetInvocationException invocation ? invocation.InnerException! : error;
            return new Observation(cause.GetType().FullName, (cause as ArgumentException)?.ParamName, null);
        }
    }

    private static void Set(object options, string property, int value)
    {
        var member = options.GetType().GetProperty(property)!;
        member.SetValue(options, member.PropertyType.IsEnum ? Enum.ToObject(member.PropertyType, value) : value);
    }

    private static void Compare(Comparison comparison, string label, Observation expected, Observation actual) => comparison
        .Check($"{label}: exception", expected.Error, actual.Error)
        .Check($"{label}: parameter", expected.Parameter, actual.Parameter)
        .Check($"{label}: value", expected.Value, actual.Value);
}
