using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Offline: argument validation must not require a context or a directory bind.
public sealed class GroupConstructorValidationComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false, null)]
    [InlineData(true, null)]
    [InlineData(true, "")]
    [InlineData(true, "group-name")]
    public void Null_context_matches_microsoft_for_each_constructor(bool named, string? name)
    {
        var expected = Record.Exception(() =>
        {
            using var group = named ? new Ms.GroupPrincipal(null!, name!) : new Ms.GroupPrincipal(null!);
        });
        var actual = Record.Exception(() =>
        {
            using var group = named ? new Ours.GroupPrincipal(null!, name!) : new Ours.GroupPrincipal(null!);
        });

        output.WriteLine($"Microsoft: {Describe(expected)}; AdForLinux: {Describe(actual)}");
        Assert.IsType<ArgumentException>(expected);
        Assert.Equal(Describe(expected), Describe(actual));
    }

    private static string Describe(Exception? error) => error is null
        ? "success"
        : $"{error.GetType().Name}; parameter={(error as ArgumentException)?.ParamName ?? "<null>"}";
}
