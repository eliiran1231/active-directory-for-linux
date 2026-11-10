using Xunit;
using Xunit.Abstractions;
#if !RECORDED_MICROSOFT_ORACLE
using Ms = System.DirectoryServices.AccountManagement;
#endif
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
        var nameArgument = name is null ? "null" : $"\"{name}\"";
        var caseId = $"{GetType().FullName}.{nameof(Null_context_matches_microsoft_for_each_constructor)}(named: {named}, name: {nameArgument})";
#if RECORDED_MICROSOFT_ORACLE
        var expectedState = RecordedMicrosoftOracle.Read(caseId);
#else
        var expected = Record.Exception(() =>
        {
            using var group = named ? new Ms.GroupPrincipal(null!, name!) : new Ms.GroupPrincipal(null!);
        });
        var expectedState = Describe(expected);
#endif
        var actual = Record.Exception(() =>
        {
            using var group = named ? new Ours.GroupPrincipal(null!, name!) : new Ours.GroupPrincipal(null!);
        });

        output.WriteLine($"Microsoft: {expectedState}; AdForLinux: {Describe(actual)}");
#if !RECORDED_MICROSOFT_ORACLE
        DifferentialRecording.Write(output, caseId, expectedState, Describe(actual));
        Assert.IsType<ArgumentException>(expected);
#endif
        Assert.Equal(expectedState, Describe(actual));
    }

    private static string Describe(Exception? error) => error is null
        ? "success"
        : $"{error.GetType().Name}; parameter={(error as ArgumentException)?.ParamName ?? "<null>"}";
}
