using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public class CompatibilitySynchronizationComparisonTests
{
    [Theory]
    [InlineData(0L)]
    [InlineData(0x800L)]
    [InlineData(0x2000L)]
    [InlineData(0x80000000L)]
    [InlineData(0x2801L)]
    [InlineData(0x80002801L)]
    [InlineData(2L)]
    [InlineData(0x80002803L)]
    [InlineData(0x100000000L)]
    [InlineData(-2147483648L)]
    [InlineData(long.MinValue)]
    [InlineData(long.MaxValue)]
    public void Full_width_option_validation_matches_for_constructors_and_setter(long option)
    {
        var comparison = new Comparison($"DirSync option=0x{option:X16}");
        Ms.DirectorySynchronization? expected = null;
        Ours.DirectorySynchronization? actual = null;
        Exceptions(comparison, "options constructor",
            () => expected = new Ms.DirectorySynchronization((Ms.DirectorySynchronizationOptions)option),
            () => actual = new Ours.DirectorySynchronization((Ours.DirectorySynchronizationOptions)option));
        CompareCreated("options constructor");
        expected = null;
        actual = null;
        Exceptions(comparison, "options and cookie constructor",
            () => expected = new Ms.DirectorySynchronization((Ms.DirectorySynchronizationOptions)option, new byte[] { 0, 127, 255 }),
            () => actual = new Ours.DirectorySynchronization((Ours.DirectorySynchronizationOptions)option, new byte[] { 0, 127, 255 }));
        CompareCreated("options and cookie constructor");

        expected = new Ms.DirectorySynchronization(Ms.DirectorySynchronizationOptions.ObjectSecurity, new byte[] { 4, 5 });
        actual = new Ours.DirectorySynchronization(Ours.DirectorySynchronizationOptions.ObjectSecurity, new byte[] { 4, 5 });
        Exceptions(comparison, "setter", () => expected.Option = (Ms.DirectorySynchronizationOptions)option,
            () => actual.Option = (Ours.DirectorySynchronizationOptions)option);
        State(comparison, "setter state including rejected assignment", expected, actual);
        comparison.Assert();

        void CompareCreated(string label)
        {
            comparison.Check($"{label}: created", expected is not null, actual is not null);
            if (expected is not null && actual is not null)
                State(comparison, label, expected, actual);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Copies_preserve_options_and_isolate_later_mutations(bool useCopyMethod, bool emptyCookie)
    {
        var expected = new Ms.DirectorySynchronization(Ms.DirectorySynchronizationOptions.ParentsFirst,
            emptyCookie ? Array.Empty<byte>() : new byte[] { 1, 2, 255 });
        var actual = new Ours.DirectorySynchronization(Ours.DirectorySynchronizationOptions.ParentsFirst,
            emptyCookie ? Array.Empty<byte>() : new byte[] { 1, 2, 255 });
        var expectedCopy = useCopyMethod ? expected.Copy() : new Ms.DirectorySynchronization(expected);
        var actualCopy = useCopyMethod ? actual.Copy() : new Ours.DirectorySynchronization(actual);
        var comparison = new Comparison($"DirSync copy method={useCopyMethod}, empty={emptyCookie}");
        comparison.Check("same instance", ReferenceEquals(expected, expectedCopy), ReferenceEquals(actual, actualCopy));
        State(comparison, "initial copy", expectedCopy, actualCopy);

        expected.Option = Ms.DirectorySynchronizationOptions.PublicDataOnly;
        actual.Option = Ours.DirectorySynchronizationOptions.PublicDataOnly;
        expected.ResetDirectorySynchronizationCookie(new byte[] { 8, 9 });
        actual.ResetDirectorySynchronizationCookie(new byte[] { 8, 9 });
        State(comparison, "copy after source mutation", expectedCopy, actualCopy);
        expectedCopy.Option = Ms.DirectorySynchronizationOptions.IncrementalValues;
        actualCopy.Option = Ours.DirectorySynchronizationOptions.IncrementalValues;
        expectedCopy.ResetDirectorySynchronizationCookie(new byte[] { 3, 4, 5 });
        actualCopy.ResetDirectorySynchronizationCookie(new byte[] { 3, 4, 5 });
        State(comparison, "source after copy mutation", expected, actual);
        State(comparison, "copy after own mutation", expectedCopy, actualCopy);

        var expectedRead = expectedCopy.GetDirectorySynchronizationCookie();
        var actualRead = actualCopy.GetDirectorySynchronizationCookie();
        expectedRead[0] = 99;
        actualRead[0] = 99;
        State(comparison, "copy after returned array mutation", expectedCopy, actualCopy);
        State(comparison, "source after returned array mutation", expected, actual);
        comparison.Assert();
    }

    [Theory]
    [InlineData("parameterless")]
    [InlineData("null")]
    [InlineData("empty")]
    [InlineData("nonempty")]
    public void Reset_preserves_options_and_detaches_cookie_buffers(string reset)
    {
        var expected = new Ms.DirectorySynchronization(Ms.DirectorySynchronizationOptions.IncrementalValues, new byte[] { 1, 2 });
        var actual = new Ours.DirectorySynchronization(Ours.DirectorySynchronizationOptions.IncrementalValues, new byte[] { 1, 2 });
        var oldExpected = expected.GetDirectorySynchronizationCookie();
        var oldActual = actual.GetDirectorySynchronizationCookie();
        byte[]? expectedInput = reset == "null" ? null : reset == "empty" ? Array.Empty<byte>() : new byte[] { 7, 8, 9 };
        var actualInput = expectedInput?.ToArray();
        if (reset == "parameterless")
        {
            expected.ResetDirectorySynchronizationCookie();
            actual.ResetDirectorySynchronizationCookie();
        }
        else
        {
            expected.ResetDirectorySynchronizationCookie(expectedInput);
            actual.ResetDirectorySynchronizationCookie(actualInput);
        }
        var comparison = new Comparison($"DirSync reset={reset}");
        State(comparison, "immediately after reset", expected, actual);
        oldExpected[0] = 44;
        oldActual[0] = 44;
        if (expectedInput is { Length: > 0 } && actualInput is { Length: > 0 })
        {
            expectedInput[0] = 55;
            actualInput[0] = 55;
        }
        State(comparison, "after previous and input buffer mutations", expected, actual);
        expected.ResetDirectorySynchronizationCookie(new byte[] { 10, 11 });
        actual.ResetDirectorySynchronizationCookie(new byte[] { 10, 11 });
        State(comparison, "after reseeding", expected, actual);
        comparison.Assert();
    }

    private static void Exceptions(Comparison comparison, string label, Action expected, Action actual)
    {
        var left = Record.Exception(expected);
        var right = Record.Exception(actual);
        comparison.Check($"{label}: exception", left?.GetType().FullName, right?.GetType().FullName)
            .Check($"{label}: parameter", (left as ArgumentException)?.ParamName, (right as ArgumentException)?.ParamName);
    }

    private static void State(Comparison comparison, string label, Ms.DirectorySynchronization expected, Ours.DirectorySynchronization actual)
    {
        comparison.Check($"{label}: option", (long)expected.Option, (long)actual.Option)
            .Check($"{label}: cookie", Convert.ToHexString(expected.GetDirectorySynchronizationCookie()),
                Convert.ToHexString(actual.GetDirectorySynchronizationCookie()));
    }
}
