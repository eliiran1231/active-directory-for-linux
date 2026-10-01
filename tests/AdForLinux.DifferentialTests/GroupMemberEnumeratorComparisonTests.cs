using System.Collections;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Context construction may contact AD. The groups stay unsaved: these tests
// exercise public membership traversal without creating or modifying AD objects.
[Collection("differential")]
public sealed class GroupMemberEnumeratorComparisonTests(ITestOutputHelper output)
{
    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Current_at_invalid_position_matches_microsoft(bool exhausted, bool nongeneric)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.GroupPrincipal(microsoftContext);
        using var ours = new Ours.GroupPrincipal(ourContext);
        using var expected = microsoft.Members.GetEnumerator();
        using var actual = ours.Members.GetEnumerator();
        Assert.Empty(microsoft.Members);
        Assert.Empty(ours.Members);
        if (exhausted)
        {
            Assert.False(expected.MoveNext());
            Assert.False(actual.MoveNext());
        }

        Compare(
            Observe(() => nongeneric ? ((IEnumerator)expected).Current : expected.Current),
            Observe(() => nongeneric ? ((IEnumerator)actual).Current : actual.Current));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reset_without_mutation_matches_microsoft(bool exhausted)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.GroupPrincipal(microsoftContext);
        using var ours = new Ours.GroupPrincipal(ourContext);
        using var expected = microsoft.Members.GetEnumerator();
        using var actual = ours.Members.GetEnumerator();
        if (exhausted)
        {
            Assert.False(expected.MoveNext());
            Assert.False(actual.MoveNext());
        }

        var expectedReset = Observe(() => { expected.Reset(); return "reset"; });
        var actualReset = Observe(() => { actual.Reset(); return "reset"; });
        // Advance after the attempted reset as well, so failure diagnostics
        // include both the reset result and the retained traversal state.
        Compare(expectedReset + "; next=" + Observe(() => expected.MoveNext()),
            actualReset + "; next=" + Observe(() => actual.MoveNext()));
    }

    [Theory]
    [InlineData(false, false)] // Controls: unchanged empty enumeration stays usable.
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Clear_invalidates_existing_enumerator_like_microsoft(bool exhausted, bool clear)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.GroupPrincipal(microsoftContext);
        using var ours = new Ours.GroupPrincipal(ourContext);
        using var expected = microsoft.Members.GetEnumerator();
        using var actual = ours.Members.GetEnumerator();
        if (exhausted)
        {
            Assert.False(expected.MoveNext());
            Assert.False(actual.MoveNext());
        }

        if (clear)
        {
            // Microsoft detects changes using DateTime.UtcNow timestamps.
            // Cross a clock tick after construction to avoid a same-tick race.
            var afterConstruction = DateTime.UtcNow;
            Assert.True(SpinWait.SpinUntil(() => DateTime.UtcNow > afterConstruction, 2000));
            microsoft.Members.Clear();
            ours.Members.Clear();
        }

        var expectedNext = Observe(() => expected.MoveNext());
        var actualNext = Observe(() => actual.MoveNext());
        Assert.Empty(microsoft.Members);
        Assert.Empty(ours.Members);
        Compare(expectedNext, actualNext);
    }

    [Theory]
    [InlineData("Current")]
    [InlineData("MoveNext")]
    [InlineData("Reset")]
    public void Disposed_enumerator_operations_match_microsoft(string operation)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.GroupPrincipal(microsoftContext);
        using var ours = new Ours.GroupPrincipal(ourContext);
        using var expected = microsoft.Members.GetEnumerator();
        using var actual = ours.Members.GetEnumerator();
        expected.Dispose();
        actual.Dispose();

        Compare(Observe(() => Invoke(expected, operation)), Observe(() => Invoke(actual, operation)));
    }

    private static object? Invoke(IEnumerator enumerator, string operation)
    {
        if (operation == "Current") return enumerator.Current;
        if (operation == "MoveNext") return enumerator.MoveNext();
        enumerator.Reset();
        return "reset";
    }

    private static string Observe(Func<object?> action)
    {
        try { return $"returned {action() ?? "<null>"}"; }
        catch (Exception error) { return $"threw {error.GetType().Name}"; }
    }

    private void Compare(string expected, string actual)
    {
        output.WriteLine($"Microsoft: {expected}; AdForLinux: {actual}");
        Assert.Equal(expected, actual);
    }
}
