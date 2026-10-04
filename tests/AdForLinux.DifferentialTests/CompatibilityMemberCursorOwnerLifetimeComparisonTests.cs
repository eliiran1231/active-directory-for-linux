using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Normal context construction may contact AD; principals remain unsaved.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityMemberCursorOwnerLifetimeComparisonTests
{
    [Theory]
    [InlineData("alive")]
    [InlineData("group-disposed")]
    [InlineData("cursor-disposed")]
    public void Positioned_cursor_current_and_reset_follow_cursor_lifetime(string lifetime)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        using var expectedGroup = new Ms.GroupPrincipal(expectedContext);
        using var actualGroup = new Ours.GroupPrincipal(actualContext);
        using var expectedMember = new Ms.UserPrincipal(expectedContext);
        using var actualMember = new Ours.UserPrincipal(actualContext);
        var expectedMembers = expectedGroup.Members;
        var actualMembers = actualGroup.Members;
        expectedMembers.Add(expectedMember);
        actualMembers.Add(actualMember);
        using var expectedCursor = expectedMembers.GetEnumerator();
        using var actualCursor = actualMembers.GetEnumerator();
        Assert.True(expectedCursor.MoveNext());
        Assert.True(actualCursor.MoveNext());
        Assert.Same(expectedMember, expectedCursor.Current);
        Assert.Same(actualMember, actualCursor.Current);

        if (lifetime == "group-disposed")
        {
            expectedGroup.Dispose();
            actualGroup.Dispose();
        }
        else if (lifetime == "cursor-disposed")
        {
            expectedCursor.Dispose();
            actualCursor.Dispose();
        }

        // Capture both operations before assertions: Reset must not mask Current.
        var expectedCurrent = Observe(() => ReferenceEquals(expectedMember, expectedCursor.Current));
        var actualCurrent = Observe(() => ReferenceEquals(actualMember, actualCursor.Current));
        var expectedReset = Observe(() => { expectedCursor.Reset(); return "reset"; });
        var actualReset = Observe(() => { actualCursor.Reset(); return "reset"; });
        if (lifetime == "group-disposed")
        {
            // The collection really was disposed, even though the cursor survives.
            Assert.Throws<ObjectDisposedException>(() => expectedMembers.Count);
            Assert.Throws<ObjectDisposedException>(() => actualMembers.Count);
        }
        else
        {
            Assert.True(expectedMembers.Count == 1);
            Assert.True(actualMembers.Count == 1);
        }

        Assert.Equal(lifetime == "cursor-disposed" ? "threw ObjectDisposedException" : "returned True", expectedCurrent);
        Assert.Equal(lifetime == "cursor-disposed" ? "threw ObjectDisposedException" : "returned reset", expectedReset);
        Assert.Equal(new[] { expectedCurrent, expectedReset }, new[] { actualCurrent, actualReset });
    }

    private static string Observe(Func<object?> action)
    {
        try { return $"returned {action()}"; }
        catch (Exception error) { return $"threw {error.GetType().Name}"; }
    }

    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
}
