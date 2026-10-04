using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Normal context construction may contact AD; principals remain unsaved.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityDisposedPendingMemberComparisonTests
{
    [Theory]
    [InlineData(false)] // Positive control: the staged member is alive.
    [InlineData(true)]
    public void Contains_retains_staged_member_identity_after_member_disposal(bool disposeMember)
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
        Assert.True(expectedMembers.Contains(expectedMember));
        Assert.True(actualMembers.Contains(actualMember));
        Assert.True(expectedMembers.Count == 1);
        Assert.True(actualMembers.Count == 1);

        if (disposeMember)
        {
            expectedMember.Dispose();
            actualMember.Dispose();
        }

        var expected = Observe(() => expectedMembers.Contains(expectedMember));
        var actual = Observe(() => actualMembers.Contains(actualMember));
        Assert.Equal("returned True", expected);
        Assert.Equal(expected, actual);
    }

    private static string Observe(Func<bool> action)
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
