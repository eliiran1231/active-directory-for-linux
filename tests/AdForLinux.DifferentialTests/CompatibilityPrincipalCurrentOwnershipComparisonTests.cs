using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "PrincipalCurrentOwnershipLive")]
public sealed class CompatibilityPrincipalCurrentOwnershipComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Repeated_Current_returns_matching_wrapper_ownership(bool disposeFirst)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var leftFilter = new Ms.UserPrincipal(expectedContext) { SamAccountName = data.UserName };
        using var rightFilter = new Ours.UserPrincipal(actualContext) { SamAccountName = data.UserName };
        using var leftSearch = new Ms.PrincipalSearcher(leftFilter);
        using var rightSearch = new Ours.PrincipalSearcher(rightFilter);
        using var leftResults = leftSearch.FindAll();
        using var rightResults = rightSearch.FindAll();
        using var leftCursor = leftResults.GetEnumerator();
        using var rightCursor = rightResults.GetEnumerator();
        var leftOwned = new HashSet<Ms.Principal>(ReferenceEqualityComparer.Instance);
        var rightOwned = new HashSet<Ours.Principal>(ReferenceEqualityComparer.Instance);
        try
        {
            Assert.True(leftCursor.MoveNext());
            Assert.True(rightCursor.MoveNext());
            var leftFirst = leftCursor.Current;
            leftOwned.Add(leftFirst);
            var rightFirst = rightCursor.Current;
            rightOwned.Add(rightFirst);
            var leftSecond = leftCursor.Current;
            leftOwned.Add(leftSecond);
            var rightSecond = rightCursor.Current;
            rightOwned.Add(rightSecond);
            // Validate both reads before checking identity or disposing either.
            foreach (var principal in new[] { leftFirst, leftSecond })
                Assert.Equal(data.UserDn, principal.DistinguishedName, StringComparer.OrdinalIgnoreCase);
            foreach (var principal in new[] { rightFirst, rightSecond })
                Assert.Equal(data.UserDn, principal.DistinguishedName, StringComparer.OrdinalIgnoreCase);
            Assert.False(leftCursor.MoveNext());
            Assert.False(rightCursor.MoveNext());

            var comparison = new Comparison($"Principal Current ownership: disposeFirst={disposeFirst}")
                .Check("repeated Current shares wrapper", ReferenceEquals(leftFirst, leftSecond),
                    ReferenceEquals(rightFirst, rightSecond));
            if (disposeFirst)
            {
                leftFirst.Dispose();
                leftOwned.Remove(leftFirst);
                rightFirst.Dispose();
                rightOwned.Remove(rightFirst);
            }
            var leftAfter = ReadDn(() => leftSecond.DistinguishedName);
            var rightAfter = ReadDn(() => rightSecond.DistinguishedName);
            Assert.Null(leftAfter.Error);
            Assert.Equal(data.UserDn, leftAfter.Dn, StringComparer.OrdinalIgnoreCase);
            comparison.Check("retained second wrapper error", leftAfter.Error, rightAfter.Error)
                .Check("retained second wrapper DN", leftAfter.Dn?.ToUpperInvariant(), rightAfter.Dn?.ToUpperInvariant())
                .Assert();
        }
        finally
        {
            // Distinct-by-reference cleanup: the clone may return one object
            // twice, and Principal.Equals compares identity rather than ownership.
            foreach (var principal in leftOwned) principal.Dispose();
            foreach (var principal in rightOwned) principal.Dispose();
        }
    }

    private static (Type? Error, string? Dn) ReadDn(Func<string?> read)
    {
        string? dn = null;
        var error = Record.Exception(() => dn = read());
        return (error?.GetType(), dn);
    }
}
