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

    [Theory]
    [InlineData("advance")]
    [InlineData("reset")]
    [InlineData("exhaust")]
    public void Interleaved_cursors_observe_matching_shared_result_position(string operation)
    {
        // Both seeded user names share this generated suffix; validate the
        // naming premise and then validate the complete result set separately.
        var suffix = data.UserName.Split('-')[^1];
        Assert.Equal("adfl-d-u-" + suffix, data.UserName);
        Assert.Equal("adfl-d-z-" + suffix, data.UnsetUserName);
        var pattern = "adfl-d-*-" + suffix;
        var expectedDns = new[] { data.UserDn, data.UnsetUserDn };
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var leftFilter = new Ms.UserPrincipal(expectedContext) { SamAccountName = pattern };
        using var rightFilter = new Ours.UserPrincipal(actualContext) { SamAccountName = pattern };
        using var leftSearch = new Ms.PrincipalSearcher(leftFilter);
        using var rightSearch = new Ours.PrincipalSearcher(rightFilter);
        using (var probe = leftSearch.FindAll())
            VerifySeedSet(probe, principal => principal.DistinguishedName);
        using (var probe = rightSearch.FindAll())
            VerifySeedSet(probe, principal => principal.DistinguishedName);
        using var leftResults = leftSearch.FindAll();
        using var rightResults = rightSearch.FindAll();
        using var leftA = leftResults.GetEnumerator();
        using var leftB = leftResults.GetEnumerator();
        using var rightA = rightResults.GetEnumerator();
        using var rightB = rightResults.GetEnumerator();
        var leftOwned = new HashSet<Ms.Principal>(ReferenceEqualityComparer.Instance);
        var rightOwned = new HashSet<Ours.Principal>(ReferenceEqualityComparer.Instance);
        try
        {
            Assert.True(leftA.MoveNext());
            Assert.True(rightA.MoveNext());
            var leftFirst = Take(leftA, leftOwned, p => p.DistinguishedName);
            var rightFirst = Take(rightA, rightOwned, p => p.DistinguishedName);
            Assert.True(leftA.MoveNext());
            Assert.True(rightA.MoveNext());
            var leftSecond = Take(leftA, leftOwned, p => p.DistinguishedName);
            var rightSecond = Take(rightA, rightOwned, p => p.DistinguishedName);
            Assert.False(StringComparer.OrdinalIgnoreCase.Equals(leftFirst, leftSecond));
            Assert.False(StringComparer.OrdinalIgnoreCase.Equals(rightFirst, rightSecond));

            // First MoveNext on B resets Microsoft's shared result set. A's
            // own position flags still say it is positioned at its second row.
            Assert.True(leftB.MoveNext());
            Assert.True(rightB.MoveNext());
            var leftBFirst = Take(leftB, leftOwned, p => p.DistinguishedName);
            var rightBFirst = Take(rightB, rightOwned, p => p.DistinguishedName);
            var leftAAfter = Take(leftA, leftOwned, p => p.DistinguishedName);
            var rightAAfter = Take(rightA, rightOwned, p => p.DistinguishedName);
            new Comparison("Interleaved principal cursors share underlying position")
                .Check("A now observes B's row", StringComparer.OrdinalIgnoreCase.Equals(leftAAfter, leftBFirst),
                    StringComparer.OrdinalIgnoreCase.Equals(rightAAfter, rightBFirst))
                .Check("A retains its previously observed row", StringComparer.OrdinalIgnoreCase.Equals(leftAAfter, leftSecond),
                    StringComparer.OrdinalIgnoreCase.Equals(rightAAfter, rightSecond))
                .Assert();

            // Exercise the opposite interleaving too: B must observe A's move.
            Assert.True(leftA.MoveNext());
            Assert.True(rightA.MoveNext());
            CompareCurrent("B after A advances", leftB, rightB);
            if (operation == "reset")
            {
                leftA.Reset();
                rightA.Reset();
                Assert.Throws<InvalidOperationException>(() => leftA.Current);
                Assert.Throws<InvalidOperationException>(() => rightA.Current);
                CompareCurrent("B after A resets, before A moves", leftB, rightB);
                Assert.True(leftA.MoveNext());
                Assert.True(rightA.MoveNext());
                CompareCurrent("B after reset A moves", leftB, rightB);
            }
            else if (operation == "exhaust")
            {
                Assert.False(leftA.MoveNext());
                Assert.False(rightA.MoveNext());
                leftB.Reset();
                rightB.Reset();
                Assert.True(leftB.MoveNext());
                Assert.True(rightB.MoveNext());
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    new Comparison("Exhausted A after B restarts")
                        .Check("MoveNext", leftA.MoveNext(), rightA.MoveNext()).Assert();
                    Assert.Throws<InvalidOperationException>(() => leftA.Current);
                    Assert.Throws<InvalidOperationException>(() => rightA.Current);
                    CompareCurrent("B after exhausted A moves", leftB, rightB);
                }
                leftA.Reset();
                rightA.Reset();
                Assert.True(leftA.MoveNext());
                Assert.True(rightA.MoveNext());
                CompareCurrent("A restarts after its own reset", leftA, rightA);
            }

            void CompareCurrent(string label, IEnumerator<Ms.Principal> expected, IEnumerator<Ours.Principal> actual)
            {
                var expectedDn = Take(expected, leftOwned, p => p.DistinguishedName);
                var actualDn = Take(actual, rightOwned, p => p.DistinguishedName);
                new Comparison(label).Check("DN", expectedDn.ToUpperInvariant(), actualDn.ToUpperInvariant()).Assert();
            }
        }
        finally
        {
            foreach (var principal in leftOwned) principal.Dispose();
            foreach (var principal in rightOwned) principal.Dispose();
        }

        string Take<T>(IEnumerator<T> cursor, HashSet<T> owned, Func<T, string?> dn) where T : IDisposable
        {
            var principal = cursor.Current;
            owned.Add(principal);
            var name = Assert.IsType<string>(dn(principal));
            Assert.Contains(name, expectedDns, StringComparer.OrdinalIgnoreCase);
            return name;
        }

        void VerifySeedSet<T>(IEnumerable<T> results, Func<T, string?> dn) where T : IDisposable
        {
            var names = new List<string>();
            foreach (var principal in results)
            {
                using (principal) names.Add(Assert.IsType<string>(dn(principal)));
            }
            Assert.Equal(expectedDns.Order(StringComparer.OrdinalIgnoreCase),
                names.Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
        }
    }

    private static (Type? Error, string? Dn) ReadDn(Func<string?> read)
    {
        string? dn = null;
        var error = Record.Exception(() => dn = read());
        return (error?.GetType(), dn);
    }
}
