using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class PersistedPrincipalEqualityDisposalComparisonTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var sameIdentity in new[] { true, false })
        foreach (var disposeLeft in new[] { false, true })
        foreach (var disposeRight in new[] { false, true })
            yield return new object[] { sameIdentity, disposeLeft, disposeRight };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Equality_of_separately_loaded_principals_survives_disposal_like_microsoft(
        bool sameIdentity, bool disposeLeft, bool disposeRight)
    {
        // Microsoft's Equals compares its stored identity key, whereas the
        // clone reads Guid through a getter guarded by CheckDisposedOrDeleted.
        // Use fresh query results: saved-new principals need not have the same
        // identity-key initialization as principals returned by FindByIdentity.
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((msOwner, ourOwner, _, _) =>
        {
            var leftDn = msOwner.DistinguishedName!;
            var rightDn = sameIdentity ? leftDn : ourOwner.DistinguishedName!;
            using var msLeft = Ms.UserPrincipal.FindByIdentity(msOwner.Context, Ms.IdentityType.DistinguishedName, leftDn);
            using var msRight = Ms.UserPrincipal.FindByIdentity(msOwner.Context, Ms.IdentityType.DistinguishedName, rightDn);
            using var ourLeft = Ours.UserPrincipal.FindByIdentity(ourOwner.Context, Ours.IdentityType.DistinguishedName, leftDn);
            using var ourRight = Ours.UserPrincipal.FindByIdentity(ourOwner.Context, Ours.IdentityType.DistinguishedName, rightDn);
            Assert.NotNull(msLeft);
            Assert.NotNull(msRight);
            Assert.NotNull(ourLeft);
            Assert.NotNull(ourRight);
            Assert.NotSame(msLeft, msRight);
            Assert.NotSame(ourLeft, ourRight);
            Assert.NotNull(msLeft.Guid);
            Assert.NotNull(msRight.Guid);
            Assert.Equal(msLeft.Guid, ourLeft.Guid);
            Assert.Equal(msRight.Guid, ourRight.Guid);
            Assert.Equal(sameIdentity, msLeft.Equals(msRight));
            Assert.Equal(sameIdentity, ourLeft.Equals(ourRight));

            if (disposeLeft)
            {
                msLeft.Dispose();
                ourLeft.Dispose();
            }
            if (disposeRight)
            {
                msRight.Dispose();
                ourRight.Dispose();
            }

            var comparison = new Comparison(
                $"Persisted equality: same identity={sameIdentity}, disposed left={disposeLeft}, right={disposeRight}");
            Compare("left.Equals(right)", () => msLeft.Equals(msRight), () => ourLeft.Equals(ourRight));
            Compare("right.Equals(left)", () => msRight.Equals(msLeft), () => ourRight.Equals(ourLeft));
            // These exercise early exits in Equals without reading identity.
            Compare("self", () => msLeft.Equals(msLeft), () => ourLeft.Equals(ourLeft));
            Compare("null", () => msLeft.Equals(null), () => ourLeft.Equals(null));
            Compare("unrelated object", () => msLeft.Equals("not a principal"), () => ourLeft.Equals("not a principal"));
            comparison.Assert();

            void Compare(string label, Func<bool> microsoft, Func<bool> ours)
            {
                bool? expectedValue = null;
                bool? actualValue = null;
                var expectedError = Record.Exception(() => { expectedValue = microsoft(); });
                var actualError = Record.Exception(() => { actualValue = ours(); });
                comparison.Check($"{label}: exception", expectedError?.GetType(), actualError?.GetType());
                comparison.Check($"{label}: result", expectedValue, actualValue);
            }
        });
    }
}
