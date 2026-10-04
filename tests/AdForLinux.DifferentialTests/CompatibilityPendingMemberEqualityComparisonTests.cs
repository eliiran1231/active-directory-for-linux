using System.Runtime.CompilerServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// The existing fixture creates/deletes AD objects. This method performs only
// reads and unsaved group edits; execute only in an authorized disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityPendingMemberEqualityComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;
    public CompatibilityPendingMemberEqualityComparisonTests(TestDataFixture data) => _data = data;

    // Microsoft's inserted-value lists dispatch Principal.Equals. The clone
    // falls back to a DN staging key even when the retained member rejects
    // equality with a second wrapper of the same directory object.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollection.cs#L508
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Pending_contains_honors_principal_equality(bool referenceEquality)
    {
        using var raw = new MsDirectory.DirectoryEntry(DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        raw.RefreshCache(new[] { "distinguishedName", "sAMAccountName", "objectGUID" });
        Assert.Equal(_data.UserDn, (string)raw.Properties["distinguishedName"].Value!, ignoreCase: true);
        Assert.Equal(_data.UserName, raw.Properties["sAMAccountName"].Value);
        var identity = raw.Guid;
        Assert.NotEqual(Guid.Empty, identity);

        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expectedA = FindMicrosoft(expectedContext, referenceEquality);
        using var expectedB = FindMicrosoft(expectedContext, referenceEquality);
        using var actualA = FindOurs(actualContext, referenceEquality);
        using var actualB = FindOurs(actualContext, referenceEquality);
        Assert.NotNull(expectedA);
        Assert.NotNull(expectedB);
        Assert.NotNull(actualA);
        Assert.NotNull(actualB);
        Assert.NotSame(expectedA, expectedB);
        Assert.NotSame(actualA, actualB);
        foreach (var principal in new[] { expectedA, expectedB })
        {
            Assert.Equal(identity, principal.Guid);
            Assert.Equal(_data.UserDn, principal.DistinguishedName, ignoreCase: true);
            Assert.Equal(_data.UserName, principal.SamAccountName);
        }
        foreach (var principal in new[] { actualA, actualB })
        {
            Assert.Equal(identity, principal.Guid);
            Assert.Equal(_data.UserDn, principal.DistinguishedName, ignoreCase: true);
            Assert.Equal(_data.UserName, principal.SamAccountName);
        }
        Assert.Equal(!referenceEquality, expectedA.Equals(expectedB));
        Assert.Equal(!referenceEquality, actualA.Equals(actualB));
        Assert.Equal(!referenceEquality, expectedB.Equals(expectedA));
        Assert.Equal(!referenceEquality, actualB.Equals(actualA));
        Assert.True(expectedA.Equals(expectedA));
        Assert.True(actualA.Equals(actualA));

        using var expectedGroup = new Ms.GroupPrincipal(expectedContext);
        using var actualGroup = new Ours.GroupPrincipal(actualContext);
        Assert.Null(expectedGroup.Guid);
        Assert.Null(actualGroup.Guid);
        Assert.False(expectedGroup.Members.Contains(expectedB));
        Assert.False(actualGroup.Members.Contains(actualB));
        expectedGroup.Members.Add(expectedA);
        actualGroup.Members.Add(actualA);
        Assert.True(expectedGroup.Members.Count == 1);
        Assert.True(actualGroup.Members.Count == 1);
        Assert.True(expectedGroup.Members.Contains(expectedA));
        Assert.True(actualGroup.Members.Contains(actualA));
        var expectedContains = expectedGroup.Members.Contains(expectedB);
        var actualContains = actualGroup.Members.Contains(actualB);
        Assert.Equal(!referenceEquality, expectedContains);
        // No Save: group membership never reaches the directory.
        Assert.Null(expectedGroup.DistinguishedName);
        Assert.Null(actualGroup.DistinguishedName);
        new Comparison($"Pending Contains equality; reference override={referenceEquality}")
            .Check("contains a distinct wrapper of the same directory identity", expectedContains, actualContains)
            .Check("count after Contains", expectedGroup.Members.Count, actualGroup.Members.Count)
            .Assert();
    }

    private Ms.UserPrincipal? FindMicrosoft(Ms.PrincipalContext context, bool custom) => custom
        ? MicrosoftReferenceUser.Find(context, _data.UserDn)
        : Ms.UserPrincipal.FindByIdentity(context, Ms.IdentityType.DistinguishedName, _data.UserDn);
    private Ours.UserPrincipal? FindOurs(Ours.PrincipalContext context, bool custom) => custom
        ? OurReferenceUser.Find(context, _data.UserDn)
        : Ours.UserPrincipal.FindByIdentity(context, Ours.IdentityType.DistinguishedName, _data.UserDn);

    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    public sealed class MicrosoftReferenceUser : Ms.UserPrincipal
    {
        public MicrosoftReferenceUser(Ms.PrincipalContext context) : base(context) { }
        public static MicrosoftReferenceUser? Find(Ms.PrincipalContext context, string dn) =>
            (MicrosoftReferenceUser?)FindByIdentityWithType(context, typeof(MicrosoftReferenceUser),
                Ms.IdentityType.DistinguishedName, dn);
        public override bool Equals(object? other) => ReferenceEquals(this, other);
        public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    public sealed class OurReferenceUser : Ours.UserPrincipal
    {
        public OurReferenceUser(Ours.PrincipalContext context) : base(context) { }
        public static OurReferenceUser? Find(Ours.PrincipalContext context, string dn) =>
            (OurReferenceUser?)FindByIdentityWithType(context, typeof(OurReferenceUser),
                Ours.IdentityType.DistinguishedName, dn);
        public override bool Equals(object? other) => ReferenceEquals(this, other);
        public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);
    }
}
