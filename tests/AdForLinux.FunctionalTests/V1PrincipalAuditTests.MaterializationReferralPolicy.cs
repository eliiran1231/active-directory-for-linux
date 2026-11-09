using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_principal_query_policy_does_not_override_a_materialized_entry_default(bool findAll)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var searcher = fixture.Search(query);
        var underlying = Assert.IsType<DirectorySearcher>(searcher.GetUnderlyingSearcher());
        var root = underlying.SearchRoot!;
        root.Options.Referral = ReferralChasingOption.None;
        var admissions = new List<ReferralChasingOption>();
        var open = root.OperationSessionFactory!;
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
        {
            admissions.Add(referrals);
            return open(options, count, referrals, fresh, minimum);
        };
        using var results = findAll ? searcher.FindAll() : null;
        using var cursor = results?.GetEnumerator();
        if (cursor is not null) Assert.True(cursor.MoveNext());
        using var principal = cursor is null ? searcher.FindOne()! : cursor.Current;
        var entry = Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject());

        Assert.Equal(fixture.Identity, principal.Guid);
        Assert.Equal(ReferralChasingOption.None, root.Options.Referral);
        Assert.Equal(ReferralChasingOption.None, underlying.ReferralChasing);
        Assert.Equal(ReferralChasingOption.External, entry.Options.Referral);
        Assert.Equal(ReferralChasingOption.None, admissions[0]);
        Assert.Equal(ReferralChasingOption.External, admissions[^1]);
        Assert.Single(admissions, policy => policy == ReferralChasingOption.External);
        Assert.Equal(2, admissions.Count(policy => policy == ReferralChasingOption.None));
        Assert.Equal(3, admissions.Count);
        // This characterizes separate public policies; it does not label the
        // compatibility default a defect or authorize a live endpoint probe.
    }
}
