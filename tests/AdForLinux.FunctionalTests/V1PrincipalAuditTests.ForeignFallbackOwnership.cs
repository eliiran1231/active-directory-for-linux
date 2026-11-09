using System.Reflection;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-32-545")]
    public void Foreign_well_known_principal_fallback_retains_identity_and_owns_the_store_entry(string sid)
    {
        using var fixture = new Fixture();
        fixture.Server["objectSid"] = [SidCodec.Parse(sid)];
        typeof(PrincipalContext).GetField("_canUseGlobalCatalog", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(fixture.Context, false);
        var discoveryAttempts = 0;
        fixture.Context.TransportSessionFactory = _ =>
        {
            discoveryAttempts++;
            throw new InvalidOperationException("Well-known fallback must not discover another authority.");
        };

        using var principal = ForeignPrincipalResolver.ResolveOrCreateFallback(fixture.Context, fixture.Entry);

        Assert.IsType<ForeignSecurityPrincipal>(principal);
        Assert.Equal(sid, principal.SidValue);
        Assert.Equal(sid, principal.Sid!.Value);
        Assert.Equal("CN=item,DC=example,DC=test", principal.DistinguishedName);
        Assert.Same(fixture.Context, principal.Context);
        Assert.Same(fixture.Entry, principal.GetUnderlyingObject());
        Assert.NotNull(principal.Guid);
        Assert.Equal(0, discoveryAttempts);
        Assert.Single(fixture.Reads);
        Assert.Empty(fixture.Writes);
        Assert.False(fixture.Entry.IsDisposed);

        principal.Dispose();
        Assert.True(fixture.Entry.IsDisposed);
        using var nextQuery = new UserPrincipal(fixture.Context);
        Assert.Same(fixture.Context, nextQuery.Context);
        Assert.Equal(0, discoveryAttempts);
        Assert.Single(fixture.Reads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Foreign_fallback_refuses_missing_or_text_SID_and_disposes_entry_before_discovery(bool textSid)
    {
        using var fixture = new Fixture();
        fixture.Server.Remove("objectSid");
        if (textSid) fixture.Server["objectSid"] = ["S-1-5-18"];
        var discoveryAttempts = 0;
        fixture.Context.TransportSessionFactory = _ =>
        {
            discoveryAttempts++;
            throw new InvalidOperationException("Unusable SID must fail before authority discovery.");
        };

        Assert.Throws<PrincipalOperationException>(() =>
            ForeignPrincipalResolver.ResolveOrCreateFallback(fixture.Context, fixture.Entry));

        Assert.True(fixture.Entry.IsDisposed);
        Assert.Equal(0, discoveryAttempts);
        Assert.Single(fixture.Reads);
        Assert.Empty(fixture.Writes);
        using var query = new UserPrincipal(fixture.Context);
        Assert.Same(fixture.Context, query.Context);
    }
}
