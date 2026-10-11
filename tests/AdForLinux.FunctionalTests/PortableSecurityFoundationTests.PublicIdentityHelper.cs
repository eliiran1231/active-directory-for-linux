#pragma warning disable CA1416
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Public_identity_helpers_construct_without_io_and_same_kind_survives_owner_disposal(bool context)
    {
        using var entry = new IdentityFixture(); using var principal = new PrincipalIdentityFixture();
        var resolver = context ? principal.Context.CreateIdentityResolver() : DirectoryIdentityResolver.ForEntry(entry.Entry);
        var sid = new SecurityIdentifier(U1, 0); var name = new NTAccount("EXAMPLE", "alice");
        Assert.Same(sid, resolver.Translate(sid, typeof(SecurityIdentifier)));
        if (context) principal.Context.Dispose(); else entry.Entry.Dispose();
        Assert.Same(sid, resolver.Translate(sid, typeof(SecurityIdentifier)));
        Assert.Same(name, resolver.Translate(name, typeof(NTAccount)));
        var input = new IdentityReferenceCollection { sid, sid };
        var result = resolver.Translate(input, typeof(SecurityIdentifier));
        Assert.NotSame(input, result); Assert.Same(sid, result[0]); Assert.Same(sid, result[1]);
        Assert.Empty(resolver.Translate(new IdentityReferenceCollection(), typeof(NTAccount)));
        Assert.Throws<ObjectDisposedException>(() => resolver.Translate(sid, typeof(NTAccount)));
        Assert.Equal(0, entry.Opened); Assert.Equal(0, principal.Transport.Opened);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Public_identity_helper_collection_preserves_order_unmapped_values_and_data_only_results(bool context, bool force)
    {
        using var entry = new IdentityFixture(); using var principal = new PrincipalIdentityFixture();
        var transport = context ? principal.Transport : entry;
        var resolver = context ? principal.Context.CreateIdentityResolver() : DirectoryIdentityResolver.ForEntry(entry.Entry);
        var missingFilter = "(objectSid=" + string.Concat(U2.Select(b => "\\" + b.ToString("x2"))) + ")";
        transport.Results = request => ((string)request.Filter).Contains(missingFilter) ? [] : [transport.Account()];
        var first = new SecurityIdentifier(U1, 0); var missing = new SecurityIdentifier(U2, 0); var offline = new NTAccount("offline");
        var input = new IdentityReferenceCollection { first, missing, offline, first };
        if (force)
        {
            var error = Assert.Throws<IdentityNotMappedException>(() => resolver.Translate(input, typeof(NTAccount), true));
            Assert.Same(missing, Assert.Single(error.UnmappedIdentities));
        }
        else
        {
            var output = resolver.Translate(input, typeof(NTAccount)); // approved default forceSuccess=false
            Assert.Equal(new[] { "EXAMPLE\\alice", missing.Value, "offline", "EXAMPLE\\alice" }, output.Select(x => x.Value));
            Assert.Same(missing, output[1]); Assert.Same(offline, output[2]); Assert.Same(output[0], output[3]);
            Assert.Throws<NotSupportedException>(() => output[0].Translate(typeof(SecurityIdentifier)));
            var copied = new IdentityReference[output.Count]; output.CopyTo(copied, 0);
            Assert.Throws<NotSupportedException>(() => copied[0].Translate(typeof(SecurityIdentifier)));
        }
        Assert.Equal(new IdentityReference[] { first, missing, offline, first }, input.ToArray());
        Assert.Equal(2, transport.AccountRequests.Count());
        Assert.Equal(1, transport.Opened); Assert.Equal(1, transport.Closed);
    }

    [Theory]
    [InlineData(false, "timeout")] [InlineData(true, "timeout")]
    [InlineData(false, "denied")] [InlineData(true, "denied")]
    public void Public_partial_translation_never_converts_transport_failure_into_unmapped_result(bool context, string failure)
    {
        using var entry = new IdentityFixture(); using var principal = new PrincipalIdentityFixture();
        var transport = context ? principal.Transport : entry;
        var resolver = context ? principal.Context.CreateIdentityResolver() : DirectoryIdentityResolver.ForEntry(entry.Entry);
        Exception expected = failure == "timeout" ? new TimeoutException("controlled") : new UnauthorizedAccessException("controlled");
        transport.Results = _ => throw expected;
        Assert.Same(expected, Record.Exception(() => resolver.Translate(
            new IdentityReferenceCollection { new SecurityIdentifier(U1, 0) }, typeof(NTAccount))));
        Assert.Equal(1, transport.Opened); Assert.Equal(1, transport.Closed);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Public_helper_discards_collection_result_after_owner_changes_during_lookup(bool context)
    {
        using var entry = new IdentityFixture(); using var principal = new PrincipalIdentityFixture();
        var transport = context ? principal.Transport : entry;
        var resolver = context ? principal.Context.CreateIdentityResolver() : DirectoryIdentityResolver.ForEntry(entry.Entry);
        transport.BeforeResponse = request =>
        {
            if (!request.Attributes.Contains("sAMAccountName")) return;
            if (context) principal.Context.Dispose(); else entry.Entry.Username = "changed";
        };
        var sid = new SecurityIdentifier(U1, 0);
        var input = new IdentityReferenceCollection { sid, new SecurityIdentifier(U2, 0) };
        Assert.IsAssignableFrom<InvalidOperationException>(Record.Exception(() => resolver.Translate(input, typeof(NTAccount))));
        Assert.Same(sid, input[0]); Assert.Equal(2, input.Count);
        Assert.Single(transport.AccountRequests); Assert.Equal(1, transport.Opened); Assert.Equal(1, transport.Closed);
        Assert.Same(sid, resolver.Translate(sid, typeof(SecurityIdentifier)));
    }

    [Fact]
    public void Public_helper_results_and_descriptor_copies_do_not_attach_lookup_authority()
    {
        using var fixture = new IdentityFixture();
        fixture.Entry.Options.SecurityMasks = AllEntrySections;
        fixture.Entry.SecurityReadOverride = _ => Build(U1, U1, Acl(4), Acl(4));
        var source = fixture.Entry.ObjectSecurity;
        var resolver = DirectoryIdentityResolver.ForEntry(fixture.Entry);
        var name = resolver.Translate(source.GetOwner(typeof(SecurityIdentifier))!, typeof(NTAccount));
        Assert.Throws<NotSupportedException>(() => name.Translate(typeof(SecurityIdentifier)));
        var copy = new ActiveDirectorySecurity(); copy.SetSecurityDescriptorBinaryForm(source.GetSecurityDescriptorBinaryForm());
        Assert.Throws<NotSupportedException>(() => copy.GetOwner(typeof(NTAccount)));
        fixture.Entry.Close();
        Assert.Throws<InvalidOperationException>(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(new SecurityIdentifier(U1, 0), copy.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }
}
