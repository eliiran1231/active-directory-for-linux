using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class CrossContextFixture : IDisposable
    {
        internal const string DomainDn = "DC=example,DC=test";
        internal const string ItemDn = "CN=item," + DomainDn;
        internal readonly PrincipalContext Source = new(ContextType.Domain, "source.invalid", DomainDn,
            ContextOptions.Negotiate, "source-reader", "source-test-value");
        internal readonly PrincipalContext Destination = new(ContextType.Domain, "destination.invalid", DomainDn,
            ContextOptions.Negotiate, "destination-reader", "destination-test-value");
        internal readonly Guid DomainGuid = Guid.NewGuid(), ObjectGuid = Guid.NewGuid(), ContainerGuid = Guid.NewGuid();
        internal readonly string ObjectSid = new SecurityIdentifier(SecurityDescriptorFixtures.U1, 0).Value;
        internal string DomainSid => new SecurityIdentifier(ObjectSid).AccountDomainSid!.Value;
        internal readonly Guid ReplacementGuid = Guid.NewGuid();
        internal readonly DirectoryEntry Entry;
        internal readonly UserPrincipal User;
        internal readonly List<(bool Destination, string Path, string User)> Reads = [];
        internal string Fault = "";
        internal int Writes;
        internal CrossContextFixture()
        {
            foreach (var context in new[] { Source, Destination })
                typeof(PrincipalContext).GetField("_defaultNamingContext", BindingFlags.NonPublic | BindingFlags.Instance)!
                    .SetValue(context, DomainDn);
            Entry = Source.CreateDirectoryEntry(ItemDn);
            Entry.PropertyReadOverride = (_, _) =>
            {
                var values = new PropertyCollection();
                values.ReplaceLoaded("objectGUID", [(Fault == "refreshed-replacement" ? ReplacementGuid : ObjectGuid).ToByteArray()]);
                values.ReplaceLoaded("objectSid", [SidBytes(ObjectSid)]);
                return values;
            };
            Entry.WriteRequestOverride = _ => { Writes++; return System.DirectoryServices.Protocols.ResultCode.Success; };
            User = new UserPrincipal(Source);
            typeof(Principal).GetMethod("AttachExisting", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(User, [Source, Entry]);
            Source.SaveContextSearchOverride = searcher => Read(false, searcher);
            Destination.SaveContextSearchOverride = searcher => Read(true, searcher);
        }

        private SearchResultCollection Read(bool destination, DirectorySearcher searcher)
        {
            Assert.Equal(ReferralChasingOption.None, searcher.ReferralChasing);
            Assert.Equal(ReferralChasingOption.None, searcher.SearchRoot!.Options.Referral);
            var options = searcher.SearchRoot.BuildOptions();
            Assert.Equal(destination ? "destination-reader" : "source-reader", options.BindDn);
            Assert.Equal(destination ? "destination-test-value" : "source-test-value", options.BindPassword);
            Reads.Add((destination, searcher.SearchRoot.Path, options.BindDn!));
            var domain = searcher.Filter == "(objectClass=domainDNS)";
            var replica = searcher.SearchScope == SearchScope.Subtree;
            var container = destination && !domain && !replica;
            if (replica && Fault == "missing") return new SearchResultCollection([]);
            var guid = domain ? DomainGuid : container ? ContainerGuid : ObjectGuid;
            if (destination && ((domain && Fault == "domain-guid") || (replica && Fault == "object-guid"))) guid = Guid.NewGuid();
            if (!domain && !container && Fault == "refreshed-replacement") guid = ReplacementGuid;
            if (container && Fault == "empty-container-guid") guid = Guid.Empty;
            var sid = domain ? DomainSid : ObjectSid;
            if (destination && ((domain && Fault == "domain-sid") || (replica && Fault == "object-sid")))
                sid = "S-1-5-21-900-901-902-903";
            if (!destination && !domain && Fault == "source-replaced") guid = Guid.NewGuid();
            var dn = domain || container ? DomainDn : ItemDn;
            if (container && Fault == "outside-container") dn = "OU=elsewhere,DC=other,DC=test";
            if (container && Fault == "escaped-container") dn = @"CN=outside\,DC=example,DC=test";
            if (container && Fault == "nested-container") dn = "OU=valid," + DomainDn;
            var props = new ResultPropertyCollection();
            props.Set("objectGUID", [guid.ToByteArray()]); props.Set("objectSid", [SidBytes(sid)]);
            props.Set("distinguishedName", [dn]);
            var result = new SearchResult(searcher.SearchRoot, props);
            return new SearchResultCollection(replica && Fault == "duplicate" ? [result, result] : [result]);
        }
        private static byte[] SidBytes(string text)
        {
            var sid = new SecurityIdentifier(text); var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes;
        }
        public void Dispose() { User.Dispose(); Entry.Dispose(); Source.Dispose(); Destination.Dispose(); }
    }

    [Fact]
    public void Cross_context_preflight_is_data_only_and_does_not_apply_pending_rename()
    {
        using var f = new CrossContextFixture();
        f.User.Name = "pending, name"; f.User.Description = "pending description";
        f.Entry.Properties["displayName"].Value = "direct pending";
        var plan = CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry, f.ObjectGuid, CrossContextFixture.DomainDn, f.User.Name);
        Assert.Equal(f.ObjectGuid, plan.ObjectGuid); Assert.Equal(f.DomainGuid, plan.DomainGuid);
        Assert.Equal(f.ContainerGuid, plan.ContainerGuid); Assert.Equal("CN=item", plan.CurrentRdn);
        Assert.Equal("pending, name", plan.PendingName); Assert.Equal(5, f.Reads.Count);
        Assert.All(typeof(CrossContextSavePlan).GetProperties(), property =>
            Assert.True(property.PropertyType == typeof(string) || property.PropertyType == typeof(Guid)));
        Assert.Equal(0, f.Writes); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
        Assert.Equal("direct pending", f.Entry.Properties["displayName"].Value);
    }

    [Fact]
    public void Cross_context_save_refuses_after_preflight_without_changing_wrapper_authority_or_intent()
    {
        using var f = new CrossContextFixture();
        f.User.Name = "pending name"; f.User.Description = "pending description";
        var error = Assert.Throws<PlatformNotSupportedException>(() => f.User.Save(f.Destination));
        Assert.Equal(CrossContextSavePlan.ExecutionBoundary, error.Message);
        Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
        Assert.Contains("source.invalid", f.Entry.Path); Assert.Equal("source-reader", f.Entry.Username);
        Assert.Equal("pending name", f.User.Name); Assert.Equal("pending description", f.User.Description);
        Assert.Equal(0, f.Writes); Assert.Equal(5, f.Reads.Count);
    }

    [Theory]
    [InlineData("domain-guid")] [InlineData("domain-sid")]
    [InlineData("object-guid")] [InlineData("object-sid")]
    [InlineData("missing")] [InlineData("duplicate")]
    [InlineData("empty-container-guid")] [InlineData("outside-container")]
    [InlineData("source-replaced")] [InlineData("escaped-container")]
    public void Cross_context_identity_preflight_refuses_incomplete_or_conflicting_proof(string fault)
    {
        using var f = new CrossContextFixture { Fault = fault };
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
    }

    [Fact]
    public void Cross_context_preflight_rejects_refreshed_replacement_of_attached_identity()
    {
        using var f = new CrossContextFixture { Fault = "refreshed-replacement" };
        f.Entry.RefreshCache();
        Assert.Equal(f.ReplacementGuid, f.Entry.Guid);
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Same(f.Source, f.User.Context);
    }

    [Fact]
    public void Cross_context_preflight_accepts_nested_container_boundaries()
    {
        using var f = new CrossContextFixture { Fault = "nested-container" };
        var plan = CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry, f.ObjectGuid, "OU=valid," + CrossContextFixture.DomainDn, null);
        Assert.Equal("OU=valid," + CrossContextFixture.DomainDn, plan.ContainerDn);
        Assert.Equal(0, f.Writes);
    }

    [Fact]
    public void Cross_context_preflight_refuses_changed_source_authority_before_reads()
    {
        using var f = new CrossContextFixture(); f.Entry.Username = "changed-reader";
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Empty(f.Reads); Assert.Equal(0, f.Writes);
    }
}
