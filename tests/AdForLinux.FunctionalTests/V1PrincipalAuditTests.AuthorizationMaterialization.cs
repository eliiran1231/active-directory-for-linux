using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class AuthorizationGraphFixture : IDisposable
    {
        internal const string DomainGroup = "CN=domain-group,DC=example,DC=test";
        internal const string RenamedDomainGroup = "CN=domain-group-renamed,OU=renamed,DC=example,DC=test";
        internal const string ForestGroup = "CN=forest-group,DC=other,DC=test";
        internal const string ResourceGroup = "CN=resource-group,DC=other,DC=test";
        internal const string NoSidGroup = "CN=no-sid-group,DC=example,DC=test";
        internal const string AccountDn = "CN=item,DC=example,DC=test";
        internal const string ForeignPlaceholder = "CN=S-1-5-21-1-2-3-1001,CN=ForeignSecurityPrincipals,DC=other,DC=test";
        internal readonly Fixture Source = new();
        internal readonly List<(DirectoryEntry Root, string Filter)> Searches = [];
        internal readonly List<SearchRequest> Reads = [];
        internal readonly List<(string Dn, Guid Identity)> ReturnedObjectIdentities = [];
        internal int Opens, Disposals;
        internal bool ReturnTokens = true;
        internal bool DuplicateDomainRow;
        internal bool DistinctDnDuplicate;
        private readonly bool globalCatalog;
        private readonly bool missingSid;
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(1, 1, startTimer: false);
        private readonly byte[] firstSid = SidCodec.Parse("S-1-5-21-1-2-3-2001");
        private readonly byte[] secondSid = SidCodec.Parse("S-1-5-21-4-5-6-2002");

        internal AuthorizationGraphFixture(bool globalCatalog, bool missingSid)
        {
            this.globalCatalog = globalCatalog;
            this.missingSid = missingSid;
            var fields = BindingFlags.Instance | BindingFlags.NonPublic;
            typeof(PrincipalContext).GetField("_defaultNamingContext", fields)!.SetValue(Source.Context, "DC=example,DC=test");
            typeof(PrincipalContext).GetField("_rootDomainNamingContext", fields)!.SetValue(Source.Context, "DC=test");
            typeof(PrincipalContext).GetField("_canUseGlobalCatalog", fields)!.SetValue(Source.Context, globalCatalog);
            Source.Context.AuthorizationSearchOverride = Search;
        }

        private SearchResultCollection Search(DirectorySearcher searcher)
        {
            var root = searcher.SearchRoot!;
            Searches.Add((root, searcher.Filter));
            if (searcher.SearchScope == AdForLinux.DirectoryServices.SearchScope.Base)
            {
                Assert.Single(Searches);
                Assert.Equal(AccountDn, root.DistinguishedName);
                var properties = new ResultPropertyCollection();
                properties.Set("tokenGroups", ReturnTokens ? [firstSid, secondSid, firstSid.ToArray()] : []);
                return new SearchResultCollection([new SearchResult(root, properties)]);
            }
            Assert.Equal(AdForLinux.DirectoryServices.SearchScope.Subtree, searcher.SearchScope);
            Assert.Equal(500, searcher.PageSize);
            root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    Opens++;
                    var connection = SaveReadConnection.Create(request =>
                    {
                        var read = Assert.IsType<SearchRequest>(request);
                        Reads.Add(read);
                        if (read.DistinguishedName == "")
                            return SaveResponse("", [], 0, ResultCode.Success, false, false);
                        var values = GroupValues(read.DistinguishedName);
                        ReturnedObjectIdentities.Add((read.DistinguishedName, new Guid((byte[])values["objectGUID"][0])));
                        return SaveResponse(read.DistinguishedName, values, 1,
                            ResultCode.Success, false, false);
                    }, () => Disposals++);
                    return new BoundLdapSession(connection, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            if (Searches.Count == 2)
            {
                Assert.EndsWith("/DC=example,DC=test", root.Path);
                if (DuplicateDomainRow) return Rows(root, DomainGroup, DomainGroup.ToUpperInvariant());
                return Rows(root, missingSid ? [DomainGroup, NoSidGroup] : [DomainGroup]);
            }
            Assert.True(globalCatalog);
            Assert.EndsWith("/DC=test", root.Path);
            if (Searches.Count == 3) return Rows(root,
                DistinctDnDuplicate ? RenamedDomainGroup : DomainGroup.ToUpperInvariant(), ForestGroup);
            if (Searches.Count == 4)
            {
                Assert.Equal("(objectSid=\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\01\\00\\00\\00\\02\\00\\00\\00\\03\\00\\00\\00\\e9\\03\\00\\00)", searcher.Filter);
                return Rows(root, AccountDn, AccountDn.ToUpperInvariant(), ForeignPlaceholder, ForeignPlaceholder.ToUpperInvariant());
            }
            Assert.Equal(5, Searches.Count);
            return Rows(root, ForestGroup, ResourceGroup);
        }

        private Dictionary<string, object[]> GroupValues(string dn)
        {
            var (guid, sid, name) = dn.Equals(RenamedDomainGroup, StringComparison.OrdinalIgnoreCase)
                ? ("40000000-0000-0000-0000-000000000005", firstSid, "duplicate-sid-observation")
                : dn.Equals(DomainGroup, StringComparison.OrdinalIgnoreCase)
                ? ("40000000-0000-0000-0000-000000000001", firstSid, "domain-group")
                : dn.Equals(ForestGroup, StringComparison.OrdinalIgnoreCase)
                    ? ("40000000-0000-0000-0000-000000000002", secondSid, "forest-group")
                    : dn.Equals(ResourceGroup, StringComparison.OrdinalIgnoreCase)
                        ? ("40000000-0000-0000-0000-000000000003", SidCodec.Parse("S-1-5-21-4-5-6-2003"), "resource-group")
                        : ("40000000-0000-0000-0000-000000000004", Array.Empty<byte>(), "no-sid-group");
            var values = new Dictionary<string, object[]>
            {
                ["objectGUID"] = [Guid.Parse(guid).ToByteArray()], ["objectClass"] = ["top", "group"],
                ["sAMAccountName"] = [name], ["name"] = [name],
            };
            if (sid.Length > 0) values["objectSid"] = [sid];
            return values;
        }

        private static SearchResultCollection Rows(DirectoryEntry root, params string[] dns)
            => new(dns.Select(dn =>
            {
                var values = new ResultPropertyCollection();
                values.Set("adspath", [root.PathForDn(dn)]);
                values.Set("distinguishedName", [dn]);
                return new SearchResult(root, values);
            }).ToArray());

        internal void AssertReleased(int materializations)
        {
            Assert.Equal(materializations, Opens);
            Assert.Equal(materializations, Disposals);
            Assert.Equal(materializations * 2, Reads.Count);
            Assert.Equal(materializations, Reads.Count(read => read.DistinguishedName == ""));
            Assert.All(Searches, search => Assert.True(search.Root.IsDisposed));
            Assert.Equal(0, pool.Snapshot.Total);
            Assert.Equal(0, pool.Snapshot.Waiting);
            Assert.Empty(Source.Writes);
        }

        public void Dispose() { Source.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Authorization_group_materialization_deduplicates_SIDs_across_domain_forest_and_resource_queries(bool globalCatalog, bool missingSid)
    {
        using var fixture = new AuthorizationGraphFixture(globalCatalog, missingSid);
        using var user = fixture.Source.Attach(new UserPrincipal(fixture.Source.Context));
        using var results = user.GetAuthorizationGroups();
        var groups = results.ToArray();
        try
        {
            Assert.All(groups, principal => Assert.IsType<GroupPrincipal>(principal));
            Assert.Equal(globalCatalog ? new[] { "domain-group", "forest-group", "resource-group" } : new[] { "domain-group" },
                groups.Select(group => group.SamAccountName));
            Assert.Equal(globalCatalog ? new[] { "S-1-5-21-1-2-3-2001", "S-1-5-21-4-5-6-2002", "S-1-5-21-4-5-6-2003" }
                : new[] { "S-1-5-21-1-2-3-2001" }, groups.Select(group => group.SidValue));
            Assert.Equal(globalCatalog ? 5 : 2, fixture.Searches.Count);
            foreach (var search in fixture.Searches.Where(search => search.Filter.Contains("objectCategory=group")))
                Assert.Contains("(groupType:1.2.840.113556.1.4.803:=2147483648)", search.Filter);
            if (globalCatalog)
            {
                var filter = fixture.Searches[4].Filter;
                Assert.Equal(2, filter.Split("member:1.2.840.113556.1.4.1941:=", StringSplitOptions.None).Length - 1);
                Assert.Contains("CN=item,DC=example,DC=test", filter);
                Assert.Contains("CN=ForeignSecurityPrincipals,DC=other,DC=test", filter);
            }
            fixture.AssertReleased((globalCatalog ? 5 : 1) + (missingSid ? 1 : 0));
        }
        finally { foreach (var group in groups) group.Dispose(); }
        Assert.All(groups, group => Assert.Throws<ObjectDisposedException>(() => _ = group.Context));
        Assert.False(fixture.Source.Entry.IsDisposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Authorization_without_tokens_materializes_domain_security_groups_and_merges_primary_group_filter(bool primaryGroup)
    {
        using var fixture = new AuthorizationGraphFixture(false, false)
            { ReturnTokens = false, DuplicateDomainRow = true };
        if (primaryGroup) fixture.Source.Server["primaryGroupID"] = ["513"];
        using var user = fixture.Source.Attach(new UserPrincipal(fixture.Source.Context));
        using var results = user.GetAuthorizationGroups();
        using var group = Assert.Single(results);

        Assert.IsType<GroupPrincipal>(group);
        Assert.Equal("domain-group", group.SamAccountName);
        Assert.Equal("S-1-5-21-1-2-3-2001", group.SidValue);
        Assert.Equal(2, fixture.Searches.Count);
        var filter = fixture.Searches[1].Filter;
        Assert.Contains("(objectCategory=group)", filter);
        Assert.Contains("(groupType:1.2.840.113556.1.4.803:=2147483648)", filter);
        Assert.Contains("(member:1.2.840.113556.1.4.1941:=CN=item,DC=example,DC=test)", filter);
        if (primaryGroup)
            Assert.Contains("(objectSid=\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\01\\00\\00\\00\\02\\00\\00\\00\\03\\00\\00\\00\\01\\02\\00\\00)", filter);
        else Assert.DoesNotContain("objectSid=", filter);
        fixture.AssertReleased(2);
    }

    [Fact]
    public void Authorization_groups_deduplicate_same_SID_returned_at_distinct_domain_and_GC_DNs()
    {
        using var fixture = new AuthorizationGraphFixture(true, false) { DistinctDnDuplicate = true };
        using var user = fixture.Source.Attach(new UserPrincipal(fixture.Source.Context));
        using var results = user.GetAuthorizationGroups();
        var groups = results.ToArray();
        try
        {
            // Canned domain/GC rows deliberately have different DNs and GUIDs
            // but the same SID. Neither a DN set nor a GUID set satisfies this
            // SID-based result invariant. This does not validate AD uniqueness
            // rules or the behavior of a real rename/replication event.
            Assert.Equal(new[] { AuthorizationGraphFixture.DomainGroup, AuthorizationGraphFixture.ForestGroup,
                AuthorizationGraphFixture.ResourceGroup }, groups.Select(group => group.DistinguishedName));
            Assert.Equal(new[] { "domain-group", "forest-group", "resource-group" },
                groups.Select(group => group.SamAccountName));
            Assert.Equal(new[] { "S-1-5-21-1-2-3-2001", "S-1-5-21-4-5-6-2002", "S-1-5-21-4-5-6-2003" },
                groups.Select(group => group.SidValue));
            Assert.Equal(new Guid("40000000-0000-0000-0000-000000000001"), groups[0].Guid);
            var objectReads = fixture.Reads.Where(read => read.DistinguishedName != "").ToArray();
            Assert.Equal(new[] { AuthorizationGraphFixture.DomainGroup, AuthorizationGraphFixture.RenamedDomainGroup,
                AuthorizationGraphFixture.ForestGroup, AuthorizationGraphFixture.ForestGroup,
                AuthorizationGraphFixture.ResourceGroup }, objectReads.Select(read => read.DistinguishedName));
            Assert.Single(objectReads, read => read.DistinguishedName == AuthorizationGraphFixture.DomainGroup);
            Assert.Single(objectReads, read => read.DistinguishedName == AuthorizationGraphFixture.RenamedDomainGroup);
            Assert.Equal(new[] { new Guid("40000000-0000-0000-0000-000000000001"),
                new Guid("40000000-0000-0000-0000-000000000005") },
                fixture.ReturnedObjectIdentities.Take(2).Select(row => row.Identity));
            Assert.Equal(5, fixture.Searches.Count);
            fixture.AssertReleased(5);
        }
        finally { foreach (var group in groups) group.Dispose(); }
        // Transport/root cleanup is observable here; disposal of the discarded
        // duplicate entry wrapper has no existing direct observation seam.
    }
}
