using System.Reflection;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class V1PrincipalAuditTests
{
    private sealed class ExtendedGroup(PrincipalContext context) : GroupPrincipal(context)
    {
        public void SetExtension(string value) => ExtensionSet("extensionAttribute1", value);
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "OU=scoped,DC=example,DC=test");
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/CN=item,DC=example,DC=test");
        internal readonly Dictionary<string, object[]> Server = new(StringComparer.OrdinalIgnoreCase)
        {
            ["objectGUID"] = [Guid.NewGuid().ToByteArray()],
            ["distinguishedName"] = ["CN=item,DC=example,DC=test"],
            ["objectSid"] = [SecurityDescriptorFixtures.U1],
            ["servicePrincipalName"] = ["HOST/old"],
            ["lockoutTime"] = ["0"],
            ["msDS-User-Account-Control-Computed"] = ["16"],
        };
        internal readonly List<ModifyRequest> Writes = [];
        internal readonly List<string[]> Reads = [];
        internal bool Fail;
        internal Fixture()
        {
            Entry.PropertyReadOverride = (names, _) =>
            {
                Reads.Add(names);
                var properties = new PropertyCollection();
                foreach (var (key, value) in Server)
                    if (names.Length == 0 || names.Contains("*") || names.Contains(key, StringComparer.OrdinalIgnoreCase))
                        properties.ReplaceLoaded(key, value);
                return properties;
            };
            Entry.WriteRequestOverride = request =>
            {
                if (Fail) return ResultCode.UnwillingToPerform;
                var modify = Assert.IsType<ModifyRequest>(request);
                Writes.Add(modify);
                foreach (DirectoryAttributeModification m in modify.Modifications)
                {
                    var values = Server.GetValueOrDefault(m.Name, []).ToList();
                    if (m.Operation == DirectoryAttributeOperation.Replace) values = m.Cast<object>().ToList();
                    else if (m.Operation == DirectoryAttributeOperation.Add) values.AddRange(m.Cast<object>());
                    else if (m.Count == 0) values.Clear();
                    else foreach (var value in m.Cast<object>()) values.Remove(value);
                    Server[m.Name] = values.ToArray();
                }
                return ResultCode.Success;
            };
        }
        internal T Attach<T>(T principal) where T : Principal
        {
            typeof(Principal).GetMethod("AttachExisting", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(principal, [Context, Entry]);
            return principal;
        }
        public void Dispose() { Entry.Dispose(); Context.Dispose(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Authorization_queries_only_security_groups_across_domain_not_context_ou(bool tokens)
    {
        using var f = new Fixture(); using var user = f.Attach(new UserPrincipal(f.Context));
        foreach (var (name, value) in new (string, object)[] {
            ("_defaultNamingContext", "DC=example,DC=test"),
            ("_rootDomainNamingContext", "DC=example,DC=test"), ("_canUseGlobalCatalog", tokens) })
            typeof(PrincipalContext).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(f.Context, value);
        f.Server["primaryGroupID"] = ["513"];
        f.Entry.RefreshCache();
        var queries = new List<(string Path, string Filter)>();
        f.Context.AuthorizationSearchOverride = searcher =>
        {
            if (searcher.SearchScope == AdForLinux.DirectoryServices.SearchScope.Base)
            {
                var props = new ResultPropertyCollection();
                if (tokens) props.Set("tokenGroups", new object[] { SecurityDescriptorFixtures.U1 });
                return new SearchResultCollection(new[] { new SearchResult(searcher.SearchRoot!, props) });
            }
            queries.Add((searcher.SearchRoot!.Path, searcher.Filter));
            return new SearchResultCollection(Array.Empty<SearchResult>());
        };
        using var groups = user.GetAuthorizationGroups();
        Assert.Empty(groups);
        var groupQueries = queries.Where(q => q.Filter.Contains("objectCategory=group")).ToArray();
        Assert.NotEmpty(groupQueries);
        Assert.All(groupQueries, query =>
        {
            Assert.EndsWith("/DC=example,DC=test", query.Path);
            Assert.Contains("(groupType:1.2.840.113556.1.4.803:=2147483648)", query.Filter);
        });
        Assert.Contains(groupQueries, query => query.Filter.Contains("member:1.2.840.113556.1.4.1941"));
        if (!tokens) Assert.Contains("objectSid=", Assert.Single(groupQueries).Filter);
    }

    [Fact(Skip = "Confirmed item 5: same-container cross-DC Save changes Context but leaves the existing entry at the source endpoint.")]
    public void Cross_dc_same_container_save_requires_rebinding_existing_wrapper()
    {
        using var f = new Fixture(); using var user = f.Attach(new UserPrincipal(f.Context));
        using var destination = new PrincipalContext(ContextType.Domain, "other.invalid", "DC=example,DC=test");
        foreach (var context in new[] { f.Context, destination })
            typeof(PrincipalContext).GetField("_defaultNamingContext", BindingFlags.NonPublic | BindingFlags.Instance)!
                .SetValue(context, "DC=example,DC=test");
        var original = user.GetUnderlyingObject();
        user.Save(destination);
        Assert.Same(original, user.GetUnderlyingObject());
        Assert.Same(destination, user.Context);
        Assert.Contains("other.invalid", Assert.IsType<DirectoryEntry>(user.GetUnderlyingObject()).Path);
        Assert.Empty(f.Writes);
    }

    [Fact]
    public void Group_success_clears_extension_intent_before_unrelated_save()
    {
        using var f = new Fixture(); using var group = f.Attach(new ExtendedGroup(f.Context));
        group.SetExtension("first"); group.Save();
        f.Server["extensionAttribute1"] = ["external"];
        f.Entry.RefreshCache(); group.Description = "unrelated"; group.Save();
        Assert.Equal("external", Assert.Single(f.Server["extensionAttribute1"]));
        Assert.DoesNotContain(f.Writes[1].Modifications.Cast<DirectoryAttributeModification>(), m => m.Name == "extensionAttribute1");
    }

    [Fact]
    public void Group_failed_save_retains_extension_intent_across_refresh()
    {
        using var f = new Fixture(); using var group = f.Attach(new ExtendedGroup(f.Context));
        group.SetExtension("retry"); f.Fail = true;
        Assert.ThrowsAny<Exception>(() => group.Save());
        f.Entry.RefreshCache(); f.Fail = false; group.Save();
        Assert.Equal("retry", Assert.Single(f.Server["extensionAttribute1"]));
    }

    [Theory(Skip = "Confirmed item 4: principal SPN intent is lost on entry refresh; safe retry accounting and native failure validation remain open.")]
    [InlineData(false)] [InlineData(true)]
    public void Service_names_preserve_edit_intent_across_entry_refresh(bool remove)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var values = computer.ServicePrincipalNames;
        if (remove) values.Remove("HOST/old"); else values.Add("HOST/new");
        f.Entry.RefreshCache(); computer.Save();
        Assert.Equal(values.ToArray(), f.Server["servicePrincipalName"].Cast<string>().ToArray());
        computer.Description = "unrelated"; computer.Save();
        Assert.DoesNotContain(f.Writes.Last().Modifications.Cast<DirectoryAttributeModification>(), m => m.Name == "servicePrincipalName");
    }

    [Theory(Skip = "Confirmed item 4: principal SPN intent is lost on entry refresh; safe retry accounting and native failure validation remain open.")]
    [InlineData(false)] [InlineData(true)]
    public void Service_names_retry_preserves_unrelated_refreshed_values(bool remove)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames;
        if (remove) names.Remove("HOST/old"); else names.Add("HOST/new");
        f.Fail = true; Assert.ThrowsAny<Exception>(() => computer.Save());
        f.Server["servicePrincipalName"] = ["HOST/old", "HOST/external"];
        f.Entry.RefreshCache(); f.Fail = false; computer.Save();
        Assert.Contains("HOST/external", f.Server["servicePrincipalName"]);
        Assert.Equal(!remove, f.Server["servicePrincipalName"].Contains("HOST/old"));
        Assert.Equal(!remove, f.Server["servicePrincipalName"].Contains("HOST/new"));
    }

    [Theory]
    [InlineData(0, false)] [InlineData(16, true)] [InlineData(8388608, false)]
    public void Lockout_uses_fresh_server_computed_effective_state(int computed, bool locked)
    {
        using var f = new Fixture(); using var user = f.Attach(new UserPrincipal(f.Context));
        f.Server["lockoutTime"] = [DateTime.UtcNow.ToFileTimeUtc().ToString()];
        f.Entry.Properties["description"].Value = "pending";
        f.Server["msDS-User-Account-Control-Computed"] = [computed.ToString()];
        Assert.Equal(locked, user.IsAccountLockedOut());
        f.Server["msDS-User-Account-Control-Computed"] = ["0"];
        Assert.False(user.IsAccountLockedOut());
        user.Save();
        Assert.Equal("pending", Assert.Single(f.Server["description"]));
        Assert.Contains(f.Reads, names => names.Contains("msDS-User-Account-Control-Computed") && names.Contains("lockoutTime"));
    }
}
