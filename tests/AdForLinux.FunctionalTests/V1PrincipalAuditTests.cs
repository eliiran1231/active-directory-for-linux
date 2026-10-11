using System.Reflection;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class ExtendedGroup(PrincipalContext context) : GroupPrincipal(context)
    {
        public void SetExtension(string value) => ExtensionSet("extensionAttribute1", value);
    }
    private sealed class PostSaveComputer(PrincipalContext context) : ComputerPrincipal(context)
    {
        internal bool FailAfterCommit;
        private protected override void OnAfterSave()
        {
            if (FailAfterCommit) throw new InvalidOperationException("post-save failure");
            base.OnAfterSave();
        }
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
        internal int Attempts;
        internal Action? BeforeWrite;
        internal Action? AfterWrite;
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
                Attempts++;
                if (Fail) return ResultCode.UnwillingToPerform;
                BeforeWrite?.Invoke();
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
                AfterWrite?.Invoke();
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

    [Fact(Skip = "Item 5 execution remains gated: verified cross-DC authority rebinding and retained-wrapper lifecycle are not implemented.")]
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

    [Theory]
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

    [Theory]
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

    [Fact]
    public void Lockout_after_entry_close_keeps_unrelated_attributes_available()
    {
        using var f = new Fixture(); using var user = f.Attach(new UserPrincipal(f.Context));
        f.Server["displayName"] = ["retained"];
        f.Entry.Close();
        Assert.True(user.IsAccountLockedOut());
        Assert.NotNull(user.Sid);
        Assert.Equal("retained", f.Entry.Properties["displayName"].Value);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Rejected_service_name_write_can_be_cancelled_without_refresh(bool remove)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames;
        if (remove) names.Remove("HOST/old"); else names.Add("HOST/new");
        f.Fail = true; Assert.ThrowsAny<Exception>(() => computer.Save());
        if (remove) names.Add("HOST/old"); else names.Remove("HOST/new");
        f.Fail = false; computer.Save();
        Assert.Equal(new object[] { "HOST/old" }, f.Server["servicePrincipalName"]);
    }

    [Theory]
    [InlineData("clear")] [InlineData("replace")] [InlineData("duplicates")]
    public void Service_name_deltas_preserve_external_and_direct_entry_edits(string edit)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames;
        if (edit == "clear") names.Clear();
        else if (edit == "replace") names[0] = "HOST/new";
        else { names.Add("HOST/new"); names.Add("HOST/new"); }
        f.Server["servicePrincipalName"] = ["HOST/old", "HOST/external"];
        f.Entry.RefreshCache();
        f.Entry.Properties["servicePrincipalName"].Add("HOST/direct");
        computer.Save();
        Assert.Contains("HOST/external", f.Server["servicePrincipalName"]);
        Assert.Contains("HOST/direct", f.Server["servicePrincipalName"]);
        Assert.Equal(edit == "duplicates", f.Server["servicePrincipalName"].Contains("HOST/old"));
        Assert.Equal(edit == "clear" ? 0 : 1, f.Server["servicePrincipalName"].Count(v => Equals(v, "HOST/new")));
        f.Server["servicePrincipalName"] = ["HOST/later"];
        computer.Description = "unrelated"; computer.Save();
        Assert.Equal(new object[] { "HOST/later" }, f.Server["servicePrincipalName"]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Service_name_acknowledgement_preserves_edits_made_during_request(bool remove)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames;
        if (remove) names.Remove("HOST/old"); else names.Add("HOST/new");
        f.BeforeWrite = () => { f.BeforeWrite = null; if (remove) names.Add("HOST/old"); else names.Remove("HOST/new"); };
        computer.Save(); computer.Save();
        Assert.Equal(new object[] { "HOST/old" }, f.Server["servicePrincipalName"]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Uncertain_service_name_write_requires_readback_and_does_not_replay(bool accepted)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/new");
        if (accepted) f.AfterWrite = () => throw new TimeoutException();
        else f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save());
        names.Add("HOST/later");
        Assert.Throws<InvalidOperationException>(() => computer.Save()); Assert.Equal(1, f.Attempts);
        f.BeforeWrite = null; f.AfterWrite = null;
        f.Entry.RefreshCache(new[] { "servicePrincipalName" });
        if (!accepted)
        {
            Assert.Throws<InvalidOperationException>(() => computer.Save());
            Assert.Equal(1, f.Attempts); return;
        }
        computer.Save();
        Assert.Equal(new object[] { "HOST/old", "HOST/new", "HOST/later" }, f.Server["servicePrincipalName"]);
        var final = f.Writes.Last().Modifications.Cast<DirectoryAttributeModification>().ToArray();
        Assert.Single(final); Assert.Equal("HOST/later", final[0][0]);
    }

    [Fact]
    public void Acknowledged_service_names_are_not_replayed_after_post_save_failure()
    {
        using var f = new Fixture(); using var computer = f.Attach(new PostSaveComputer(f.Context));
        computer.ServicePrincipalNames.Add("HOST/new"); computer.FailAfterCommit = true;
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        f.Server["servicePrincipalName"] = ["HOST/external"];
        computer.FailAfterCommit = false; computer.Description = "later"; computer.Save();
        Assert.Equal(new object[] { "HOST/external" }, f.Server["servicePrincipalName"]);
        Assert.DoesNotContain(f.Writes.Last().Modifications.Cast<DirectoryAttributeModification>(), m => m.Name == "servicePrincipalName");
    }

    [Fact]
    public void Service_name_cache_refresh_during_preparation_refuses_before_send()
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Add("HOST/new");
        f.Entry.Close();
        var read = f.Entry.PropertyReadOverride!;
        f.Entry.PropertyReadOverride = (names, full) =>
        {
            f.Entry.PropertyReadOverride = read;
            f.Entry.RefreshCache(new[] { "servicePrincipalName" });
            return read(names, full);
        };
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(0, f.Attempts);
        computer.Save(); Assert.Contains("HOST/new", f.Server["servicePrincipalName"]);
    }

    [Fact]
    public void Partial_readback_cannot_acknowledge_uncertain_service_names()
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Add("HOST/new"); computer.Description = "changed";
        f.AfterWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save());
        f.AfterWrite = null;
        f.Entry.RefreshCache(new[] { "description" });
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(1, f.Attempts);
        f.Entry.RefreshCache(new[] { "description", "servicePrincipalName" });
        computer.Description = "next"; computer.Save();
        Assert.DoesNotContain(f.Writes.Last().Modifications.Cast<DirectoryAttributeModification>(), m => m.Name == "servicePrincipalName");
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public void Uncertain_service_names_require_proof_when_entry_ledger_already_has_the_same_edit(bool accepted, bool remove)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        if (remove)
        {
            computer.ServicePrincipalNames.Remove("HOST/old");
            f.Entry.Properties["servicePrincipalName"].Remove("HOST/old");
        }
        else
        {
            computer.ServicePrincipalNames.Add("HOST/new");
            f.Entry.Properties["servicePrincipalName"].Add("HOST/new");
        }
        if (accepted) f.AfterWrite = () => throw new TimeoutException();
        else f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save());
        f.AfterWrite = null; f.BeforeWrite = null;
        f.Entry.RefreshCache(new[] { "servicePrincipalName" });
        if (accepted) computer.Save();
        else Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(1, f.Attempts);
        Assert.Equal(!remove, computer.ServicePrincipalNames.Contains(remove ? "HOST/old" : "HOST/new"));
        Assert.Equal(remove ? !accepted : accepted,
            f.Server["servicePrincipalName"].Contains(remove ? "HOST/old" : "HOST/new"));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Guarded_service_name_delete_requires_explicit_readback_even_when_request_only_changes_description(bool matches)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Remove("HOST/old");
        f.Server["servicePrincipalName"] = [];
        f.Entry.RefreshCache(new[] { "servicePrincipalName" });
        computer.Description = "changed";
        f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save());
        f.BeforeWrite = null;
        f.Server["servicePrincipalName"] = matches ? [] : ["HOST/old"];
        f.Entry.RefreshCache(new[] { "description" });
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(1, f.Attempts);
        f.Entry.RefreshCache(new[] { "description", "servicePrincipalName" });
        if (matches) computer.Save();
        else Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(matches ? 2 : 1, f.Attempts);
        Assert.Empty(computer.ServicePrincipalNames);
        if (matches) Assert.DoesNotContain(f.Writes.Last().Modifications.Cast<DirectoryAttributeModification>(),
            modification => modification.Name == "servicePrincipalName");
    }
}
