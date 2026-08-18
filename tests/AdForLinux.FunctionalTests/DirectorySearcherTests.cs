using AdForLinux.DirectoryServices;
using System.ComponentModel;
using Xunit;
using ProtocolDirectoryOperationException = System.DirectoryServices.Protocols.DirectoryOperationException;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 4: search with DirectorySearcher against smblds.
/// </summary>
public class DirectorySearcherTests
{
    private static DirectoryEntry Root() =>
        new(TestSettings.PathFor(TestSettings.BaseDn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    [Fact]
    public void Searcher_participates_in_component_lifecycle()
    {
        var searcher = new TrackingDirectorySearcher();
        Component component = searcher;
        IComponent iComponent = searcher;
        var disposedCount = 0;
        component.Disposed += (_, _) => disposedCount++;

        using var container = new Container();
        container.Add(iComponent, "searcher");

        Assert.Same(searcher, component);
        Assert.Same(searcher, iComponent);
        Assert.Same(container, searcher.Site!.Container);
        Assert.Equal("searcher", searcher.Site.Name);
        Assert.False(searcher.Site.DesignMode);

        container.Dispose();

        Assert.Null(searcher.Site);
        Assert.Equal(1, disposedCount);
        Assert.Equal(1, searcher.DisposeCallCount);
    }

    [Fact]
    public void Disposing_searcher_does_not_dispose_caller_owned_search_root()
    {
        var root = new TrackingDirectoryEntry();
        try
        {
            using (Component searcher = new DirectorySearcher(root))
            {
            }

            Assert.Equal(0, root.DisposeCallCount);
        }
        finally
        {
            root.Dispose();
        }

        Assert.Equal(1, root.DisposeCallCount);
    }

    [Fact]
    public void Constructor_and_option_surface_matches_the_portable_api()
    {
        using var searcher = new DirectorySearcher(
            "(objectClass=person)",
            new[] { "cn", "mail" },
            SearchScope.OneLevel)
        {
            Asynchronous = true,
            CacheResults = false,
            ClientTimeout = TimeSpan.FromSeconds(5),
            DerefAlias = DereferenceAlias.Always,
            ExtendedDN = ExtendedDN.Standard,
            PropertyNamesOnly = true,
            ReferralChasing = ReferralChasingOption.All,
            ServerPageTimeLimit = TimeSpan.FromSeconds(3),
            ServerTimeLimit = TimeSpan.FromSeconds(4),
            Sort = new SortOption("cn", SortDirection.Descending),
        };

        Assert.Equal(SearchScope.OneLevel, searcher.SearchScope);
        Assert.Equal(new[] { "cn", "mail" }, searcher.PropertiesToLoad.Cast<string>());
        Assert.True(searcher.Asynchronous);
        Assert.True(searcher.PropertyNamesOnly);
        Assert.Equal("cn", searcher.Sort!.PropertyName);
        Assert.Equal(SortDirection.Descending, searcher.Sort.Direction);
    }

    [Fact]
    public void Filter_only_constructor_and_defaults_match_microsoft()
    {
        using var searcher = new DirectorySearcher("(objectClass=person)");

        Assert.Equal("(objectClass=person)", searcher.Filter);
        Assert.Null(searcher.SearchRoot);
        Assert.Equal(SearchScope.Subtree, searcher.SearchScope);
        Assert.Equal(TimeSpan.FromSeconds(-1), searcher.ClientTimeout);
        Assert.Equal(TimeSpan.FromSeconds(-1), searcher.ServerPageTimeLimit);
        Assert.Equal(TimeSpan.FromSeconds(-1), searcher.ServerTimeLimit);
        Assert.NotNull(searcher.Sort);
        Assert.Null(searcher.Sort.PropertyName);
        Assert.Equal(SortDirection.Ascending, searcher.Sort.Direction);
    }

    [Fact]
    public void Invalid_limits_and_null_sort_fail_like_microsoft()
    {
        using var searcher = new DirectorySearcher();

        Assert.Throws<ArgumentException>(() => searcher.PageSize = -1);
        Assert.Throws<ArgumentException>(() => searcher.SizeLimit = -1);
        Assert.Throws<ArgumentNullException>(() => searcher.Sort = null!);
    }

    [Fact]
    public void Constructors_allow_null_properties_to_load_like_microsoft()
    {
        using var filterOnly = new DirectorySearcher("(objectClass=person)", null);
        using var filterAndScope = new DirectorySearcher("(objectClass=person)", null, SearchScope.OneLevel);
        using var rooted = new DirectorySearcher(null, "(objectClass=person)", null);
        using var rootedAndScoped = new DirectorySearcher(
            null, "(objectClass=person)", null, SearchScope.OneLevel);

        Assert.Empty(filterOnly.PropertiesToLoad.Cast<string>());
        Assert.Empty(filterAndScope.PropertiesToLoad.Cast<string>());
        Assert.Empty(rooted.PropertiesToLoad.Cast<string>());
        Assert.Empty(rootedAndScoped.PropertiesToLoad.Cast<string>());
    }

    [Fact]
    public void Page_size_and_directory_synchronization_are_mutually_exclusive()
    {
        using var pageFirst = new DirectorySearcher { PageSize = 100 };
        Assert.Throws<ArgumentException>(
            () => pageFirst.DirectorySynchronization = new DirectorySynchronization());
        Assert.Null(pageFirst.DirectorySynchronization);

        using var synchronizationFirst = new DirectorySearcher
        {
            DirectorySynchronization = new DirectorySynchronization(),
        };
        Assert.Throws<ArgumentException>(() => synchronizationFirst.PageSize = 100);
        Assert.Equal(0, synchronizationFirst.PageSize);

        synchronizationFirst.PageSize = 0;
        synchronizationFirst.DirectorySynchronization = null;
        synchronizationFirst.PageSize = 100;
        Assert.Equal(100, synchronizationFirst.PageSize);
    }

    [Fact]
    public void Virtual_list_view_enforces_cache_results_semantics()
    {
        using var implicitCaching = new DirectorySearcher();
        implicitCaching.VirtualListView = new DirectoryVirtualListView();
        Assert.False(implicitCaching.CacheResults);

        using var explicitCaching = new DirectorySearcher { CacheResults = true };
        Assert.Throws<ArgumentException>(
            () => explicitCaching.VirtualListView = new DirectoryVirtualListView());
        Assert.Null(explicitCaching.VirtualListView);

        using var viewFirst = new DirectorySearcher
        {
            VirtualListView = new DirectoryVirtualListView(),
        };
        Assert.Throws<ArgumentException>(() => viewFirst.CacheResults = true);
        Assert.False(viewFirst.CacheResults);

        using var cachingDisabled = new DirectorySearcher { CacheResults = false };
        cachingDisabled.VirtualListView = new DirectoryVirtualListView();
        Assert.NotNull(cachingDisabled.VirtualListView);
    }

    [Fact]
    public void Option_setters_validate_enum_and_timeout_ranges()
    {
        using var searcher = new DirectorySearcher();

        Assert.Throws<InvalidEnumArgumentException>(
            () => searcher.DerefAlias = (DereferenceAlias)int.MaxValue);
        Assert.Throws<InvalidEnumArgumentException>(
            () => searcher.ReferralChasing = (ReferralChasingOption)int.MaxValue);

        var maximum = TimeSpan.FromSeconds(int.MaxValue);
        var tooLarge = maximum.Add(TimeSpan.FromSeconds(1));
        searcher.ClientTimeout = maximum;
        searcher.ServerPageTimeLimit = maximum;
        searcher.ServerTimeLimit = maximum;

        Assert.Throws<ArgumentException>(() => searcher.ClientTimeout = tooLarge);
        Assert.Throws<ArgumentException>(() => searcher.ServerPageTimeLimit = tooLarge);
        Assert.Throws<ArgumentException>(() => searcher.ServerTimeLimit = tooLarge);
    }

    [Fact]
    public void Attribute_scope_query_requires_base_scope()
    {
        using var searcher = new DirectorySearcher();

        searcher.AttributeScopeQuery = "member";
        Assert.Equal(SearchScope.Base, searcher.SearchScope);

        searcher.AttributeScopeQuery = null;
        searcher.SearchScope = SearchScope.Subtree;

        Assert.Throws<ArgumentException>(() => searcher.AttributeScopeQuery = "member");
    }

    [Fact]
    public void Directory_synchronization_and_virtual_list_view_preserve_request_state()
    {
        var cookie = new byte[] { 1, 2, 3 };
        var synchronization = new DirectorySynchronization(
            DirectorySynchronizationOptions.ObjectSecurity | DirectorySynchronizationOptions.ParentsFirst,
            cookie);
        var copiedSynchronization = new DirectorySynchronization(synchronization);
        var view = new DirectoryVirtualListView(2, 3, 10)
        {
            ApproximateTotal = 100,
        };

        cookie[0] = 99;
        Assert.Equal(new byte[] { 1, 2, 3 }, synchronization.GetDirectorySynchronizationCookie());
        Assert.Equal(synchronization.Option, copiedSynchronization.Option);
        Assert.Equal(new byte[] { 1, 2, 3 }, copiedSynchronization.GetDirectorySynchronizationCookie());

        using var searcher = new DirectorySearcher
        {
            DirectorySynchronization = synchronization,
            VirtualListView = view,
            Tombstone = true,
            SecurityMasks = SecurityMasks.Owner | SecurityMasks.Dacl,
        };

        Assert.Same(synchronization, searcher.DirectorySynchronization);
        Assert.Same(view, searcher.VirtualListView);
        Assert.True(searcher.Tombstone);
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Dacl, searcher.SecurityMasks);
    }

    [Fact]
    public void FindOne_locates_a_user_by_sam_account_name()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root)
        {
            Filter = "(&(objectClass=user)(sAMAccountName=Administrator))",
        };
        searcher.PropertiesToLoad.Add("sAMAccountName");
        searcher.PropertiesToLoad.Add("distinguishedName");

        var result = searcher.FindOne();

        Assert.NotNull(result);
        Assert.Equal("Administrator", result!.Properties["sAMAccountName"][0].ToString());
    }

    [Fact]
    public void FindOne_returns_null_when_nothing_matches()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=no-such-user-xyz)");

        Assert.Null(searcher.FindOne());
    }

    [Fact]
    public void Properties_contains_reports_loaded_attributes()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=Administrator)");
        searcher.PropertiesToLoad.Add("sAMAccountName");

        var result = searcher.FindOne();

        Assert.NotNull(result);
        Assert.True(result!.Properties.Contains("sAMAccountName"));
        Assert.False(result.Properties.Contains("givenName")); // not requested
    }

    [Fact]
    public void GetDirectoryEntry_reopens_the_matched_object()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=Administrator)");

        var result = searcher.FindOne();
        Assert.NotNull(result);

        using var entry = result!.GetDirectoryEntry();
        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
    }

    [Fact]
    public void FindAll_with_paging_returns_many_objects()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(objectClass=*)")
        {
            PageSize = 100,
        };

        var all = searcher.FindAll();

        // A provisioned AD has well over 100 objects in its subtree.
        Assert.True(all.Count > 100, $"expected many objects, got {all.Count}");
    }

    [Fact]
    public void FindAll_reports_the_explicitly_loaded_properties()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=Administrator)");
        searcher.PropertiesToLoad.Add("sAMAccountName");
        searcher.PropertiesToLoad.Add("distinguishedName");

        using var results = searcher.FindAll();

        Assert.Equal(new[] { "sAMAccountName", "distinguishedName" }, results.PropertiesLoaded);
        Assert.Equal(new[] { "sAMAccountName", "distinguishedName" }, searcher.PropertiesToLoad.Cast<string>());
        Assert.Equal(IntPtr.Zero, results.Handle);
    }

    [Fact]
    public void FindAll_with_cache_results_false_is_forward_only()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=Administrator)")
        {
            CacheResults = false,
        };
        using var results = searcher.FindAll();

        Assert.Single(results.Cast<SearchResult>());
        Assert.Empty(results.Cast<SearchResult>());
    }

    [Fact]
    public void FindAll_with_cache_results_false_can_be_explicitly_materialized()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=Administrator)")
        {
            CacheResults = false,
        };
        using var results = searcher.FindAll();

        _ = results.Count;
        Assert.Single(results.Cast<SearchResult>());
        Assert.Single(results.Cast<SearchResult>());
    }

    [Fact]
    public void FindAll_with_cache_results_false_materializes_the_unconsumed_tail()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(
            root, "(|(sAMAccountName=Administrator)(sAMAccountName=Guest))")
        {
            CacheResults = false,
        };
        using var results = searcher.FindAll();
        using var enumerator = results.Cast<SearchResult>().GetEnumerator();

        Assert.True(enumerator.MoveNext());
        var consumed = enumerator.Current;

        Assert.True(results.Count == 1, $"expected one unconsumed result, got {results.Count}");
        var remaining = results[0];
        Assert.NotSame(consumed, remaining);
        Assert.True(results.Contains(remaining));
        Assert.Equal(0, results.IndexOf(remaining));

        var copied = new SearchResult[1];
        results.CopyTo(copied, 0);
        Assert.Same(remaining, copied[0]);

        var nonGenericCopy = new SearchResult[1];
        ((System.Collections.ICollection)results).CopyTo(nonGenericCopy, 0);
        Assert.Same(remaining, nonGenericCopy[0]);
        Assert.False(enumerator.MoveNext());
        Assert.Same(remaining, Assert.Single(results.Cast<SearchResult>()));
    }

    [Fact]
    public void FindAll_asynchronous_searches_are_repeatable_when_cached()
    {
        using var root = Root();
        using var searcher = new DirectorySearcher(
            root, "(|(objectClass=user)(objectClass=group))")
        {
            Asynchronous = true,
        };
        using var results = searcher.FindAll();

        var firstEnumeration = results.Select(result => result.Path).ToArray();
        var secondEnumeration = results.Select(result => result.Path).ToArray();

        Assert.NotEmpty(firstEnumeration);
        Assert.Equal(firstEnumeration, secondEnumeration);
    }

    [Fact]
    public void Directory_entries_find_and_schema_filter_work_for_protocol_children()
    {
        var name = $"adfl-c-{Guid.NewGuid():N}"[..18];
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using var users = new DirectoryEntry(
                TestSettings.PathFor(TestDirectory.UsersContainer), TestSettings.BindDn, TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            var children = users.Children;
            children.SchemaFilter.Add("user");

            using var found = children.Find($"CN={name}", "user");

            Assert.Equal(dn, found.DistinguishedName, ignoreCase: true);
            Assert.Equal(name, found.Properties["sAMAccountName"].Value);
            Assert.Throws<InvalidOperationException>(() => children.Find($"CN={name}", "person"));
            Assert.Contains(children, child =>
                string.Equals(child.DistinguishedName, dn, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Attribute_scope_query_filters_and_loads_referenced_objects()
    {
        var userName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var nestedName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var groupName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var userDn = TestDirectory.Create(userName, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = userName,
        });
        var nestedDn = TestDirectory.Create(nestedName, "group", new Dictionary<string, string>
        {
            ["sAMAccountName"] = nestedName,
        });
        var groupDn = TestDirectory.Create(groupName, "group", new Dictionary<string, string>
        {
            ["sAMAccountName"] = groupName,
            ["member"] = userDn,
        });

        try
        {
            using (var group = new DirectoryEntry(
                       TestSettings.PathFor(groupDn), TestSettings.BindDn, TestSettings.BindPassword,
                       AuthenticationTypes.SecureSocketsLayer))
            {
                group.Properties["member"].Add(nestedDn);
                group.CommitChanges();
            }

            using var root = new DirectoryEntry(
                TestSettings.PathFor(groupDn), TestSettings.BindDn, TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            using var searcher = new DirectorySearcher(root)
            {
                AttributeScopeQuery = "member",
                Filter = "(objectClass=user)",
            };
            searcher.PropertiesToLoad.Add("sAMAccountName");

            var first = searcher.FindOne();
            var result = Assert.Single(searcher.FindAll());

            Assert.NotNull(first);
            Assert.Equal(userName, first!.Properties["sAMAccountName"][0]);
            Assert.Equal(userName, result.Properties["sAMAccountName"][0]);
            Assert.False(result.Properties.Contains("description"));
        }
        finally
        {
            TestDirectory.Delete(groupDn);
            TestDirectory.Delete(nestedDn);
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Attribute_scope_query_applies_size_limit_across_references()
    {
        var firstName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var secondName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var groupName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var firstDn = TestDirectory.Create(firstName, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = firstName,
        });
        var secondDn = TestDirectory.Create(secondName, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = secondName,
        });
        var groupDn = TestDirectory.Create(groupName, "group", new Dictionary<string, string>
        {
            ["sAMAccountName"] = groupName,
            ["member"] = firstDn,
        });

        try
        {
            using (var group = new DirectoryEntry(
                       TestSettings.PathFor(groupDn), TestSettings.BindDn, TestSettings.BindPassword,
                       AuthenticationTypes.SecureSocketsLayer))
            {
                group.Properties["member"].Add(secondDn);
                group.CommitChanges();
            }

            using var root = new DirectoryEntry(
                TestSettings.PathFor(groupDn), TestSettings.BindDn, TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            using var searcher = new DirectorySearcher(root)
            {
                AttributeScopeQuery = "member",
                Filter = "(objectClass=user)",
                SizeLimit = 1,
            };

            Assert.Single(searcher.FindAll());
        }
        finally
        {
            TestDirectory.Delete(groupDn);
            TestDirectory.Delete(secondDn);
            TestDirectory.Delete(firstDn);
        }
    }

    [Fact]
    public void Attribute_scope_query_rejects_an_unset_non_dn_attribute()
    {
        var groupName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var groupDn = TestDirectory.Create(groupName, "group", new Dictionary<string, string>
        {
            ["sAMAccountName"] = groupName,
        });

        try
        {
            AssertInvalidAttributeScopeQuery(groupDn, "description");
        }
        finally
        {
            TestDirectory.Delete(groupDn);
        }
    }

    [Fact]
    public void Attribute_scope_query_rejects_non_dn_text_that_is_an_existing_dn()
    {
        var userName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var groupName = $"adfl-a-{Guid.NewGuid():N}"[..18];
        var userDn = TestDirectory.Create(userName, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = userName,
        });
        var groupDn = TestDirectory.Create(groupName, "group", new Dictionary<string, string>
        {
            ["sAMAccountName"] = groupName,
            ["description"] = userDn,
        });

        try
        {
            AssertInvalidAttributeScopeQuery(groupDn, "description");
        }
        finally
        {
            TestDirectory.Delete(groupDn);
            TestDirectory.Delete(userDn);
        }
    }

    private static void AssertInvalidAttributeScopeQuery(string rootDn, string attributeName)
    {
        using var root = new DirectoryEntry(
            TestSettings.PathFor(rootDn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);
        using var searcher = new DirectorySearcher(root)
        {
            AttributeScopeQuery = attributeName,
        };

        var error = Assert.Throws<DirectoryServicesCOMException>(() => searcher.FindAll());
        Assert.Contains("InvalidAttributeSyntax (21)", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class TrackingDirectorySearcher : DirectorySearcher
    {
        public int DisposeCallCount { get; private set; }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeCallCount++;
            }

            base.Dispose(disposing);
        }
    }

    private sealed class TrackingDirectoryEntry : DirectoryEntry
    {
        public int DisposeCallCount { get; private set; }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeCallCount++;
            }

            base.Dispose(disposing);
        }
    }
}
