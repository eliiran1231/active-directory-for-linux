using AdForLinux.DirectoryServices;
using Xunit;

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
    public void Unsupported_adsi_search_modes_fail_explicitly()
    {
        using var root = new DirectoryEntry();
        using var searcher = new DirectorySearcher(root)
        {
            AttributeScopeQuery = "member",
        };

        Assert.Throws<PlatformNotSupportedException>(() => searcher.FindOne());
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
}
