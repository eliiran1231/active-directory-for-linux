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
