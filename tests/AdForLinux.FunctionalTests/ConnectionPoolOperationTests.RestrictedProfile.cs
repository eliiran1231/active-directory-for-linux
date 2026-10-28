using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private static RestrictedKerberosProfile RestrictedRecipe() => new(
        Path.GetFullPath("/nonexistent-adfl-bundle/version-1"), "/nonexistent-adfl-cache/client", "EXAMPLE.INVALID",
        "directory.invalid", 389, "kdc.invalid");

    [Fact]
    public void Explicit_restricted_selection_is_inert_preserved_and_never_ambient_fallback()
    {
        var profile = RestrictedRecipe(); // nonexistent paths: no file reads or native load
        using var entry = profile.CreateDirectoryEntry("DC=example,DC=invalid");
        Assert.Same(profile, entry.BuildOptions().RestrictedKerberos);
        Assert.Equal(ReferralChasingOption.None, entry.Options.Referral);
        Assert.False(LdapConnectionProvider.CanReuse(entry.BuildOptions()));
        using var copied = entry.CreateEntryForDn("CN=copy,DC=example,DC=invalid");
        using var boundCopy = entry.CopyBinding(entry.CaptureBindingAuthority());
        using var child = DirectoryEntry.NewChild(entry, "CN=child", "container");
        foreach (var derived in new[] { copied, boundCopy, child })
            Assert.Same(profile, derived.BuildOptions().Clone().RestrictedKerberos);
        entry.Close();
        entry.Path = "LDAP://directory.invalid:389/CN=other,DC=example,DC=invalid";
        Assert.Same(profile, entry.BuildOptions().RestrictedKerberos);
        Assert.Equal(ReferralChasingOption.None, entry.Options.Referral);
        Assert.Throws<InvalidOperationException>(() => entry.RefreshCache());
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionFactory.Create(entry.BuildOptions()));
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionProvider.AcquireValidation(entry.BuildOptions()));
    }

    [Fact]
    public void Restricted_entry_refuses_recipe_changes_without_losing_selection()
    {
        var profile = RestrictedRecipe(); using var entry = profile.CreateDirectoryEntry("");
        var path = entry.Path;
        Assert.Throws<InvalidOperationException>(() => entry.Path = "LDAP://other.invalid/");
        Assert.Throws<InvalidOperationException>(() => entry.Username = "alternate");
        Assert.Throws<InvalidOperationException>(() => entry.Password = "synthetic-unused");
        Assert.Throws<InvalidOperationException>(() => entry.AuthenticationType = AuthenticationTypes.None);
        Assert.Equal(path, entry.Path); Assert.Same(profile, entry.BuildOptions().RestrictedKerberos);
        entry.Options.Referral = ReferralChasingOption.All;
        Assert.Throws<PlatformNotSupportedException>(() => entry.RefreshCache());
        Assert.Equal(ReferralChasingOption.All, entry.Options.Referral); // request not silently rewritten
    }

    [Fact]
    public void Restricted_context_preserves_profile_and_refuses_alternate_routes_before_io()
    {
        var profile = RestrictedRecipe();
        using var context = RestrictedKerberosContext.Create(profile, "DC=example,DC=invalid");
        Assert.Same(profile, context.BuildOptions().RestrictedKerberos);
        using var entry = context.CreateDirectoryEntry("CN=one,DC=example,DC=invalid");
        Assert.Same(profile, entry.BuildOptions().RestrictedKerberos);
        Assert.Throws<PlatformNotSupportedException>(() => context.ValidateCredentials("alternate", "synthetic-unused"));
        Assert.Throws<PlatformNotSupportedException>(() => context.ValidateCredentials("alternate", "synthetic-unused", ContextOptions.SimpleBind));
        Assert.Throws<PlatformNotSupportedException>(() => { _ = context.CanUseGlobalCatalog; });
        Assert.Throws<PlatformNotSupportedException>(() => context.GetForeignDomainContext("other.invalid"));
        Assert.Throws<InvalidOperationException>(() => { _ = context.ConnectedServer; });
        using var gc = context.CreateGlobalCatalogEntry("");
        Assert.Throws<InvalidOperationException>(() => gc.BuildOptions());
        using var stock = new PrincipalContext(ContextType.Domain, "directory.invalid");
        Assert.Null(stock.BuildOptions().RestrictedKerberos);
        using var stockEntry = new DirectoryEntry("LDAP://directory.invalid/");
        Assert.Null(stockEntry.BuildOptions().RestrictedKerberos);
        Assert.Equal(ReferralChasingOption.External, stockEntry.Options.Referral);
    }

    [Fact]
    public void Restricted_selection_is_part_of_authority_and_cannot_be_replaced_by_save()
    {
        var profile = RestrictedRecipe();
        using var selected = profile.CreateDirectoryEntry("DC=example,DC=invalid");
        using var same = profile.CreateDirectoryEntry("OU=other,DC=example,DC=invalid");
        using var different = RestrictedRecipe().CreateDirectoryEntry("OU=other,DC=example,DC=invalid");
        using var stock = new DirectoryEntry(selected.Path, null, null,
            AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing);
        Assert.True(selected.HasSameConnectionContext(same));
        Assert.False(selected.HasSameConnectionContext(different));
        Assert.False(selected.HasSameConnectionContext(stock));
        Assert.False(stock.HasSameConnectionContext(selected));
        using var selectedContext = RestrictedKerberosContext.Create(profile, "DC=example,DC=invalid");
        using var stockContext = new PrincipalContext(ContextType.Domain, "directory.invalid", "DC=example,DC=invalid");
        using var selectedPrincipal = new UserPrincipal(selectedContext);
        using var stockPrincipal = new UserPrincipal(stockContext);
        Assert.Throws<InvalidOperationException>(() => selectedPrincipal.Save(stockContext));
        Assert.Throws<InvalidOperationException>(() => stockPrincipal.Save(selectedContext));
        Assert.Same(selectedContext, selectedPrincipal.Context);
        Assert.Same(stockContext, stockPrincipal.Context);
    }

    [Theory]
    [InlineData("relative", "/cache", "EXAMPLE.INVALID", "directory.invalid", 389, "kdc.invalid", 88)]
    [InlineData("/bundle", "relative", "EXAMPLE.INVALID", "directory.invalid", 389, "kdc.invalid", 88)]
    [InlineData("/bundle", "/cache", "REALM\ninclude x", "directory.invalid", 389, "kdc.invalid", 88)]
    [InlineData("/bundle", "/cache", "EXAMPLE.INVALID", "directory.invalid", 636, "kdc.invalid", 88)]
    [InlineData("/bundle", "/cache", "EXAMPLE.INVALID", "directory.invalid", 389, "bad:88", 88)]
    public void Restricted_profile_rejects_unsupported_syntax_without_access(string bundle, string cache, string realm,
        string host, int port, string kdc, int kdcPort)
        => Assert.ThrowsAny<ArgumentException>(() => new RestrictedKerberosProfile(bundle, cache, realm, host, port, kdc, kdcPort));
}
