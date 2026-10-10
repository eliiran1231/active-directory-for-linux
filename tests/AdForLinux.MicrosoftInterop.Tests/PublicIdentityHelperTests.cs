using System.Reflection;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using AdForLinux.Examples;
using Xunit;
using D = AdForLinux.DirectoryServices;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using P = AdForLinux.Security.Principal;
using MP = System.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.MicrosoftInterop.Tests;

public class PublicIdentityHelperTests
{
    [Fact]
    public void Nonfriend_consumer_compiles_approved_helpers_and_uses_same_kind_without_io()
    {
        using var entry = new D.DirectoryEntry("LDAP://unused.example/DC=example,DC=com");
        using var context = new AM.PrincipalContext(AM.ContextType.Domain, "unused.example");
        var helpers = new[] { IdentityResolverUsage.FromEntry(entry), IdentityResolverUsage.FromContext(context) };
        entry.Dispose(); context.Dispose();
        var name = new P.NTAccount("EXAMPLE", "alice");
        foreach (var helper in helpers)
        {
            Assert.Same(name, helper.Translate(name, typeof(P.NTAccount)));
            Assert.Same(name, Assert.Single(IdentityResolverUsage.ResolveAvailableNames(helper, new P.IdentityReferenceCollection { name })));
            Assert.Same(name, Assert.Single(IdentityResolverUsage.ResolveAllNames(helper, new P.IdentityReferenceCollection { name })));
        }
    }

    [WindowsFact]
    public void Public_helper_identity_exports_remain_data_after_owner_disposal()
    {
        using var entry = new D.DirectoryEntry("LDAP://unused.example/DC=example,DC=com");
        var helper = D.DirectoryIdentityResolver.ForEntry(entry);
        var sid = (P.SecurityIdentifier)helper.Translate(new P.SecurityIdentifier(U1, 0), typeof(P.SecurityIdentifier));
        var native = sid.ToMicrosoftObject();
        entry.Dispose();
        Assert.Equal(sid.Value, native.Value);
        var bytes = new byte[native.BinaryLength]; native.GetBinaryForm(bytes, 0); Assert.Equal(U1, bytes);
        var copy = native.ToPortableObject(); Assert.NotSame(sid, copy);
        Assert.Throws<NotSupportedException>(() => copy.Translate(typeof(P.NTAccount)));
        Assert.Throws<ObjectDisposedException>(() => helper.Translate(copy, typeof(P.NTAccount)));
    }

    [WindowsFact]
    public void Public_helper_and_entry_context_do_not_cross_Microsoft_descriptor_export()
    {
        using var entry = new D.DirectoryEntry("LDAP://unused.example/DC=example,DC=com");
        entry.Options.SecurityMasks = (D.SecurityMasks)15;
        // Only replace the server read; the public loader, helper and exporter run normally.
        typeof(D.DirectoryEntry).GetProperty("SecurityReadOverride", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(entry, (Func<D.SecurityMasks, byte[]>)(_ => Build(U1, U1, Acl(4), Acl(4))));
        var source = entry.ObjectSecurity;
        var helper = D.DirectoryIdentityResolver.ForEntry(entry);
        var owner = helper.Translate(source.GetOwner(typeof(P.SecurityIdentifier))!, typeof(P.SecurityIdentifier));
        var native = source.ToMicrosoftObject();
        entry.Dispose();
        Assert.Equal(owner.Value, native.GetOwner(typeof(MP.SecurityIdentifier))!.Value);
        var copy = native.ToPortableObject((D.SecurityMasks)15);
        Assert.Equal(owner, copy.GetOwner(typeof(P.SecurityIdentifier)));
        Assert.Throws<NotSupportedException>(() => copy.GetOwner(typeof(P.NTAccount)));
        Assert.Throws<ObjectDisposedException>(() => helper.Translate(owner, typeof(P.NTAccount)));
    }
}
