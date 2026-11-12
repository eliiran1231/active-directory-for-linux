using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Principal_save_combines_owner_and_scalar_intent_and_acknowledges_both(bool securityFirst, bool rejectFirst)
    {
        using var fixture = new Fixture();
        var original = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)));
        fixture.Server["nTSecurityDescriptor"] = [original];
        var securityReads = 0;
        fixture.Entry.Options.SecurityMasks = EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl;
        fixture.Entry.SecurityReadOverride = masks =>
        {
            securityReads++;
            Assert.Equal(EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl, masks);
            return (byte[])fixture.Server["nTSecurityDescriptor"][0];
        };
        using var user = fixture.Attach(new MaterializedCustomUser(fixture.Context));
        var entry = Assert.IsType<DirectoryEntry>(user.GetUnderlyingObject());
        if (!securityFirst) user.Description = "combined change";
        entry.ObjectSecurity.SetOwner(new SecurityIdentifier(U2, 0));
        if (securityFirst) user.Description = "combined change";

        if (rejectFirst)
        {
            fixture.Fail = true;
            Assert.Throws<InvalidOperationException>(user.Save);
            Assert.Empty(fixture.Writes);
            Assert.Equal(original, Assert.IsType<byte[]>(fixture.Server["nTSecurityDescriptor"][0]));
            fixture.Fail = false;
        }
        user.Save();

        Assert.Equal(rejectFirst ? 2 : 1, fixture.Attempts);
        Assert.Equal(1, securityReads);
        var combined = Assert.Single(fixture.Writes);
        Assert.Equal("CN=item,DC=example,DC=test", combined.DistinguishedName);
        Assert.Equal(2, combined.Modifications.Count);
        Assert.Equal(System.DirectoryServices.Protocols.SecurityMasks.Owner,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(combined.Controls.Cast<DirectoryControl>())).SecurityMasks);
        var scalar = Assert.Single(combined.Modifications.Cast<DirectoryAttributeModification>(), change => change.Name == "description");
        Assert.Equal(DirectoryAttributeOperation.Replace, scalar.Operation);
        Assert.Equal("combined change", Assert.Single(scalar.Cast<object>()));
        var security = Assert.Single(combined.Modifications.Cast<DirectoryAttributeModification>(), change => change.Name == "nTSecurityDescriptor");
        Assert.Equal(Build(U2, U1, Acl(4, Ace(0, 0, 16, U1))), Assert.IsType<byte[]>(Assert.Single(security.Cast<object>())));

        // A later external owner and scalar value must survive an unrelated edit.
        var external = Build(U1, U2, Acl(4, Ace(0, 0, 16, U1)));
        fixture.Server["nTSecurityDescriptor"] = [external];
        fixture.Server["description"] = ["external description"];
        user.WriteAttribute("department", "later department");
        user.Save();
        Assert.Equal(2, fixture.Writes.Count);
        var later = Assert.Single(fixture.Writes[1].Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("department", later.Name);
        Assert.Empty(fixture.Writes[1].Controls.Cast<DirectoryControl>());
        Assert.Equal(external, Assert.IsType<byte[]>(fixture.Server["nTSecurityDescriptor"][0]));
        Assert.Equal("external description", Assert.Single(fixture.Server["description"]));
        Assert.Equal(1, securityReads);
    }
}
