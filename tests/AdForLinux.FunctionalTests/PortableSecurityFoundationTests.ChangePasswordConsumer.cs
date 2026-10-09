#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using C = AdForLinux.DirectoryServices.Security.Core;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static readonly Guid PasswordRight = new("ab721a53-1e2f-11d0-9819-00aa0040529b");
    private static readonly byte[] PasswordSelf = Convert.FromHexString("01010000000000050A000000");
    private static UserPrincipal PasswordPrincipal(EntryWriteFixture fixture, PrincipalContext context)
    {
        fixture.Entry.PropertyReadOverride = (names, _) =>
        {
            var properties = new PropertyCollection();
            properties.ReplaceLoaded("objectGUID", new object[] { G1.ToByteArray() });
            properties.ReplaceLoaded("objectSid", new object[] { U1 });
            if (names.Contains("nTSecurityDescriptor"))
                properties.ReplaceLoaded("nTSecurityDescriptor", new object[] { fixture.Raw });
            return properties;
        };
        return new UserPrincipal(context, fixture.Entry);
    }

    [Theory]
    [InlineData(0x10)] [InlineData(0x20000)]
    public void Principal_password_acl_changes_only_intended_rights_through_raw_entry_planner(int otherRights)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = Build(U1, U1, Acl(4,
            ObjAce(6, 0, (uint)otherRights | 0x100, 1, PasswordRight, null, PasswordSelf),
            ObjAce(6, 0, 0x100, 1, PasswordRight, null, Everyone)));
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        using var principal = PasswordPrincipal(fixture, context);
        principal.UserCannotChangePassword = false;
        principal.Save();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal(System.DirectoryServices.Protocols.SecurityMasks.Dacl,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
        var bytes = Assert.IsType<byte[]>(Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>())[0]);
        var changed = C.SecurityDescriptor.Parse(bytes, AllEntrySections);
        Assert.Equal(U1, changed.Owner!.ToArray()); Assert.Equal(U1, changed.Group!.ToArray());
        var remainder = Assert.Single(changed.Dacl!.Aces, ace => ace.AceType == 6);
        Assert.Equal((uint)otherRights, remainder.AccessMask);
        Assert.Equal(PasswordSelf, remainder.Sid!.ToArray()); Assert.Equal(PasswordRight, remainder.ObjectType);
        Assert.Equal(2, changed.Dacl.Aces.Count(ace => ace.AceType == 5 && ace.AccessMask == 0x100));
    }

    [Theory]
    [InlineData("trailer")] [InlineData("opaque")] [InlineData("gap")] [InlineData("reserved")]
    public void Principal_password_acl_unsupported_storage_refuses_before_any_write(string storage)
    {
        using var fixture = new EntryWriteFixture();
        var acl = storage == "trailer" ? AclWithTail(4, new byte[] { 1, 2, 3, 4 })
            : storage == "opaque" ? Acl(4, new byte[] { 0x42, 0, 4, 0 }) : Acl(4);
        if (storage == "reserved") acl[1] = 1;
        fixture.Raw = Build(U1, U1, acl, gapBefore: storage == "gap" ? 4 : 0);
        var before = (byte[])fixture.Raw.Clone();
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        using var principal = PasswordPrincipal(fixture, context);
        principal.UserCannotChangePassword = true;
        if (storage == "gap") Assert.Throws<NotSupportedException>(principal.Save);
        else Assert.Throws<InvalidOperationException>(principal.Save);
        Assert.Empty(fixture.Writes); Assert.Equal(before, fixture.Raw);
        Assert.Equal(before, fixture.Entry.ObjectSecurity._securityDescriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(EntryMasks.None, fixture.Entry.ObjectSecurity.PendingWriteSections);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Principal_password_acl_failure_retains_intent_and_never_replays_uncertain_write(bool lostResponse)
    {
        using var fixture = new EntryWriteFixture(); fixture.Raw = Build(U1, U1, Acl(4));
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        using var principal = PasswordPrincipal(fixture, context);
        principal.UserCannotChangePassword = true;
        fixture.Entry.WriteRequestOverride = request =>
        {
            fixture.Writes.Add(request);
            if (!lostResponse) return ResultCode.UnwillingToPerform;
            fixture.Raw = (byte[])Assert.IsType<ModifyRequest>(request).Modifications[0][0];
            throw new TimeoutException("accepted, lost response");
        };
        Assert.NotNull(Record.Exception(principal.Save));
        Assert.Equal(EntryMasks.Dacl, fixture.Entry.ObjectSecurity.PendingWriteSections);
        if (lostResponse)
        {
            Assert.Throws<InvalidOperationException>(principal.Save);
            fixture.Entry.RefreshCache(new[] { "nTSecurityDescriptor" });
        }
        fixture.Entry.WriteRequestOverride = request =>
        {
            fixture.Writes.Add(request);
            fixture.Raw = (byte[])Assert.IsType<ModifyRequest>(request).Modifications[0][0];
            return ResultCode.Success;
        };
        principal.Save();
        Assert.Equal(lostResponse ? 1 : 2, fixture.Writes.Count);
        Assert.True(ChangePasswordAcl.IsDenied(fixture.Raw));
    }

    [Fact]
    public void Principal_password_acl_cannot_edit_an_unretrieved_dacl()
    {
        using var fixture = new EntryWriteFixture(); fixture.Entry.Options.SecurityMasks = EntryMasks.Owner;
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        using var principal = PasswordPrincipal(fixture, context);
        principal.UserCannotChangePassword = true;
        Assert.Throws<InvalidOperationException>(principal.Save); Assert.Empty(fixture.Writes);
    }

    [Theory]
    [InlineData("path")] [InlineData("close")] [InlineData("dispose")]
    public void Principal_password_acl_preparation_refuses_stale_entry_binding(string change)
    {
        using var fixture = new EntryWriteFixture(); fixture.Raw = Build(U1, U1, Acl(4));
        var security = fixture.Entry.ObjectSecurity;
        var before = security._securityDescriptor.MutationState;
        Assert.NotNull(Record.Exception(() => security.EditRawDacl(raw =>
        {
            switch (change)
            {
                case "path": fixture.Entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
                case "close": fixture.Entry.Close(); break;
                case "dispose": fixture.Entry.Dispose(); break;
            }
            return ChangePasswordAcl.SetDenied(raw, true);
        })));
        Assert.Same(before, security._securityDescriptor.MutationState); Assert.Empty(fixture.Writes);
    }
}
