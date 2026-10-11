#pragma warning disable CA1416
using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(16)]
    public void Add_planning_never_infers_known_sections_from_complete_bytes(int mask)
    {
        var raw = Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000);
        var add = new AddRequest("CN=child,DC=example,DC=com", "user");
        Assert.Throws<NotSupportedException>(() => A.RawSecurityWritePreparation.AppendAdd(add, raw, (EntryMasks)mask));
        Assert.Equal("objectClass", Assert.Single(add.Attributes.Cast<DirectoryAttribute>()).Name);
        Assert.Empty(add.Controls.Cast<DirectoryControl>());
        // Coverage has no meaning when no descriptor was assigned; defaults stay omitted.
        A.RawSecurityWritePreparation.AppendAdd(add, null, (EntryMasks)mask);
        Assert.Equal("objectClass", Assert.Single(add.Attributes.Cast<DirectoryAttribute>()).Name);
        Assert.Empty(add.Controls.Cast<DirectoryControl>());
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Add_planning_refuses_stored_acl_with_present_bit_clear_atomically(bool sacl, bool entry)
    {
        var raw = Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000);
        var control = BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(2));
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(2), (ushort)(control & ~(sacl ? SaclPresent : DaclPresent)));
        var original = (byte[])raw.Clone();
        if (entry)
        {
            using var fixture = new EntryWriteFixture();
            using var child = DirectoryEntry.NewChild(fixture.Entry, "CN=child", "user");
            var valid = Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000);
            child.ObjectSecurity = new ActiveDirectorySecurity(valid, AllEntrySections);
            var assigned = child.ObjectSecurity;
            var source = new ActiveDirectorySecurity(raw, AllEntrySections);
            Assert.Throws<NotSupportedException>(() => child.ObjectSecurity = source);
            Assert.Same(assigned, child.ObjectSecurity);
            Assert.Equal(original, source._securityDescriptor.MutationState.Descriptor.GetBinaryForm());
            child.WriteRequestOverride = request => { fixture.Writes.Add(request); return ResultCode.Success; };
            child.CommitChanges();
            var add = Assert.IsType<AddRequest>(Assert.Single(fixture.Writes));
            Assert.Equal(valid, Assert.IsType<byte[]>(add.Attributes.Cast<DirectoryAttribute>().Single(a => a.Name == "nTSecurityDescriptor")[0]));
        }
        else
        {
            var add = new AddRequest("CN=child,DC=example,DC=com", "user");
            var attribute = Assert.Single(add.Attributes.Cast<DirectoryAttribute>());
            Assert.Throws<NotSupportedException>(() => A.RawSecurityWritePreparation.AppendAdd(add, raw, AllEntrySections));
            Assert.Same(attribute, Assert.Single(add.Attributes.Cast<DirectoryAttribute>()));
            Assert.Empty(add.Controls.Cast<DirectoryControl>());
        }
        Assert.Equal(original, raw);
    }

    [Theory]
    [InlineData("empty")] [InlineData("common")] [InlineData("object")]
    [InlineData("callback")] [InlineData("opaque")] [InlineData("storage")]
    [InlineData("shared")] [InlineData("inherited")]
    public void Add_planning_copies_accepted_raw_bytes_without_claiming_server_roundtrip(string kind)
    {
        var dacl = kind switch
        {
            "empty" => Acl(4),
            "object" => Acl(4, ObjAce(5, 0, 16, 1, G1, null, U1)),
            "callback" => Acl(4, Ace(9, 0, 16, U1, new byte[] { 1, 2, 3, 4 })),
            "opaque" => Acl(4, new byte[] { 0x7f, 0, 8, 0, 1, 2, 3, 4 }),
            "inherited" => Acl(4, Ace(0, 0x10, 16, U1)),
            _ => AclWithTail(4, new byte[] { 5, 6, 7, 8 }, Ace(0, 0, 0, U1), Ace(0, 0, 16, U1), Ace(0, 0, 32, U1))
        };
        var raw = Build(U1, U1, dacl, Acl(4), extraControl: 0x3000);
        if (kind == "storage")
        {
            dacl[1] = 0x42; dacl[6] = 0x24;
            raw = Build(U1, U1, dacl, Acl(4), extraControl: 0x7040, sbz1: 0x7e,
                gapBefore: 4, tail: new byte[] { 9, 10, 11, 12 },
                order: new[] { Part.Dacl, Part.Owner, Part.Sacl, Part.Group });
        }
        if (kind == "shared") raw.AsSpan(4, 4).CopyTo(raw.AsSpan(8, 4));
        var original = (byte[])raw.Clone();
        var prepared = A.RawSecurityWritePreparation.PrepareAdd(raw, AllEntrySections)!;
        var add = new AddRequest("CN=child,DC=example,DC=com", "user");
        A.RawSecurityWritePreparation.AppendAdd(add, raw, AllEntrySections);
        var sent = Assert.IsType<byte[]>(add.Attributes.Cast<DirectoryAttribute>().Single(a => a.Name == "nTSecurityDescriptor")[0]);
        Assert.Equal(original, prepared); Assert.Equal(original, sent);
        Assert.NotSame(raw, prepared); Assert.NotSame(raw, sent);
        Assert.Empty(add.Controls.Cast<DirectoryControl>());
        Array.Clear(raw); Array.Clear(prepared);
        Assert.Equal(original, sent);
    }

    [Theory]
    [InlineData("owner")] [InlineData("group")]
    [InlineData("absent-dacl")] [InlineData("null-dacl")]
    [InlineData("absent-sacl")] [InlineData("null-sacl")]
    [InlineData("unprotected-dacl")] [InlineData("unprotected-sacl")]
    public void Add_planning_keeps_default_dependent_forms_unsupported(string kind)
    {
        var raw = Build(kind == "owner" ? null : U1, kind == "group" ? null : U1,
            kind is "absent-dacl" or "null-dacl" ? null : Acl(4),
            kind is "absent-sacl" or "null-sacl" ? null : Acl(4),
            extraControl: kind == "unprotected-dacl" ? (ushort)0x2000 : kind == "unprotected-sacl" ? (ushort)0x1000 : (ushort)0x3000,
            nullDacl: kind == "null-dacl");
        if (kind == "null-sacl") raw[2] |= (byte)SaclPresent;
        var original = (byte[])raw.Clone();
        var add = new AddRequest("CN=child,DC=example,DC=com", "user");
        Assert.Throws<NotSupportedException>(() => A.RawSecurityWritePreparation.AppendAdd(add, raw, AllEntrySections));
        Assert.Equal(original, raw);
        Assert.Equal("objectClass", Assert.Single(add.Attributes.Cast<DirectoryAttribute>()).Name);
        Assert.Empty(add.Controls.Cast<DirectoryControl>());
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Add_planning_rejects_untracked_descriptor_or_sd_flags_even_without_assignment(bool control, bool explicitDescriptor)
    {
        var add = new AddRequest("CN=child,DC=example,DC=com", "user");
        var sentinel = new byte[] { 1, 2, 3, 4 };
        if (control) add.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", sentinel, false, true));
        else add.Attributes.Add(new DirectoryAttribute("NTsecurityDESCRIPTOR", sentinel));
        var attributes = add.Attributes.Cast<DirectoryAttribute>().ToArray();
        var controls = add.Controls.Cast<DirectoryControl>().ToArray();
        var raw = explicitDescriptor ? Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000) : null;
        Assert.Throws<InvalidOperationException>(() => A.RawSecurityWritePreparation.AppendAdd(add, raw, AllEntrySections));
        Assert.Equal(attributes, add.Attributes.Cast<DirectoryAttribute>());
        Assert.Equal(controls, add.Controls.Cast<DirectoryControl>());
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, sentinel);
    }
}
