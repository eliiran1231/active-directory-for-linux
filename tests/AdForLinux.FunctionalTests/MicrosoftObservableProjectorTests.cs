using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;
using CoreAcl = AdForLinux.DirectoryServices.Security.Core.Acl;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;

namespace AdForLinux.FunctionalTests;

/// <summary>In-memory only; no collection fixture, DirectoryEntry, AD or Samba dependency.</summary>
public class MicrosoftObservableProjectorTests
{
    public static TheoryData<byte> Families => new() { 0, 1, 2, 5, 6, 7 };

    [Theory]
    [MemberData(nameof(Families))]
    public void Exact_inactive_predicate_exhausts_all_header_flags_and_acl_kinds(byte type)
    {
        var audit = type is 2 or 7;
        for (var flags = 0; flags <= byte.MaxValue; flags++)
        {
            var ace = CoreAce.Read(Make(type, (byte)flags));
            foreach (var isDacl in new[] { true, false })
            {
                var knownBits = audit ? 0xdc : 0x1c;
                var expected = isDacl != audit && (flags & 8) != 0 && (flags & ~knownBits) == 0;
                Assert.Equal(expected, MicrosoftObservableProjector.IsInactiveInheritOnly(ace, isDacl));
            }
        }
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void Inactive_drop_preserves_raw_and_never_activates_the_ace(byte type)
    {
        var isDacl = type is not (2 or 7);
        var bytes = Make(type, (byte)(isDacl ? 0x1c : 0xdc));
        var raw = CoreAcl.Read(Acl(4, bytes));
        var projected = MicrosoftObservableProjector.ProjectAcl(raw, isDacl);
        Assert.Empty(projected.Aces);
        Assert.Equal(bytes, Assert.Single(raw.Aces).RawBytes.ToArray());
        Assert.True((raw.Aces[0].AceFlags & 8) != 0); // does not apply to current object
        Assert.Equal(0, raw.Aces[0].AceFlags & 3); // cannot propagate to descendants
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void Either_inheritance_bit_prevents_inactive_drop(byte type)
    {
        foreach (var flags in new byte[] { 9, 10, 11, 13, 14, 15 })
        {
            var bytes = Make(type, (byte)(flags | (type is 2 or 7 ? 0x40 : 0)));
            var raw = CoreAcl.Read(Acl(4, bytes));
            var projected = MicrosoftObservableProjector.ProjectAcl(raw, type is not (2 or 7));
            Assert.Equal(bytes, Assert.Single(projected.Aces).RawBytes.ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void No_propagate_without_inheritance_is_cleared_without_changing_access(byte type)
    {
        var flags = (byte)(type is 2 or 7 ? 0xc4 : 4);
        var raw = CoreAcl.Read(Acl(4, Make(type, flags)));
        var output = Assert.Single(MicrosoftObservableProjector.ProjectAcl(raw, type is not (2 or 7)).Aces);
        Assert.Equal((byte)(flags & ~4), output.AceFlags);
        Assert.Equal(raw.Aces[0].AccessMask, output.AccessMask);
        Assert.Equal(raw.Aces[0].Sid, output.Sid);
        Assert.Equal(raw.Aces[0].ObjectType, output.ObjectType);
        Assert.Equal(raw.Aces[0].InheritedObjectType, output.InheritedObjectType);
        Assert.Equal(flags, raw.Aces[0].AceFlags);
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void Trailing_payload_and_wrong_acl_kind_refuse_atomically(byte type)
    {
        var normal = Make(type, (byte)(type is 2 or 7 ? 0x48 : 8));
        var tailed = normal.Concat(new byte[] { 0xde, 0xad, 0xbe, 0xef }).ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(tailed.AsSpan(2), (ushort)tailed.Length);
        foreach (var (bytes, isDacl) in new[] { (tailed, type is not (2 or 7)), (normal, type is 2 or 7) })
        {
            var raw = CoreAcl.Read(Acl(4, bytes));
            Assert.False(MicrosoftObservableProjector.IsInactiveInheritOnly(raw.Aces[0], isDacl));
            Assert.Throws<InvalidOperationException>(() => MicrosoftObservableProjector.ProjectAcl(raw, isDacl));
            Assert.Equal(bytes, raw.Aces[0].RawBytes.ToArray());
        }
    }

    [Fact]
    public void Unsupported_types_flags_object_flags_and_invalid_sid_cannot_qualify_for_drop()
    {
        var cases = new[]
        {
            Ace(9, 8, 16, U1), Ace(0x20, 8, 16, U1), Ace(0, 0x28, 16, U1),
            Ace(0, 0x48, 16, U1), ObjAce(5, 8, 16, 4, null, null, U1),
            ObjAce(5, 8, 16, 1, null, null, U1), Ace(0, 8, 16, new byte[12]),
        };
        foreach (var bytes in cases)
        {
            var raw = CoreAcl.Read(Acl(4, bytes));
            Assert.False(MicrosoftObservableProjector.IsInactiveInheritOnly(raw.Aces[0], true));
            Assert.Throws<InvalidOperationException>(() => MicrosoftObservableProjector.ProjectAcl(raw, true));
            Assert.Equal(bytes, raw.Aces[0].RawBytes.ToArray());
        }
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(2u)]
    [InlineData(3u)]
    public void All_exact_guid_presence_combinations_qualify(uint objectFlags)
    {
        foreach (var type in new byte[] { 5, 6, 7 })
        {
            var bytes = ObjAce(type, 8, 16, objectFlags, (objectFlags & 1) != 0 ? G1 : null,
                (objectFlags & 2) != 0 ? G2 : null, U1);
            Assert.Empty(MicrosoftObservableProjector.ProjectAcl(CoreAcl.Read(Acl(4, bytes)), type != 7).Aces);
        }
    }

    [Fact]
    public void Dacl_object_partition_stays_within_qualifier_groups_and_preserves_inherited_order()
    {
        var aces = new[] { Make(6, 0), Make(1, 0), Make(5, 0), Make(0, 0), Make(5, 16), Make(0, 16), Make(1, 0) };
        var projected = MicrosoftObservableProjector.ProjectAcl(CoreAcl.Read(Acl(4, aces)), true);
        Assert.Equal(new[] { aces[1], aces[0], aces[3], aces[2], aces[4], aces[5], aces[6] },
            projected.Aces.Select(a => a.RawBytes.ToArray()).ToArray());
    }

    [Fact]
    public void Sacl_order_is_not_changed_by_unresolved_sorting_policy()
    {
        var aces = new[] { Make(7, 0x40), Make(2, 0x80), Make(7, 0x50), Make(2, 0xc0) };
        var projected = MicrosoftObservableProjector.ProjectAcl(CoreAcl.Read(Acl(4, aces)), false);
        Assert.Equal(aces, projected.Aces.Select(a => a.RawBytes.ToArray()).ToArray());
    }

    [Fact]
    public void Descriptor_projection_is_detached_and_retains_raw_absent_null_distinction()
    {
        const SecurityMasks all = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
        foreach (var nullDacl in new[] { false, true })
        {
            var bytes = Build(Admins, Admins, null, sacl: Acl(4, Make(2, 0x48)), nullDacl: nullDacl);
            var raw = SecurityDescriptor.Parse(bytes, all);
            var projected = MicrosoftObservableProjector.Project(raw);
            Assert.Equal(AclState.Absent, projected.DaclState);
            Assert.Equal(nullDacl ? AclState.Null : AclState.Absent, raw.DaclState);
            Assert.Equal(AclState.Empty, projected.SaclState);
            Assert.Equal(AclState.Populated, raw.SaclState);
            Assert.Equal(all, projected.RetrievedSections);
            Assert.Equal(bytes, raw.GetBinaryForm());
        }
    }

    [Fact]
    public void Active_zero_mask_and_unaudited_aces_refuse_unapproved_loss()
    {
        Assert.Throws<InvalidOperationException>(() => MicrosoftObservableProjector.ProjectAcl(
            CoreAcl.Read(Acl(4, Ace(0, 0, 0, U1))), true));
        Assert.Throws<InvalidOperationException>(() => MicrosoftObservableProjector.ProjectAcl(
            CoreAcl.Read(Acl(4, Ace(2, 0, 16, U1))), false));
        // Exact D13 inactive exceptions still qualify, including audit with neither audit bit.
        Assert.Empty(MicrosoftObservableProjector.ProjectAcl(CoreAcl.Read(Acl(4, Ace(2, 8, 0, U1))), false).Aces);
    }

    private static byte[] Make(byte type, byte flags) => type >= 5
        ? ObjAce(type, flags, 16, 3, G1, G2, U1)
        : Ace(type, flags, 16, U1);
}
