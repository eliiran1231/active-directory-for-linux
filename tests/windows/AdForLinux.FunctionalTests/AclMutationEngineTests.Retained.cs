using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class AclMutationEngineTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Retained_live_groups_survive_getters_identity_other_acl_and_failed_edits(bool audit)
    {
        var section = audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var opposite = audit ? SecurityMasks.Dacl : SecurityMasks.Sacl;
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var acl = Acl(4, Ace(type, flags, 0x10, U1), Ace(type, flags, 0x20, U1), Ace(type, flags, 0x40, U1), Ace(type, flags, 0x80, U1));
        var raw = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl, Acl(4));
        var initial = Engine(raw);
        CoreAce RuleFor(uint mask) => CoreAce.Read(Ace(type, flags, mask, U1));
        var first = initial.ModifyProjected(section, AclModification.Remove, RuleFor(0x10)).Engine;
        Assert.Equal(new uint[] { 0x20, 0x40, 0x80 }, RawAcl(first).Aces.Select(ace => ace.AccessMask));
        Assert.Equal(new uint[] { 0x20, 0xC0 }, first.GetObservableAcl(section)!.Aces.Select(ace => ace.AccessMask));
        var firstRaw = first.Descriptor.GetBinaryForm();
        var firstLive = first.GetObservableDescriptor().GetBinaryForm();
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(firstLive, first.GetObservableDescriptor().GetBinaryForm());
            Assert.Equal(firstRaw, first.Descriptor.GetBinaryForm());
        }
        var freshImport = new AclMutationEngine(first.Descriptor);
        Assert.Equal(new uint[] { 0x60, 0x80 }, freshImport.GetObservableAcl(section)!.Aces.Select(ace => ace.AccessMask));
        Assert.Equal(SecurityMasks.None, freshImport.WriteIntent);
        Assert.Same(first, first.ModifyProjected(section, AclModification.Add, RuleFor(0x20)).Engine);
        var staged = first.SetOwner(Trustee(U2)).Engine.SetGroup(Trustee(U2)).Engine;
        var oppositeRule = CoreAce.Read(Ace((byte)(audit ? 0 : 2), (byte)(audit ? 0 : 0x40), 4, U2));
        staged = staged.Modify(opposite, AclModification.Add, oppositeRule).Engine;
        var beforeRaw = staged.Descriptor.GetBinaryForm();
        var beforeLive = staged.GetObservableDescriptor().GetBinaryForm();
        var intent = section | opposite | SecurityMasks.Owner | SecurityMasks.Group;
        var conflict = CoreAce.Read(ObjAce((byte)(audit ? 7 : 5), flags, 0x20, 1, G1, null, U1));
        var failed = staged.ModifyProjected(section, AclModification.Remove, conflict);
        Assert.False(failed.ReturnValue);
        Assert.False(failed.Modified);
        Assert.Same(staged, failed.Engine);
        Assert.Equal(beforeRaw, staged.Descriptor.GetBinaryForm());
        Assert.Equal(beforeLive, staged.GetObservableDescriptor().GetBinaryForm());
        Assert.Equal(intent, staged.WriteIntent);
        Assert.Throws<InvalidOperationException>(() => staged.Modify(section, AclModification.Add, RuleFor(0x20)));
        Assert.Throws<InvalidOperationException>(() => staged.Purge(section, Trustee(U1)));
        Assert.Throws<InvalidOperationException>(() => staged.SetProtection(section, true, true));
        var second = staged.ModifyProjected(section, AclModification.RemoveSpecific, RuleFor(0xC0)).Engine;
        Assert.Equal(new uint[] { 0x20 }, RawAcl(second).Aces.Select(ace => ace.AccessMask));
        Assert.Equal(new uint[] { 0x20 }, second.GetObservableAcl(section)!.Aces.Select(ace => ace.AccessMask));
        Assert.Same(second, second.ModifyProjected(section, AclModification.RemoveSpecific, RuleFor(0xC0)).Engine);
        Assert.Equal(intent, second.WriteIntent);
        Assert.Equal(raw, second.OriginalDescriptor.GetBinaryForm());
        // Older snapshots retain their raw, live, provenance and intent after later edits.
        Assert.Equal(raw, initial.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, initial.WriteIntent);
        Assert.Equal(firstRaw, first.Descriptor.GetBinaryForm());
        Assert.Equal(firstLive, first.GetObservableDescriptor().GetBinaryForm());
        Assert.Equal(beforeRaw, staged.Descriptor.GetBinaryForm());
        Assert.Equal(beforeLive, staged.GetObservableDescriptor().GetBinaryForm());
        var fork = first.ModifyProjected(section, AclModification.RemoveSpecific, RuleFor(0xC0)).Engine;
        Assert.Single(RawAcl(fork).Aces);
        Acl RawAcl(AclMutationEngine engine) => (audit ? engine.Descriptor.Sacl : engine.Descriptor.Dacl)!;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Retained_duplicate_occurrences_do_not_steal_equal_bytes_from_other_groups(bool audit)
    {
        var section = audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var ace = Ace(type, flags, 0x10, U1);
        var acl = Acl(4, ace, ace, ace, ace);
        var original = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl);
        var first = Engine(original).ModifyProjected(section, AclModification.Add, CoreAce.Read(Ace(type, flags, 1, U1))).Engine;
        var second = first.ModifyProjected(section, AclModification.RemoveSpecific, CoreAce.Read(ace)).Engine;
        var raw = (audit ? second.Descriptor.Sacl : second.Descriptor.Dacl)!;
        Assert.Equal(new uint[] { 0x11, 0x10 }, raw.Aces.Select(a => a.AccessMask));
        Assert.Equal(0x11u, Assert.Single(second.GetObservableAcl(section)!.Aces).AccessMask);
        Assert.Equal(4, (audit ? first.Descriptor.Sacl : first.Descriptor.Dacl)!.Aces.Count);
        Assert.Equal(original, second.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Retained_audit_split_maps_each_new_residual_without_touching_other_identity()
    {
        var unrelated = new[] { Ace(2, 0x40, 0x10, U2), Ace(2, 0x40, 0x20, U2) };
        var raw = Build(Admins, Admins, Acl(4), Acl(4, Ace(2, 0x40, 0x30, U1), Ace(2, 0x80, 0x30, U1), unrelated[0], unrelated[1]));
        var first = Engine(raw).ModifyProjected(SecurityMasks.Sacl, AclModification.Remove, CoreAce.Read(Ace(2, 0x40, 0x10, U1))).Engine;
        Assert.Equal(new[] { Ace(2, 0xC0, 0x20, U1), Ace(2, 0x80, 0x10, U1) }, first.GetObservableAcl(SecurityMasks.Sacl)!.Aces.Where(a => a.Sid!.Equals(Trustee(U1))).Select(a => a.RawBytes.ToArray()).ToArray());
        var second = first.ModifyProjected(SecurityMasks.Sacl, AclModification.RemoveSpecific, CoreAce.Read(Ace(2, 0x80, 0x10, U1))).Engine;
        Assert.Equal(unrelated, second.Descriptor.Sacl!.Aces.Where(a => a.Sid!.Equals(Trustee(U2))).Select(a => a.RawBytes.ToArray()).ToArray());
        Assert.Equal(Ace(2, 0xC0, 0x20, U1), Assert.Single(second.GetObservableAcl(SecurityMasks.Sacl)!.Aces, a => a.Sid!.Equals(Trustee(U1))).RawBytes.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Retained_projection_does_not_bypass_reserved_header_and_tail_refusal(bool audit)
    {
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var section = audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var tail = new byte[] { 0x12, 0x34, 0x56, 0x78 };
        var acl = AclWithTail(4, tail, Ace(type, flags, 0x10, U1), Ace(type, flags, 0x20, U1), Ace(type, flags, 0x40, U1), Ace(type, flags, 0x80, U1));
        acl[1] = 0x42; acl[6] = 0xA5;
        var raw = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl);
        var initial = Engine(raw);
        Assert.Throws<InvalidOperationException>(() => initial.GetObservableAcl(section));
        var result = initial.ModifyProjected(section, AclModification.Remove, CoreAce.Read(Ace(type, flags, 0x10, U1))).Engine;
        var preserved = (audit ? result.Descriptor.Sacl : result.Descriptor.Dacl)!;
        Assert.Equal((byte)0x42, preserved.Sbz1);
        Assert.Equal((ushort)0xA5, preserved.Sbz2);
        Assert.Equal(tail, preserved.Trailing.ToArray());
        Assert.Throws<InvalidOperationException>(() => result.GetObservableAcl(section));
        Assert.Throws<InvalidOperationException>(() => result.GetObservableDescriptor());
        Assert.Equal(raw, initial.Descriptor.GetBinaryForm());
        Assert.Equal(raw, result.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Retained_section_is_lazy_beside_opaque_opposite_acl()
    {
        var opaque = Acl(4, Ace(0x20, 0x20, 0x10, U1));
        var raw = Build(Admins, Admins, opaque, Acl(4, Ace(2, 0x40, 0x10, U1), Ace(2, 0x40, 0x20, U1), Ace(2, 0x40, 0x40, U1), Ace(2, 0x40, 0x80, U1)));
        var first = Engine(raw).ModifyProjected(SecurityMasks.Sacl, AclModification.Remove, CoreAce.Read(Ace(2, 0x40, 0x10, U1))).Engine;
        var second = first.SetOwner(Trustee(U2)).Engine;
        Assert.Equal(new uint[] { 0x20, 0xC0 }, second.GetObservableAcl(SecurityMasks.Sacl)!.Aces.Select(a => a.AccessMask));
        Assert.Equal(opaque, AclBytes(second.Descriptor, 16));
        Assert.Equal(SecurityMasks.Sacl | SecurityMasks.Owner, second.WriteIntent);
        Assert.Equal(raw, second.OriginalDescriptor.GetBinaryForm());
    }
}
