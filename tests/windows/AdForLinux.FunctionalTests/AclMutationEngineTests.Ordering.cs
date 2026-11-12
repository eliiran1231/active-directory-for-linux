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
    public void Projection_compaction_never_replaces_unrelated_original_entries_during_edit(bool audit)
    {
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var originals = new[] { Ace(type, flags, 0x10, U1), Ace(type, flags, 0x20, U1) };
        var raw = audit ? Build(Admins, Admins, Acl(4), Acl(4, originals)) : WithDacl(originals);
        var engine = Engine(raw);
        var projection = MicrosoftObservableProjector.Project(engine.Descriptor);
        Assert.Single((audit ? projection.Sacl : projection.Dacl)!.Aces);
        Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, engine.WriteIntent);
        var section = audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var edited = engine.ModifyProjected(section, AclModification.Add, CoreAce.Read(Ace(type, flags, 4, U2))).Engine;
        var aces = (audit ? edited.Descriptor.Sacl : edited.Descriptor.Dacl)!.Aces;
        Assert.Equal(3, aces.Count);
        Assert.Equal(originals, aces.Take(2).Select(a => a.RawBytes.ToArray()).ToArray());
        Assert.Equal(section, edited.WriteIntent);
        Assert.Equal(raw, edited.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(2, (audit ? MicrosoftObservableProjector.Project(edited.Descriptor).Sacl
            : MicrosoftObservableProjector.Project(edited.Descriptor).Dacl)!.Aces.Count);
    }

    [Theory]
    [InlineData(false, "Add")]
    [InlineData(false, "Remove")]
    [InlineData(false, "RemoveSpecific")]
    [InlineData(true, "Add")]
    [InlineData(true, "Remove")]
    [InlineData(true, "RemoveSpecific")]
    public void Projected_compacted_identity_reconciles_narrow_edit_and_preserves_prior_intent(bool audit, string operationName)
    {
        var operation = Enum.Parse<AclModification>(operationName);
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var acl = Acl(4, Ace(type, flags, 0x10, U1), Ace(type, flags, 0x20, U1));
        var original = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl);
        var engine = Engine(original).SetOwner(Trustee(U2)).Engine;
        var before = engine.Descriptor.GetBinaryForm();
        var section = audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var result = engine.ModifyProjected(section, operation, CoreAce.Read(Ace(type, flags, 0x30, U1)));
        if (operation == AclModification.Add) Assert.Same(engine, result.Engine);
        else Assert.Empty((audit ? result.Engine.Descriptor.Sacl : result.Engine.Descriptor.Dacl)!.Aces);
        Assert.Equal(before, engine.Descriptor.GetBinaryForm());
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Owner | (operation == AclModification.Add ? SecurityMasks.None : section), result.Engine.WriteIntent);
    }

    [Theory]
    [InlineData(false, "Set")]
    [InlineData(false, "Reset")]
    [InlineData(false, "RemoveAll")]
    [InlineData(true, "Set")]
    [InlineData(true, "Reset")]
    [InlineData(true, "RemoveAll")]
    public void Projected_whole_identity_operations_reconcile_against_original_entries(bool audit, string operationName)
    {
        var operation = Enum.Parse<AclModification>(operationName);
        var type = (byte)(audit ? 2 : 0);
        var flags = (byte)(audit ? 0x40 : 0);
        var acl = Acl(4, Ace(type, flags, 0x10, U1), Ace(type, flags, 0x20, U1), Ace(type, flags, 4, U2));
        var original = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl);
        var engine = Engine(original);
        var rule = CoreAce.Read(Ace(type, flags, 8, U1));
        var result = engine.ModifyProjected(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, operation, rule);
        var aces = (audit ? result.Engine.Descriptor.Sacl : result.Engine.Descriptor.Dacl)!.Aces;
        Assert.Equal(operation == AclModification.RemoveAll ? 1 : 2, aces.Count);
        Assert.Equal(Ace(type, flags, 4, U2), aces.Last().RawBytes.ToArray());
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
    }

    [Theory]
    [InlineData(false, "Add")]
    [InlineData(true, "Add")]
    [InlineData(false, "RemoveSpecific")]
    [InlineData(true, "RemoveSpecific")]
    public void Projected_edit_preserves_unrelated_compacted_group_for_same_sid(bool audit, string operationName)
    {
        var type = (byte)(audit ? 7 : 5);
        var flags = (byte)(audit ? 0x40 : 0);
        var unrelated = new[] { ObjAce(type, flags, 0x10, 1, G2, null, U1), ObjAce(type, flags, 0x20, 1, G2, null, U1) };
        var acl = Acl(4, ObjAce(type, flags, 0x10, 1, G1, null, U1), ObjAce(type, flags, 0x20, 1, G1, null, U1), unrelated[0], unrelated[1]);
        var raw = audit ? Build(Admins, Admins, Acl(4), acl) : Build(Admins, Admins, acl);
        var engine = Engine(raw);
        var operation = Enum.Parse<AclModification>(operationName);
        var rule = CoreAce.Read(ObjAce(type, flags, operation == AclModification.Add ? 0x10000u : 0x30u, 1, G1, null, U1));
        var result = engine.ModifyProjected(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, operation, rule);
        var changed = (audit ? result.Engine.Descriptor.Sacl : result.Engine.Descriptor.Dacl)!;
        Assert.Equal(unrelated, changed.Aces.Where(ace => ace.ObjectType == G2).Select(ace => ace.RawBytes.ToArray()).ToArray());
        Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        Assert.Equal(raw, result.Engine.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Multi_entry_audit_order_keeps_metadata_payloads_and_other_acl_exact()
    {
        var first = Ace(2, 0x40, 0x20, U2);
        var second = Ace(2, 0x80, 4, U2);
        var tail = new byte[] { 0xFA, 0xCE, 0xBA, 0xBE };
        var acl = AclWithTail(4, tail, first, second);
        acl[1] = 0x71; acl[6] = 0x39;
        var opaque = Acl(4, Ace(0x20, 0x20, 0x10, U1));
        var original = Build(Admins, Admins, opaque, acl);
        var engine = Engine(original).SetGroup(Trustee(U2)).Engine;
        var addition = CoreAce.Read(Ace(2, 0x40, 0x100, Sid.Parse("S-1-1-0").ToArray()));
        var result = engine.ModifyAuditRule(AclModification.Add, addition);
        var sacl = result.Engine.Descriptor.Sacl!;
        Assert.Equal(new[] { addition.RawBytes.ToArray(), second, first }, sacl.Aces.Select(a => a.RawBytes.ToArray()).ToArray());
        Assert.Equal(tail, sacl.Trailing.ToArray());
        Assert.Equal((byte)0x71, sacl.Sbz1);
        Assert.Equal((ushort)0x39, sacl.Sbz2);
        Assert.Equal(opaque, AclBytes(result.Engine.Descriptor, 16));
        Assert.Equal(SecurityMasks.Group | SecurityMasks.Sacl, result.Engine.WriteIntent);
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Noncanonical_audit_order_is_preserved_on_projection_and_mutation_refuses()
    {
        var raw = Build(Admins, Admins, Acl(4), Acl(4, Ace(2, 0x50, 0x10, U1), Ace(2, 0x40, 0x20, U2)));
        var engine = Engine(raw);
        Assert.Equal(raw, MicrosoftObservableProjector.Project(engine.Descriptor).GetBinaryForm());
        Assert.Throws<InvalidOperationException>(() => engine.ModifyAuditRule(AclModification.Add, Rule(4, 2, 0x40)));
        Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, engine.WriteIntent);
    }
}
