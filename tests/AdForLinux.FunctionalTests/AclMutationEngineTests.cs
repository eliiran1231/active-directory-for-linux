using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

/// <summary>In-memory safety and algebraic tests. No directory fixture or identity translation.</summary>
public class AclMutationEngineTests
{
    private const SecurityMasks All = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
    private static AclMutationEngine Engine(byte[] bytes, SecurityMasks retrieved = All) => new(SecurityDescriptor.Parse(bytes, retrieved));
    private static CoreAce Rule(uint mask = 0x10, byte type = 0, byte flags = 0) => CoreAce.Read(Ace(type, flags, mask, U1));
    private static Sid Trustee(byte[] bytes)
    {
        Assert.True(Sid.TryRead(bytes, out var sid, out var consumed));
        Assert.Equal(bytes.Length, consumed);
        return sid!;
    }

    public static IEnumerable<object[]> UnsafeDacls()
    {
        yield return new object[] { "unknown ACE", Acl(4, Ace(0x20, 0, 0x10, U1)) };
        yield return new object[] { "callback payload", Acl(4, Ace(9, 0, 0x10, U1, new byte[] { 1, 2, 3, 4 })) };
        yield return new object[] { "unknown flags", Acl(4, Ace(0, 0x20, 0x10, U1)) };
        yield return new object[] { "unexplained ACE payload", Acl(4, Ace(0, 0, 0x10, U1, new byte[] { 1, 2, 3, 4 })) };
        yield return new object[] { "unknown object flags", Acl(4, ObjAce(5, 0, 0x10, 4, null, null, U1)) };
    }

    [Theory]
    [MemberData(nameof(UnsafeDacls))]
    public void Unsupported_acl_mutations_fail_atomically(string reason, byte[] acl)
    {
        _ = reason;
        var bytes = Build(Admins, Admins, acl);
        var engine = Engine(bytes);
        foreach (var operation in Enum.GetValues<AclModification>())
        {
            Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, operation, Rule()));
            Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
            Assert.Equal(bytes, engine.OriginalDescriptor.GetBinaryForm());
            Assert.Equal((SecurityMasks)0, engine.WriteIntent);
        }
    }

    [Theory]
    [MemberData(nameof(UnsafeDacls))]
    public void Owner_and_group_edits_preserve_opaque_acl_bytes(string reason, byte[] acl)
    {
        _ = reason;
        var bytes = Build(Admins, Admins, acl, Acl(4, Ace(0x20, 0, 1, U2)));
        var original = Engine(bytes);
        var updated = original.SetOwner(Trustee(U1)).Engine.SetGroup(Trustee(U2)).Engine;
        Assert.Equal(Trustee(U1), updated.Descriptor.Owner);
        Assert.Equal(Trustee(U2), updated.Descriptor.Group);
        Assert.Equal(acl, AclBytes(updated.Descriptor, 16));
        Assert.Equal(AclBytes(original.Descriptor, 12), AclBytes(updated.Descriptor, 12));
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Group, updated.WriteIntent);
        Assert.Equal(bytes, original.Descriptor.GetBinaryForm());
        Assert.Equal(bytes, updated.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Acl_trailing_bytes_survive_a_successful_edit_exactly()
    {
        var tail = new byte[] { 0xFA, 0xCE, 0xBA, 0xBE };
        var bytes = Build(Admins, Admins, AclWithTail(4, tail, Ace(0, 0, 0x10, U1)));
        var engine = Engine(bytes);
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule(0x20));
        Assert.Equal(tail, result.Engine.Descriptor.Dacl!.Trailing.ToArray());
        Assert.Equal(0x30u, Assert.Single(result.Engine.Descriptor.Dacl.Aces).AccessMask);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Shared_owner_group_storage_is_unshared_before_owner_edit()
    {
        var bytes = Build(Admins, null, Acl(4));
        bytes.AsSpan(4, 4).CopyTo(bytes.AsSpan(8, 4));
        var original = Engine(bytes);
        Assert.True(original.Descriptor.HasOverlappingComponents);
        var result = original.SetOwner(Trustee(U1));
        Assert.False(result.Engine.Descriptor.HasOverlappingComponents);
        Assert.Equal(Trustee(Admins), result.Engine.Descriptor.Group);
        Assert.Equal(Trustee(U1), result.Engine.Descriptor.Owner);
        Assert.Equal(bytes, original.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Owner, result.Engine.WriteIntent);
    }

    [Fact]
    public void Unretrieved_acl_cannot_be_mutated_or_marked_for_write()
    {
        var bytes = WithDacl(Ace(0, 0, 0x10, U1));
        var engine = Engine(bytes, SecurityMasks.Owner);
        Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule()));
        Assert.Equal(AclState.NotRetrieved, engine.Descriptor.DaclState);
        Assert.Equal((SecurityMasks)0, engine.WriteIntent);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Caller_owned_buffers_and_output_buffers_do_not_alias_engine()
    {
        var bytes = WithDacl(Ace(0, 0, 0x10, U1));
        var expected = bytes.ToArray();
        var engine = Engine(bytes);
        Array.Fill(bytes, (byte)0);
        var output = engine.Descriptor.GetBinaryForm();
        Array.Fill(output, (byte)0);
        Assert.Equal(expected, engine.Descriptor.GetBinaryForm());
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule(0x20));
        Assert.Equal(expected, engine.Descriptor.GetBinaryForm());
        Assert.Equal(expected, result.Engine.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(0x30u, Assert.Single(result.Engine.Descriptor.Dacl!.Aces).AccessMask);
    }

    [Fact]
    public void Deterministic_disjoint_mask_add_remove_preserves_other_trustees_and_sections()
    {
        var random = new Random(2262026);
        for (var iteration = 0; iteration < 100; iteration++)
        {
            // Disjoint supported AD rights exercise exact subtraction without inheritance splitting.
            var first = 1u << random.Next(0, 8);
            uint second;
            do { second = 1u << random.Next(0, 8); } while (first == second);
            var other = Ace(0, 0, 0x100, U2);
            var sacl = Acl(4, Ace(2, 0x40, 0x10, U2));
            var bytes = Build(Admins, Admins, Acl(4, Ace(0, 0, first, U1), other), sacl);
            var original = Engine(bytes);
            var added = original.Modify(SecurityMasks.Dacl, AclModification.Add, Rule(second));
            var removed = added.Engine.Modify(SecurityMasks.Dacl, AclModification.Remove, Rule(second));
            Assert.True(removed.ReturnValue);
            Assert.Equal(first, Assert.Single(removed.Engine.Descriptor.Dacl!.Aces.Where(a => a.Sid!.Equals(Trustee(U1)))).AccessMask);
            Assert.Equal(other, Assert.Single(removed.Engine.Descriptor.Dacl.Aces.Where(a => a.Sid!.Equals(Trustee(U2)))).RawBytes.ToArray());
            Assert.Equal(sacl, AclBytes(removed.Engine.Descriptor, 12));
            Assert.Equal(SecurityMasks.Dacl, removed.Engine.WriteIntent);
            Assert.Equal(bytes, original.Descriptor.GetBinaryForm());
            Assert.Equal(bytes, removed.Engine.OriginalDescriptor.GetBinaryForm());
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Unexplained_descriptor_storage_causes_atomic_refusal(bool gap)
    {
        var bytes = Build(Admins, Admins, Acl(4, Ace(0, 0, 0x10, U1)),
            gapBefore: gap ? 4 : 0, tail: gap ? null : new byte[] { 9, 8, 7 });
        var engine = Engine(bytes);
        Assert.Throws<InvalidOperationException>(() => engine.SetOwner(Trustee(U2)));
        Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule(0x20)));
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
        Assert.Equal((SecurityMasks)0, engine.WriteIntent);
    }

    [Fact]
    public void Shared_empty_sacl_and_dacl_are_unshared_before_dacl_mutation()
    {
        var bytes = Build(Admins, Admins, Acl(4), extraControl: SaclPresent);
        bytes.AsSpan(16, 4).CopyTo(bytes.AsSpan(12, 4));
        var engine = Engine(bytes);
        Assert.True(engine.Descriptor.HasOverlappingComponents);
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule());
        Assert.False(result.Engine.Descriptor.HasOverlappingComponents);
        Assert.Equal(AclState.Empty, result.Engine.Descriptor.SaclState);
        Assert.Single(result.Engine.Descriptor.Dacl!.Aces);
        Assert.Equal(SecurityMasks.Dacl, result.Engine.WriteIntent);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Partial_overlap_with_trustee_sid_does_not_change_owner_on_dacl_edit()
    {
        var bytes = Build(null, Admins, Acl(4, Ace(0, 0, 0x10, U1)));
        var daclOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), daclOffset + 16);
        var engine = Engine(bytes);
        Assert.True(engine.Descriptor.HasOverlappingComponents);
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.RemoveSpecific, Rule());
        Assert.False(result.Engine.Descriptor.HasOverlappingComponents);
        Assert.Equal(Trustee(U1), result.Engine.Descriptor.Owner);
        Assert.Equal(AclState.Empty, result.Engine.Descriptor.DaclState);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Acl_size_limit_refuses_growth_without_truncating_tail()
    {
        // Largest ushort-sized ACL: growth by one nonmatching ACE must fail before publication.
        var tail = new byte[ushort.MaxValue - 8 - Ace(0, 0, 0x10, U2).Length];
        Array.Fill(tail, (byte)0xA5);
        var bytes = Build(Admins, Admins, AclWithTail(4, tail, Ace(0, 0, 0x10, U2)));
        var engine = Engine(bytes);
        Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.Add, Rule()));
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
        Assert.Equal((SecurityMasks)0, engine.WriteIntent);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Protection_removes_or_converts_inherited_aces_without_editing_original(bool preserve)
    {
        var explicitAce = Ace(0, 0, 0x10, U1);
        var inheritedAce = Ace(0, 0x12, 0x20, U2);
        var bytes = WithDacl(explicitAce, inheritedAce);
        var engine = Engine(bytes);
        var result = engine.SetProtection(SecurityMasks.Dacl, true, preserve);
        Assert.Equal(0x1000, result.Engine.Descriptor.Control & 0x1000);
        Assert.Equal(preserve ? 2 : 1, result.Engine.Descriptor.Dacl!.Aces.Count);
        Assert.All(result.Engine.Descriptor.Dacl.Aces, a => Assert.Equal(0, a.AceFlags & 0x10));
        Assert.Equal(explicitAce, result.Engine.Descriptor.Dacl.Aces[0].RawBytes.ToArray());
        if (preserve) Assert.Equal(Ace(0, 2, 0x20, U2), result.Engine.Descriptor.Dacl.Aces[1].RawBytes.ToArray());
        Assert.Equal(SecurityMasks.Dacl, result.Engine.WriteIntent);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Unprotect_retains_inherited_ace_and_only_changes_protection_bit()
    {
        var bytes = Build(Admins, Admins, Acl(4, Ace(0, 0x12, 0x10, U1)), extraControl: 0x1000);
        var engine = Engine(bytes);
        var result = engine.SetProtection(SecurityMasks.Dacl, false, false);
        var expected = bytes.ToArray();
        expected[3] &= 0xEF;
        Assert.Equal(expected, result.Engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Dacl, result.Engine.WriteIntent);
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Failed_object_narrowing_is_atomic_and_does_not_record_write_intent()
    {
        // E1 records false for object-specific removal from an unqualified allow.
        var bytes = WithDacl(Ace(0, 0, 0x10, U1));
        var engine = Engine(bytes);
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.Remove,
            CoreAce.Read(ObjAce(5, 0, 0x10, 1, G1, null, U1)));
        Assert.False(result.ReturnValue);
        Assert.False(result.Modified);
        Assert.Same(engine, result.Engine);
        Assert.Equal((SecurityMasks)0, result.Engine.WriteIntent);
        Assert.Equal(bytes, result.Engine.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Successful_no_match_removal_has_no_write_intent()
    {
        // E1 records true even when no rights match; return status is not persistence intent.
        var engine = Engine(WithDacl(Ace(0, 0, 0x20, U1)));
        var result = engine.Modify(SecurityMasks.Dacl, AclModification.Remove, Rule(0x10));
        Assert.True(result.ReturnValue);
        Assert.Same(engine, result.Engine);
        Assert.Equal((SecurityMasks)0, result.Engine.WriteIntent);
    }

    [Theory]
    [InlineData(0)] // Add identical
    [InlineData(1)] // Set identical
    [InlineData(2)] // Reset identical
    public void Identical_rule_operation_is_a_byte_noop(int operation)
    {
        var engine = Engine(WithDacl(Ace(0, 0, 0x10, U1)));
        var result = engine.Modify(SecurityMasks.Dacl, (AclModification)operation, Rule());
        Assert.True(result.ReturnValue);
        Assert.Same(engine, result.Engine);
        Assert.Equal((SecurityMasks)0, result.Engine.WriteIntent);
    }

    [Fact]
    public void Recorded_C2_and_C3_audit_merges_preserve_dacl_and_only_request_sacl_write()
    {
        var engine = Engine(Build(Admins, Admins, Acl(4), Acl(4, Ace(2, 0x40, 0x10, U1))));
        var c2 = engine.Modify(SecurityMasks.Sacl, AclModification.Add, Rule(0x10, 2, 0x80));
        Assert.Equal(Ace(2, 0xC0, 0x10, U1), Assert.Single(c2.Engine.Descriptor.Sacl!.Aces).RawBytes.ToArray());
        var c3 = engine.Modify(SecurityMasks.Sacl, AclModification.Add, Rule(0x20, 2, 0x40));
        Assert.Equal(Ace(2, 0x40, 0x30, U1), Assert.Single(c3.Engine.Descriptor.Sacl!.Aces).RawBytes.ToArray());
        Assert.Equal(AclBytes(engine.Descriptor, 16), AclBytes(c3.Engine.Descriptor, 16));
        Assert.Equal(SecurityMasks.Sacl, c2.Engine.WriteIntent);
        Assert.Equal(SecurityMasks.Sacl, c3.Engine.WriteIntent);
    }

    [Fact]
    public void Recorded_E2_audit_removal_splits_success_from_inherited_failure_scope()
    {
        var engine = Engine(Build(Admins, Admins, Acl(4), Acl(4, Ace(2, 0xC2, 0x10, U1))));
        var result = engine.Modify(SecurityMasks.Sacl, AclModification.Remove, Rule(0x10, 2, 0x80));
        Assert.True(result.ReturnValue);
        Assert.Collection(result.Engine.Descriptor.Sacl!.Aces,
            a => Assert.Equal(Ace(2, 0x42, 0x10, U1), a.RawBytes.ToArray()),
            a => Assert.Equal(Ace(2, 0x8A, 0x10, U1), a.RawBytes.ToArray()));
        Assert.Equal(SecurityMasks.Sacl, result.Engine.WriteIntent);
    }

    [Fact]
    public void Multiple_explicit_sacl_entries_refuse_every_mutation_until_ordering_is_reviewed()
    {
        var bytes = Build(Admins, Admins, Acl(4), Acl(4, Ace(2, 0x40, 0x10, U1), Ace(2, 0x80, 0x20, U2)));
        var engine = Engine(bytes);
        foreach (var operation in Enum.GetValues<AclModification>())
            Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Sacl, operation, Rule(0x10, 2, 0x40)));
        Assert.Throws<InvalidOperationException>(() => engine.Purge(SecurityMasks.Sacl, Trustee(U1)));
        Assert.Throws<InvalidOperationException>(() => engine.SetProtection(SecurityMasks.Sacl, true, true));
        Assert.Equal(bytes, engine.Descriptor.GetBinaryForm());
        Assert.Equal((SecurityMasks)0, engine.WriteIntent);
    }

    private static byte[] AclBytes(SecurityDescriptor descriptor, int offsetField)
    {
        var bytes = descriptor.GetBinaryForm();
        var offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offsetField)));
        var size = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 2));
        return bytes.AsSpan(offset, size).ToArray();
    }
}
