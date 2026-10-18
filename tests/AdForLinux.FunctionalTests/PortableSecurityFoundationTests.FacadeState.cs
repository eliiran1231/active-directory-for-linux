#pragma warning disable CA1416
using System.Security.AccessControl;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static readonly Dictionary<int, string> FacadePreservationRefusals = new()
    {
        [3509] = "7389F4A02D93DEF71C546E6EFED9EC83DB6510FA739B6B06E319A21FFF0E7D01",
        [3510] = "A5F3687145D2FB4EC6285F51B444FF4B8EB6DBCB3D1835DA13DD906A7D1B5DE2",
        [3511] = "7031D169FBE3BAD57B5F805752D22E089A061E85EAFE82394971144A437AF4D4",
        [3512] = "7B351300E5A1B8C7C8B38C67E87E9A5ABED0FE20CB2F50C8D083DAE2296673F6",
        [3513] = "CD5692F41D0F471CF159248B49A2D2425EAC7397EFA2C5525035D8ADE7E1AA1C",
        [3514] = "1361CBBB2DFD091C3979A0F53DEEA0F9ADC866606DD3516BD88DD79F7DEC4A30",
        [3515] = "7D71616EB2CB79C9C85C4A997DD9898096D2F1B822F46694495663701776DCDD",
        [3516] = "11CC6CA41A9198C114170C1304E88376216E6068B3C8E21E5AE312B0E4ECC719",
    };

    private static bool AssertFacadePreservationRefusal(JsonElement row, Exception? exception)
    {
        var id = row.GetProperty("Case").GetInt32();
        if (!FacadePreservationRefusals.TryGetValue(id, out var hash)) return false;
        Assert.Equal("FacadeEnumerationObjects", row.GetProperty("Operation").GetString());
        Assert.Equal(id - 3501, row.GetProperty("Arguments").GetProperty("Scenario").GetInt32());
        Assert.Equal(hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(row)))));
        Assert.Equal(JsonValueKind.Null, row.GetProperty("ExceptionType").ValueKind);
        Assert.Equal(JsonValueKind.Object, row.GetProperty("Outcome").ValueKind);
        Assert.Equal("Section replacement would discard unreviewed ACL data.", Assert.IsType<InvalidOperationException>(exception).Message);
        return true;
    }

    [Fact]
    public void Facade_preservation_refusals_are_exactly_the_eight_recorded_callback_clears()
    {
        Assert.Equal(Enumerable.Range(3509, 8), FacadePreservationRefusals.Keys.Order());
        foreach (var recording in ClosureRecordings())
        {
            using var document = JsonDocument.Parse((string)recording[2]);
            var row = document.RootElement;
            if (FacadePreservationRefusals.ContainsKey(row.GetProperty("Case").GetInt32()))
                Assert.True(AssertFacadePreservationRefusal(row, Record.Exception(() => FacadeContracts.Execute("FacadeEnumerationObjects", row.GetProperty("Arguments").GetProperty("Scenario").GetInt32()))));
        }
    }

    [Fact]
    public void Callback_acl_clear_refuses_atomically_and_retains_original_payload()
    {
        var raw = Build(U1, U1, Acl(4, Ace(9, 0, 16, U1)), null);
        var descriptor = new A.CommonSecurityDescriptor(true, true, raw, 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        var originalAcl = descriptor.DiscretionaryAcl;
        var state = descriptor.MutationState;
        var observable = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<InvalidOperationException>(() => descriptor.DiscretionaryAcl = null);
        Assert.Same(state, descriptor.MutationState);
        Assert.Same(originalAcl, descriptor.DiscretionaryAcl);
        Assert.Equal(raw, descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(observable, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    private static void AssertFacadeAtomicFailure(JsonElement row, object? outcome)
    {
        // Actual Windows case 3398: invalid enum 6 manufactures an empty SACL before
        // throwing. The approved transaction policy requires complete rollback instead.
        Assert.Equal("FacadeModify", row.GetProperty("Operation").GetString());
        Assert.Equal(55, row.GetProperty("Arguments").GetProperty("Scenario").GetInt32());
        var expected = JsonNode.Parse(row.GetProperty("Outcome").GetRawText())!;
        Assert.Equal("System.ArgumentOutOfRangeException", expected["Result"]!["ExceptionType"]!.GetValue<string>());
        Assert.Equal("modification", expected["Result"]!["ParamName"]!.GetValue<string>());
        Assert.Equal("0100148014000000200000002C000000340000000101000000000001000000000101000000000001000000000400080000000000020030000200000000001400100000000101000000000001000000000012140020000000010100000000000512000000", expected["State"]!["Hex"]!.GetValue<string>());
        // The pre-edit image is independently recorded by FacadeSharing scenario 3.
        expected["State"]!["Hex"] = "010004801400000020000000000000002C000000010100000000000100000000010100000000000100000000020030000200000000001400100000000101000000000001000000000012140020000000010100000000000512000000";
        Assert.Equal(expected.ToJsonString(), JsonSerializer.SerializeToNode(outcome)!.ToJsonString());
    }

    [Fact]
    public void Shared_facade_uses_retained_raw_contributors_without_transfer_of_dirty_flags()
    {
        var raw = Build(Admins, Admins, Acl(4, Ace(0, 0, 0x10, U1), Ace(0, 0, 0x20, U1), Ace(0, 0, 0x40, U1), Ace(0, 0, 0x80, U1)), Acl(4));
        var descriptor = new A.CommonSecurityDescriptor(true, true, raw, 0);
        var first = new FacadeContracts.Wrapper(descriptor);
        var second = new FacadeContracts.Wrapper(descriptor);
        var acl = descriptor.DiscretionaryAcl!;
        Assert.Equal(raw, descriptor.MutationState.Descriptor.GetBinaryForm());
        var sid = new SecurityIdentifier(U1, 0);
        acl.RemoveAccess(AccessControlType.Allow, sid, 0x10, 0, 0);
        Assert.Equal(new uint[] { 0x20, 0x40, 0x80 }, descriptor.MutationState.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
        Assert.Equal(new[] { 0x20, 0xc0 }, Enumerable.Range(0, acl.Count).Select(i => ((A.KnownAce)acl[i]).AccessMask));
        var staged = descriptor.MutationState;
        var sharedDescriptor = new A.CommonSecurityDescriptor(true, true, 0, null, null, null, acl);
        Assert.Equal(new uint[] { 0x20, 0x40, 0x80 }, sharedDescriptor.MutationState.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
        first.SetOwner(new SecurityIdentifier(U2, 0));
        first.SetAccessRuleProtection(true, true);
        acl.RemoveAccessSpecific(AccessControlType.Allow, sid, 0xc0, 0, 0);
        Assert.Equal(new uint[] { 0x20 }, descriptor.MutationState.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
        Assert.Equal(new uint[] { 0x20 }, sharedDescriptor.MutationState.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
        Assert.Same(acl, descriptor.DiscretionaryAcl);
        Assert.Equal(new[] { true, false, true, false }, first.Flags());
        Assert.Equal(new[] { false, false, false, false }, second.Flags());
        Assert.Equal(raw, descriptor.MutationState.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(new uint[] { 0x20, 0x40, 0x80 }, staged.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
    }

    [Fact]
    public void Wrapper_compatibility_locks_remain_independent_across_threads()
    {
        var descriptor = new A.CommonSecurityDescriptor(true, true, "D:");
        var first = new FacadeContracts.Wrapper(descriptor);
        var second = new FacadeContracts.Wrapper(descriptor);
        using var finished = new ManualResetEventSlim();
        Exception? failure = null;
        var worker = new Thread(() =>
        {
            try
            {
                second.EnterWrite();
                try { second.SetFlag(0, true); }
                finally { second.ExitWrite(); }
            }
            catch (Exception error) { failure = error; }
            finally { finished.Set(); }
        });
        // Keep A's thread-affine compatibility lock on this thread throughout.
        first.EnterRead();
        bool independent;
        try { worker.Start(); independent = finished.Wait(TimeSpan.FromSeconds(5)); }
        finally { first.ExitRead(); }
        Assert.True(worker.Join(TimeSpan.FromSeconds(5)));
        Assert.Null(failure);
        Assert.True(independent, "Wrapper B's lock incorrectly waited for wrapper A.");
        Assert.False(first.Flags()[0]);
        Assert.True(second.Flags()[0]);
    }

    [Fact]
    public void Caught_inner_failure_rolls_back_to_its_savepoint()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(2, 0x40, 16, U1)));
        var descriptor = new A.CommonSecurityDescriptor(true, true, raw, 0);
        A.FacadeMutation.Run(() =>
        {
            descriptor.Owner = new SecurityIdentifier(U2, 0);
            var staged = descriptor.MutationState;
            var acl = descriptor.SystemAcl;
            Assert.Throws<InvalidOperationException>(() => descriptor.SystemAcl = null);
            Assert.Same(staged, descriptor.MutationState);
            Assert.Same(acl, descriptor.SystemAcl);
        });
        Assert.Equal(new SecurityIdentifier(U2, 0), descriptor.Owner);
        Assert.Equal(SecurityMasks.Owner, descriptor.MutationState.WriteIntent);
    }

    [Fact]
    public void Facade_dirty_flag_is_not_raw_write_intent_and_identity_copies_are_detached()
    {
        var descriptor = new A.CommonSecurityDescriptor(true, true, "O:WDD:(A;;RP;;;WD)");
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        var original = descriptor.MutationState;
        wrapper.SetOwner(new SecurityIdentifier("S-1-1-0"));
        Assert.True(wrapper.Flags()[0]);
        Assert.Same(original, descriptor.MutationState);
        Assert.Equal(SecurityMasks.None, descriptor.MutationState.WriteIntent);
        Assert.Equal(0, descriptor.MutationVersion);
        var copy = new A.CommonSecurityDescriptor(true, true, wrapper.GetSecurityDescriptorBinaryForm(), 0);
        Assert.NotSame(descriptor.MutationState, copy.MutationState);
        Assert.Equal(SecurityMasks.None, copy.MutationState.WriteIntent);
        copy.Owner = new SecurityIdentifier("S-1-5-18");
        Assert.Equal("S-1-1-0", descriptor.Owner!.Value);
    }

    [Fact]
    public void Wrapper_read_snapshots_and_pending_sections_do_not_transfer_with_shared_data()
    {
        var descriptor = new A.CommonSecurityDescriptor(true, true, "O:WDD:");
        var first = new FacadeContracts.Wrapper(descriptor);
        descriptor.Owner = new SecurityIdentifier("S-1-5-18");
        var second = new FacadeContracts.Wrapper(descriptor);
        Assert.Equal(SecurityMasks.Owner, first.PendingWriteSections);
        Assert.Equal(SecurityMasks.None, second.PendingWriteSections);
        Assert.Equal("S-1-1-0", first.OriginalReadSnapshot!.Owner!.ToString());
        Assert.Equal("S-1-5-18", second.OriginalReadSnapshot!.Owner!.ToString());
        descriptor.Group = new SecurityIdentifier("S-1-1-0");
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Group, first.PendingWriteSections);
        Assert.Equal(SecurityMasks.Group, second.PendingWriteSections);
        Assert.Equal(new[] { false, false, false, false }, first.Flags());
        Assert.Equal(new[] { false, false, false, false }, second.Flags());
    }

    [Fact]
    public void Unsafe_shared_acl_edit_rolls_back_every_descriptor_and_facade_reference()
    {
        var aclBytes = Acl(4, Ace(0, 0, 16, U1));
        var original = Build(Admins, Admins, aclBytes, null).Concat(new byte[] { 0xde, 0xad, 0xbe, 0xef }).ToArray();
        // Register the safe owner first, so its staged update must be rolled back
        // when the second owner's unexplained trailer prevents ACL resizing.
        var first = new A.CommonSecurityDescriptor(true, true, Build(Admins, Admins, aclBytes, null), 0);
        var shared = first.DiscretionaryAcl!;
        var second = new A.CommonSecurityDescriptor(true, true, original, 0);
        second.DiscretionaryAcl = shared;
        var w1 = new FacadeContracts.Wrapper(first); var w2 = new FacadeContracts.Wrapper(second);
        var before1 = first.MutationState; var before2 = second.MutationState;
        var observable = w1.GetSecurityDescriptorBinaryForm();
        Assert.Throws<InvalidOperationException>(() => shared.AddAccess(AccessControlType.Allow, new SecurityIdentifier(U2, 0), 32, 0, 0));
        Assert.Same(before1, first.MutationState); Assert.Same(before2, second.MutationState);
        Assert.Equal(original, second.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(observable, w1.GetSecurityDescriptorBinaryForm());
        Assert.Same(shared, first.DiscretionaryAcl); Assert.Same(shared, second.DiscretionaryAcl);
        Assert.Equal(new[] { false, false, false, false }, w1.Flags());
        Assert.Equal(new[] { false, false, false, false }, w2.Flags());
    }

    [Fact]
    public void Binary_import_keeps_opaque_opposite_acl_and_failed_section_replacement_is_atomic()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(2, 0x40, 16, U1)));
        var descriptor = new A.CommonSecurityDescriptor(true, true, raw, 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        var initial = descriptor.MutationState;
        wrapper.SetOwner(new SecurityIdentifier(U2, 0));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, descriptor.MutationState.Descriptor.Sacl!.Trailing.ToArray());
        var before = descriptor.MutationState; var flags = wrapper.Flags();
        Assert.Throws<InvalidOperationException>(() => wrapper.SetSecurityDescriptorSddlForm("O:SYG:WDD:S:", AccessControlSections.All));
        Assert.Same(before, descriptor.MutationState);
        Assert.Equal(flags, wrapper.Flags());
        Assert.Equal(new SecurityIdentifier(U2, 0), descriptor.Owner);
        Assert.Equal(raw, initial.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Section_setter_refuses_unassignable_incoming_storage_without_dirtying_wrapper()
    {
        var wrapper = new FacadeContracts.Wrapper();
        var before = wrapper.GetSecurityDescriptorBinaryForm();
        var source = Build(U1, U1, Acl(4), null).Concat(new byte[] { 0x5a }).ToArray();
        Assert.Throws<NotSupportedException>(() => wrapper.SetSecurityDescriptorBinaryForm(source));
        Assert.Equal(before, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        var imported = new A.CommonSecurityDescriptor(true, true, new A.RawSecurityDescriptor(source, 0));
        Assert.Equal(source, imported.MutationState.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Supplied_acl_keeps_raw_tail_and_missing_resolver_cannot_leave_a_revision_upgrade()
    {
        var acl = new A.DiscretionaryAcl(true, true, new A.RawAcl(AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(0, 0, 16, U1)), 0));
        var preserved = new A.CommonSecurityDescriptor(true, true, 0, null, null, null, acl);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, preserved.MutationState.Descriptor.Dacl!.Trailing.ToArray());
        Assert.Throws<InvalidOperationException>(() => acl.Purge(new SecurityIdentifier(U1, 0)));

        var descriptor = new A.CommonSecurityDescriptor(true, true, "D:(A;;RP;;;WD)");
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        var originalAcl = descriptor.DiscretionaryAcl;
        var before = descriptor.MutationState;
        var rule = new FacadeContracts.AR(new NTAccount("EXAMPLE", "Alice"), 16, false, 0, 0, AccessControlType.Allow, G1, Guid.Empty);
        Assert.Throws<NotSupportedException>(() => wrapper.ModifyAccessRule(AccessControlModification.Add, rule, out _));
        Assert.Same(originalAcl, descriptor.DiscretionaryAcl);
        Assert.Same(before, descriptor.MutationState);
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Audit_section_changes_do_not_modify_the_raw_absent_or_null_dacl(bool present)
    {
        var descriptor = new A.CommonSecurityDescriptor(true, true, present ? ControlFlags.DiscretionaryAclPresent : 0, null, null, null, null);
        var before = descriptor.MutationState.Descriptor.DaclState;
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        wrapper.SetSecurityDescriptorSddlForm("S:(AU;SA;RP;;;WD)", AccessControlSections.Audit);
        Assert.Equal(before, descriptor.MutationState.Descriptor.DaclState);
        Assert.Equal(SecurityMasks.Sacl, descriptor.MutationState.WriteIntent);
        Assert.Equal(new[] { false, false, false, true }, wrapper.Flags());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Extension_callbacks_do_not_hold_the_shared_mutation_gate(bool factory)
    {
        var descriptor = new A.CommonSecurityDescriptor(true, true, "O:WDD:(A;;RP;;;WD)");
        using var peerReady = new ManualResetEventSlim();
        using var insideHook = new ManualResetEventSlim();
        using var peerDone = new ManualResetEventSlim();
        var peer = new FacadeContracts.Wrapper(descriptor);
        var wrapper = new CallbackWrapper(descriptor, factory, () =>
        {
            insideHook.Set();
            return peerDone.Wait(TimeSpan.FromSeconds(5));
        });
        Exception? failure = null;
        var worker = new Thread(() =>
        {
            try
            {
                peer.EnterWrite();
                try
                {
                    peerReady.Set();
                    if (!insideHook.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException();
                    peer.SetOwner(new SecurityIdentifier("S-1-5-18"));
                }
                finally { peer.ExitWrite(); }
            }
            catch (Exception error) { failure = error; }
            finally { peerDone.Set(); }
        });
        worker.Start();
        try
        {
            Assert.True(peerReady.Wait(TimeSpan.FromSeconds(5)));
            if (factory) Assert.Single(wrapper.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<A.AuthorizationRule>());
            else Assert.True(wrapper.ModifyAccessRule(AccessControlModification.Add,
                new FacadeContracts.AR(new SecurityIdentifier("S-1-1-0"), 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty), out _));
        }
        finally { insideHook.Set(); Assert.True(worker.Join(TimeSpan.FromSeconds(10))); }
        Assert.Null(failure);
        Assert.True(wrapper.SawPeerProgress, "A callback held the shared state gate while its peer needed to mutate.");
        Assert.Equal("S-1-5-18", descriptor.Owner!.Value);
    }

    private sealed class CallbackWrapper(A.CommonSecurityDescriptor descriptor, bool factory, Func<bool> progress)
        : FacadeContracts.Wrapper(descriptor)
    {
        internal bool SawPeerProgress;
        protected override bool ModifyAccess(AccessControlModification modification, A.AccessRule rule, out bool modified)
        {
            SawPeerProgress = progress(); modified = false; return true;
        }
        public override A.AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
        {
            if (factory) SawPeerProgress = progress();
            return base.AccessRuleFactory(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, type);
        }
    }
}
