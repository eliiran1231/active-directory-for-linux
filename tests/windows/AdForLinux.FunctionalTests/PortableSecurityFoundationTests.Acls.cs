#pragma warning disable CA1416 // Framework enum values only.
using System.Collections;
using System.Security.AccessControl;
using P = AdForLinux.Security.AccessControl;
using Sid = AdForLinux.Security.Principal.SecurityIdentifier;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Raw_acl_keeps_live_ace_references_while_common_acl_exposes_copies()
    {
        var raw = new P.RawAcl(4, 2);
        var ace = new P.CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10, new Sid("S-1-1-0"), false, null);
        raw.InsertAce(0, ace);
        Assert.Same(ace, raw[0]);
        ace.AccessMask = 0x20;
        var dacl = new P.DiscretionaryAcl(true, true, raw);
        Assert.NotSame(ace, dacl[0]);
        Assert.Equal(0x20, Assert.IsType<P.CommonAce>(dacl[0]).AccessMask);
        ace.AccessMask = 0x40;
        var detached = Assert.IsType<P.CommonAce>(dacl[0]);
        detached.AccessMask = 0x80;
        Assert.Equal(0x20, Assert.IsType<P.CommonAce>(dacl[0]).AccessMask);
        Assert.Throws<NotSupportedException>(() => dacl[0] = ace);
        var target = new P.GenericAce[1]; raw.CopyTo(target, 0);
        Assert.Same(ace, target[0]);
        dacl.CopyTo(target, 0);
        Assert.NotSame(dacl[0], target[0]);
    }

    [Fact]
    public void Raw_acl_roundtrips_unknown_aces_and_detects_capacity_overflow_atomically()
    {
        var raw = new P.RawAcl(4, 0);
        raw.InsertAce(0, new P.CustomAce((AceType)255, (AceFlags)0x20, new byte[] { 1, 2, 3, 4 }));
        var before = AclBytes(raw);
        var parsed = new P.RawAcl(before, 0);
        Assert.Equal(before, AclBytes(parsed));
        var huge = new P.CustomAce((AceType)255, AceFlags.None, new byte[65528]);
        Assert.Throws<OverflowException>(() => raw.InsertAce(1, huge));
        Assert.Equal(before, AclBytes(raw));
        Assert.Throws<OverflowException>(() => raw[0] = huge);
        Assert.Equal(before, AclBytes(raw));
    }

    [Fact]
    public void Acl_enumerator_and_collection_validate_state_and_bounds()
    {
        var raw = new P.RawAcl(2, 0);
        var iterator = raw.GetEnumerator();
        Assert.Throws<InvalidOperationException>(() => iterator.Current);
        Assert.False(iterator.MoveNext());
        Assert.Throws<InvalidOperationException>(() => ((IEnumerator)iterator).Current);
        raw.InsertAce(0, new P.CustomAce((AceType)255, AceFlags.None, null));
        iterator.Reset();
        Assert.True(iterator.MoveNext());
        Assert.Same(raw[0], iterator.Current);
        Assert.False(iterator.MoveNext());
        Assert.Throws<InvalidOperationException>(() => iterator.Current);
        Assert.False(raw.IsSynchronized);
        Assert.Same(raw, raw.SyncRoot);
        Assert.Throws<RankException>(() => ((ICollection)raw).CopyTo(new P.GenericAce[1, 1], 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => raw.CopyTo(new P.GenericAce[1], -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => raw.CopyTo(Array.Empty<P.GenericAce>(), 0));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Common_acl_import_compaction_does_not_edit_raw_source(bool audit)
    {
        var raw = new P.RawAcl(4, 3);
        var qualifier = audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed;
        var flags = audit ? AceFlags.SuccessfulAccess : AceFlags.None;
        foreach (var mask in new[] { 0x10, 0x20, 0x40 }) raw.InsertAce(raw.Count, new P.CommonAce(flags, qualifier, mask, new Sid("S-1-1-0"), false, null));
        var before = AclBytes(raw);
        P.CommonAcl acl = audit ? new P.SystemAcl(true, true, raw) : new P.DiscretionaryAcl(true, true, raw);
        Assert.True(acl.IsCanonical);
        Assert.True(acl.IsDS);
        Assert.True(acl.IsContainer);
        Assert.Equal(2, acl.Count); // Native import makes one adjacent compaction pass.
        Assert.Equal(before, AclBytes(raw));
        var projected = AclBytes(acl);
        Assert.Equal(projected, AclBytes(acl));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Noncanonical_acl_rejects_mutation_without_changing_original(bool audit)
    {
        var sid = new Sid("S-1-1-0");
        var raw = new P.RawAcl(4, 2);
        var qualifier = audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed;
        var flags = audit ? AceFlags.SuccessfulAccess : AceFlags.None;
        raw.InsertAce(0, new P.CommonAce(flags | AceFlags.Inherited, qualifier, 0x10, sid, false, null));
        raw.InsertAce(1, new P.CommonAce(flags, qualifier, 0x20, sid, false, null));
        P.CommonAcl acl = audit ? new P.SystemAcl(true, true, raw) : new P.DiscretionaryAcl(true, true, raw);
        Assert.False(acl.IsCanonical);
        var before = AclBytes(acl);
        Assert.Throws<InvalidOperationException>(() => acl.Purge(sid));
        Assert.Throws<InvalidOperationException>(() => acl.RemoveInheritedAces());
        Assert.Equal(before, AclBytes(acl));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Known_common_acl_mutations_succeed_then_remove_explicit_and_inherited_independently(bool audit)
    {
        var sid = new Sid("S-1-1-0");
        P.CommonAcl acl = audit ? new P.SystemAcl(true, true, 0) : new P.DiscretionaryAcl(true, true, 0);
        if (acl is P.DiscretionaryAcl dacl)
        {
            dacl.AddAccess(AccessControlType.Allow, sid, 0x10, InheritanceFlags.None, PropagationFlags.None);
            dacl.AddAccess(AccessControlType.Allow, sid, 0x20, InheritanceFlags.None, PropagationFlags.None);
            Assert.Equal(0x30, Assert.IsType<P.CommonAce>(dacl[0]).AccessMask);
            Assert.True(dacl.RemoveAccess(AccessControlType.Allow, sid, 0x10, InheritanceFlags.None, PropagationFlags.None));
            Assert.Equal(0x20, Assert.IsType<P.CommonAce>(dacl[0]).AccessMask);
            dacl.RemoveAccessSpecific(AccessControlType.Allow, sid, 0x20, InheritanceFlags.None, PropagationFlags.None);
        }
        else
        {
            var sacl = (P.SystemAcl)acl;
            sacl.AddAudit(AuditFlags.Success, sid, 0x10, InheritanceFlags.None, PropagationFlags.None);
            sacl.AddAudit(AuditFlags.Success, sid, 0x20, InheritanceFlags.None, PropagationFlags.None);
            Assert.Equal(0x30, Assert.IsType<P.CommonAce>(sacl[0]).AccessMask);
            Assert.True(sacl.RemoveAudit(AuditFlags.Success, sid, 0x10, InheritanceFlags.None, PropagationFlags.None));
            Assert.Equal(0x20, Assert.IsType<P.CommonAce>(sacl[0]).AccessMask);
            sacl.RemoveAuditSpecific(AuditFlags.Success, sid, 0x20, InheritanceFlags.None, PropagationFlags.None);
        }
        Assert.Equal(0, acl.Count);
    }

    private static byte[] AclBytes(P.GenericAcl acl)
    {
        var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes;
    }
}
