// Framework access-control enum values are portable; no platform implementation is invoked.
#pragma warning disable CA1416
using System.Buffers.Binary;
using System.Security.AccessControl;
using P = AdForLinux.Security.AccessControl;
using Sid = AdForLinux.Security.Principal.SecurityIdentifier;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(17)]
    [InlineData(21)]
    [InlineData(255)]
    public void Custom_ace_preserves_unknown_flags_and_payload_with_offset_and_deep_copy(byte type)
    {
        var opaque = new byte[] { 1, 2, 3, 4, 0xFF, 0, 0xA5, 0x5A };
        var ace = new P.CustomAce((AceType)type, (AceFlags)0xFF, opaque);
        Assert.Same(opaque, ace.GetOpaque()); // Framework intentionally exposes live opaque storage.
        var copy = ace.Copy();
        Assert.IsType<P.CustomAce>(copy);
        Assert.Equal(ace, copy);
        Assert.Equal(ace.GetHashCode(), copy.GetHashCode());
        var buffer = Enumerable.Repeat((byte)0xCC, ace.BinaryLength + 6).ToArray();
        ace.GetBinaryForm(buffer, 3);
        Assert.Equal(new byte[] { 0xCC, 0xCC, 0xCC }, buffer[..3]);
        Assert.Equal(new byte[] { 0xCC, 0xCC, 0xCC }, buffer[^3..]);
        Assert.Equal(ace, P.GenericAce.CreateFromBinaryForm(buffer, 3));
        Assert.True(ace.IsInherited);
        Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, ace.InheritanceFlags);
        Assert.Equal(PropagationFlags.InheritOnly | PropagationFlags.NoPropagateInherit, ace.PropagationFlags);
        Assert.Equal(AuditFlags.Success | AuditFlags.Failure, ace.AuditFlags);
        opaque[0] ^= 0xFF;
        Assert.NotEqual(ace, copy);
        Assert.Equal(1, ((P.CustomAce)copy).GetOpaque()![0]);
        ace.AceFlags = AceFlags.None;
        Assert.False(ace.IsInherited);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(16)]
    public void Custom_ace_rejects_defined_type(int type) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new P.CustomAce((AceType)type, AceFlags.None, null));

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(65532)]
    public void Custom_ace_rejects_invalid_payload_atomically(int length)
    {
        var ace = new P.CustomAce((AceType)255, AceFlags.None, new byte[4]);
        var before = AceBytes(ace);
        Assert.Throws<ArgumentOutOfRangeException>(() => ace.SetOpaque(new byte[length]));
        Assert.Equal(before, AceBytes(ace));
    }

    [Fact]
    public void Custom_ace_maximum_aligned_payload_and_null_are_supported()
    {
        var ace = new P.CustomAce((AceType)255, AceFlags.None, new byte[P.CustomAce.MaxOpaqueLength & ~3]);
        Assert.Equal(65532, ace.BinaryLength);
        Assert.Equal(ace, ace.Copy());
        ace.SetOpaque(null);
        Assert.Null(ace.GetOpaque());
        Assert.Equal(4, ace.BinaryLength);
        Assert.Equal(ace, ace.Copy());
    }

    [Fact]
    public void Ace_binary_bounds_fail_before_writing_and_parse_rejects_bad_lengths()
    {
        var ace = new P.CustomAce((AceType)255, AceFlags.None, new byte[4]);
        Assert.Throws<ArgumentNullException>(() => ace.GetBinaryForm(null!, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ace.GetBinaryForm(new byte[8], -1));
        var buffer = Enumerable.Repeat((byte)0xCC, 8).ToArray();
        Assert.Throws<ArgumentOutOfRangeException>(() => ace.GetBinaryForm(buffer, 1));
        Assert.All(buffer, b => Assert.Equal(0xCC, b));
        Assert.Throws<ArgumentNullException>(() => P.GenericAce.CreateFromBinaryForm(null!, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => P.GenericAce.CreateFromBinaryForm(new byte[4], -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => P.GenericAce.CreateFromBinaryForm(new byte[3], 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => P.GenericAce.CreateFromBinaryForm(new byte[] { 255, 0, 8, 0 }, 0));
        Assert.Throws<ArgumentException>(() => P.GenericAce.CreateFromBinaryForm(new byte[] { 255, 0, 5, 0, 1 }, 0));
        Assert.Throws<ArgumentException>(() => P.GenericAce.CreateFromBinaryForm(new byte[] { 255, 0, 0, 0 }, 0));
    }

    [Theory]
    [InlineData(AceQualifier.AccessAllowed, false)]
    [InlineData(AceQualifier.AccessDenied, false)]
    [InlineData(AceQualifier.SystemAudit, false)]
    [InlineData(AceQualifier.SystemAlarm, false)]
    [InlineData(AceQualifier.AccessAllowed, true)]
    [InlineData(AceQualifier.AccessDenied, true)]
    [InlineData(AceQualifier.SystemAudit, true)]
    [InlineData(AceQualifier.SystemAlarm, true)]
    public void Qualified_families_roundtrip_trailing_bytes_and_deep_copy(AceQualifier qualifier, bool callback)
    {
        var sid = new Sid("S-1-5-21-1-2-3-1001");
        var opaque = new byte[] { 0xAA, 0, 0xBB, 0 };
        foreach (P.QualifiedAce ace in new P.QualifiedAce[]
        {
            new P.CommonAce((AceFlags)0xDF, qualifier, unchecked((int)0x80000001), sid, callback, opaque),
            new P.ObjectAce((AceFlags)0xDF, qualifier, 0x30, sid,
                ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
                Guid.Parse("11111111-1111-1111-1111-111111111111"), Guid.Empty, callback, opaque),
        })
        {
            var parsed = P.GenericAce.CreateFromBinaryForm(AceBytes(ace), 0);
            Assert.Equal(ace.GetType(), parsed.GetType());
            Assert.Equal(ace, parsed);
            Assert.Equal(callback, ((P.QualifiedAce)parsed).IsCallback);
            Assert.Equal(opaque, ((P.QualifiedAce)parsed).GetOpaque());
            var copy = (P.QualifiedAce)ace.Copy();
            copy.GetOpaque()![0] ^= 0xFF;
            Assert.NotEqual(ace, copy);
            var before = AceBytes(ace);
            Assert.Throws<ArgumentNullException>(() => ace.SecurityIdentifier = null!);
            Assert.Equal(before, AceBytes(ace));
        }
    }

    [Fact]
    public void Compound_ace_roundtrips_and_mutable_fields_affect_equality()
    {
        var ace = new P.CompoundAce(AceFlags.Inherited, 0x12345678, CompoundAceType.Impersonation, new Sid("S-1-1-0"));
        var copy = Assert.IsType<P.CompoundAce>(ace.Copy());
        Assert.True(ace == copy);
        copy.AccessMask ^= 1;
        Assert.True(ace != copy);
        copy.CompoundAceType = (CompoundAceType)0x1234;
        Assert.Equal(copy, copy.Copy());
        copy.SecurityIdentifier = new Sid("S-1-5-32-544");
        Assert.Equal(copy, copy.Copy());
        Assert.False(ace.Equals(null));
        Assert.False(ace.Equals("ace"));
    }

    [Fact]
    public void Object_ace_unknown_object_flags_and_guid_presence_are_preserved()
    {
        var ace = new P.ObjectAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10, new Sid("S-1-1-0"),
            unchecked((ObjectAceFlags)0x80000003), Guid.Empty, Guid.Empty, false, new byte[] { 1, 2, 3, 4 });
        var parsed = Assert.IsType<P.ObjectAce>(ace.Copy());
        Assert.Equal(ace, parsed);
        Assert.Equal(unchecked((ObjectAceFlags)0x80000003), parsed.ObjectAceFlags);
        parsed.ObjectAceFlags = ObjectAceFlags.None;
        Assert.Equal(ace.BinaryLength - 32, parsed.BinaryLength);
    }

    [Fact]
    public void Ace_hash_matches_binary_word_xor()
    {
        var ace = new P.CustomAce((AceType)255, (AceFlags)0xA5, new byte[] { 1, 2, 3, 4 });
        var bytes = AceBytes(ace);
        Assert.Equal(BinaryPrimitives.ReadInt32LittleEndian(bytes) ^ BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4)), ace.GetHashCode());
    }

    private static byte[] AceBytes(P.GenericAce ace)
    {
        var bytes = new byte[ace.BinaryLength];
        ace.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
