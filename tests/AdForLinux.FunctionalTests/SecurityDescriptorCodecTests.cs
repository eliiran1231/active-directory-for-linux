using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Offline tests for the internal security-descriptor codec. No directory is used. Inputs are
/// built independently (see <see cref="SecurityDescriptorFixtures"/>) or are descriptors that
/// Microsoft System.DirectoryServices 9.0.0 serialized in the offline Windows oracle.
/// </summary>
public class SecurityDescriptorCodecTests
{
    private const SecurityMasks All = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
    private static readonly byte[] AppData = { 0x61, 0x72, 0x74, 0x78 };
    private static readonly byte[] LabelSid = Convert.FromHexString("010100000000001000200000");

    private static readonly Dictionary<string, byte[]> Corpus = new()
    {
        ["empty DACL"] = WithDacl(),
        ["populated DACL"] = WithDacl(Ace(0x00, 0, 0x10, Everyone)),
        ["absent DACL"] = Build(Admins, Admins, null),
        ["NULL DACL"] = Build(Admins, Admins, null, nullDacl: true),
        ["no owner or group"] = Build(null, null, Acl(4)),
        ["SACL and DACL"] = Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)), sacl: Acl(4, Ace(0x02, 0x40, 0x10, U1))),
        ["object ACEs with flags 0-3"] = WithDacl(
            ObjAce(0x06, 0, 0x20, 2, null, G2, U2),
            ObjAce(0x05, 0, 0x10, 0, null, null, U1),
            ObjAce(0x05, 0, 0x10, 1, G1, null, U1),
            ObjAce(0x05, 0x02, 0x10, 3, G1, G2, U1)),
        ["object ACE with present all-zero GUID"] = WithDacl(ObjAce(0x05, 0, 0x10, 1, Guid.Empty, null, U1)),
        ["callback ACE 0x09 with payload"] = WithDacl(Ace(0x09, 0, 0x10, U1, AppData)),
        ["callback object ACE 0x0B with payload"] = WithDacl(ObjAce(0x0B, 0, 0x10, 1, G1, null, U1, AppData)),
        ["unknown ACE type 0x20"] = WithDacl(Ace(0x20, 0, 0x10, U1)),
        ["unknown object flag 0x4"] = WithDacl(ObjAce(0x05, 0, 0x10, 5, G1, null, U1)),
        ["ACE with trailing bytes"] = WithDacl(Ace(0x00, 0, 0x10, U1, new byte[4])),
        ["ACL with trailing bytes"] = Build(Admins, Admins, AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(0x00, 0, 0x10, U1))),
        ["ACL revision 2 with object ACE"] = Build(Admins, Admins, Acl(2, ObjAce(0x05, 0, 0x10, 1, G1, null, U1))),
        ["unknown ACE flag 0x20"] = WithDacl(Ace(0x00, 0x20, 0x10, U1)),
        ["unknown control bits"] = Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)), extraControl: 0x0540),
        ["resource-manager control byte"] = Build(Admins, Admins, Acl(4), extraControl: 0x4000, sbz1: 0x5A),
        ["mandatory label ACE in SACL"] = Build(Admins, Admins, Acl(4), sacl: Acl(2, Ace(0x11, 0, 1, LabelSid))),
        ["audit ACE inside DACL"] = WithDacl(Ace(0x02, 0x40, 0x10, U1)),
        ["inactive InheritOnly ACE"] = WithDacl(Ace(0x01, 0, 0x20, U2), Ace(0x00, 0x08, 0x10, U1), Ace(0x00, 0, 0x04, U2)),
        ["non-canonical allow before deny"] = WithDacl(Ace(0x00, 0, 0x10, U1), Ace(0x01, 0, 0x10, U2)),
        ["DACL before owner and group"] = Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)),
            order: new[] { Part.Dacl, Part.Owner, Part.Group }),
        ["gaps before every component"] = Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)), sacl: Acl(4), gapBefore: 4),
        ["bytes after the last component"] = Build(Admins, Admins, Acl(4), tail: new byte[] { 9, 9, 9 }),
        ["DACL data without present bit"] = ClearControl(WithDacl(Ace(0x00, 0, 0x10, U1)), DaclPresent),
        // Descriptors serialized by Microsoft System.DirectoryServices 9.0.0 (offline Windows oracle).
        ["Microsoft: deny/allow/object ordering (D1)"] = Convert.FromHexString(
            "010004801400000024000000000000003400000001020000000000052000000020020000010200000000000520000000200200000400E400050000000100240010000000010500000000000515000000010000000200000003000000EA03000006003800200000000100000011111111111111111111111111111111010500000000000515000000010000000200000003000000E90300000000240010000000010500000000000515000000010000000200000003000000E90300000002240004000000010500000000000515000000010000000200000003000000EA03000005003800100000000100000011111111111111111111111111111111010500000000000515000000010000000200000003000000EA030000"),
        ["Microsoft: audit split in SACL (E2)"] = Convert.FromHexString(
            "0100148014000000240000003400000084000000010200000000000520000000200200000102000000000005200000002002000004005000020000000242240010000000010500000000000515000000010000000200000003000000E9030000028A240010000000010500000000000515000000010000000200000003000000E90300000400080000000000"),
        ["Microsoft: object and inherited-object GUIDs (C1)"] = Convert.FromHexString(
            "0100048014000000240000000000000034000000010200000000000520000000200200000102000000000005200000002002000004008800020000000502480010000000030000001111111111111111111111111111111122222222222222222222222222222222010500000000000515000000010000000200000003000000E903000005023800100000000100000011111111111111111111111111111111010500000000000515000000010000000200000003000000E9030000"),
        ["Microsoft: callback object ACE after edit (H2)"] = Convert.FromHexString(
            "0100048014000000240000000000000034000000010200000000000520000000200200000102000000000005200000002002000004006800020000000000240020000000010500000000000515000000010000000200000003000000EA0300000B003C00100000000100000011111111111111111111111111111111010500000000000515000000010000000200000003000000E903000061727478"),
        ["Microsoft: protected DACL (B4)"] = Convert.FromHexString(
            "0100049014000000240000000000000034000000010200000000000520000000200200000102000000000005200000002002000004001C00010000000000140010000000010100000000000100000000"),
    };

    public static TheoryData<string> CorpusNames => new(Corpus.Keys);

    [Theory]
    [MemberData(nameof(CorpusNames))]
    public void Accepted_descriptors_round_trip_byte_for_byte(string name)
    {
        var input = Corpus[name];
        var snapshot = input.ToArray();

        var descriptor = SecurityDescriptor.Parse(input, All);

        Assert.Equal(input, descriptor.GetBinaryForm());
        Assert.Equal(snapshot, input);
        Assert.False(descriptor.HasOverlappingComponents);
    }

    // Layouts whose components share bytes. Microsoft RawSecurityDescriptor and
    // ActiveDirectorySecurity 9.0.0 accept all of these (offline Windows oracle, case J6).
    private static readonly Dictionary<string, byte[]> Overlapping = new()
    {
        ["owner offset equals group offset"] = WithOffset(Corpus["SACL and DACL"], 8, ReadU32(Corpus["SACL and DACL"], 4)),
        ["SACL offset equals DACL offset"] = WithOffset(Corpus["SACL and DACL"], 12, ReadU32(Corpus["SACL and DACL"], 16)),
        ["group SID inside a DACL ACE"] = WithOffset(Corpus["populated DACL"], 8, ReadU32(Corpus["populated DACL"], 16) + 16),
        ["owner SID inside a DACL ACE"] = WithOffset(Corpus["populated DACL"], 4, ReadU32(Corpus["populated DACL"], 16) + 16),
    };

    public static TheoryData<string> OverlappingNames => new(Overlapping.Keys);

    [Theory]
    [MemberData(nameof(OverlappingNames))]
    public void Shared_component_storage_is_accepted_and_round_trips(string name)
    {
        var input = Overlapping[name];

        var descriptor = SecurityDescriptor.Parse(input, All);

        Assert.True(descriptor.HasOverlappingComponents);
        Assert.Equal(input, descriptor.GetBinaryForm());
    }

    [Fact]
    public void Shared_storage_components_read_the_same_bytes()
    {
        var sameOwnerGroup = SecurityDescriptor.Parse(Overlapping["owner offset equals group offset"], All);
        var sharedAcl = SecurityDescriptor.Parse(Overlapping["SACL offset equals DACL offset"], All);
        var groupInAce = SecurityDescriptor.Parse(Overlapping["group SID inside a DACL ACE"], All);

        Assert.Equal(sameOwnerGroup.Owner, sameOwnerGroup.Group);
        Assert.Equal(sharedAcl.Dacl!.Aces.Single().RawBytes.ToArray(), sharedAcl.Sacl!.Aces.Single().RawBytes.ToArray());
        Assert.Equal("S-1-1-0", groupInAce.Group!.ToString());
        Assert.Equal(groupInAce.Dacl!.Aces.Single().Sid, groupInAce.Group);
    }

    [Theory]
    [MemberData(nameof(CorpusNames))]
    public void Round_trip_does_not_depend_on_the_retrieved_sections(string name)
    {
        var input = Corpus[name];

        Assert.Equal(input, SecurityDescriptor.Parse(input, SecurityMasks.None).GetBinaryForm());
        Assert.Equal(input, SecurityDescriptor.Parse(input, SecurityMasks.Dacl).GetBinaryForm());
    }

    [Theory]
    [InlineData("absent DACL", nameof(AclState.Absent))]
    [InlineData("NULL DACL", nameof(AclState.Null))]
    [InlineData("empty DACL", nameof(AclState.Empty))]
    [InlineData("populated DACL", nameof(AclState.Populated))]
    [InlineData("DACL data without present bit", nameof(AclState.Absent))]
    public void Dacl_states_stay_distinct(string name, string expectedState)
    {
        var expected = Enum.Parse<AclState>(expectedState);
        var descriptor = SecurityDescriptor.Parse(Corpus[name], All);

        Assert.Equal(expected, descriptor.DaclState);
        Assert.Equal(expected is AclState.Empty or AclState.Populated, descriptor.Dacl is not null);
    }

    [Fact]
    public void Unrequested_sections_are_not_retrieved_rather_than_absent()
    {
        var input = Corpus["SACL and DACL"];

        var daclOnly = SecurityDescriptor.Parse(input, SecurityMasks.Dacl);

        Assert.Equal(AclState.NotRetrieved, daclOnly.SaclState);
        Assert.Null(daclOnly.Sacl);
        Assert.Null(daclOnly.Owner);
        Assert.False(daclOnly.IsRetrieved(SecurityMasks.Owner));
        Assert.Equal(AclState.Populated, daclOnly.DaclState);

        var nothing = SecurityDescriptor.Parse(Corpus["absent DACL"], SecurityMasks.None);
        Assert.Equal(AclState.NotRetrieved, nothing.DaclState);
        Assert.Equal(AclState.NotRetrieved, nothing.SaclState);
    }

    [Fact]
    public void Sacl_states_and_owner_group_are_read()
    {
        var withSacl = SecurityDescriptor.Parse(Corpus["SACL and DACL"], All);
        var noSacl = SecurityDescriptor.Parse(Corpus["populated DACL"], All);
        var noOwner = SecurityDescriptor.Parse(Corpus["no owner or group"], All);

        Assert.Equal(AclState.Populated, withSacl.SaclState);
        Assert.Equal(AclState.Absent, noSacl.SaclState);
        Assert.Equal("S-1-5-32-544", withSacl.Owner!.ToString());
        Assert.Equal("S-1-5-32-544", withSacl.Group!.ToString());
        Assert.Null(noOwner.Owner);
        Assert.Null(noOwner.Group);
        Assert.True(noOwner.IsRetrieved(SecurityMasks.Owner));
    }

    [Fact]
    public void Acl_data_without_present_bit_is_kept_but_not_exposed()
    {
        var descriptor = SecurityDescriptor.Parse(Corpus["DACL data without present bit"], All);

        Assert.True(descriptor.HasAclDataWithoutPresentBit(SecurityMasks.Dacl));
        Assert.False(descriptor.HasAclDataWithoutPresentBit(SecurityMasks.Sacl));
        Assert.Null(descriptor.Dacl);
    }

    [Fact]
    public void Control_and_reserved_fields_are_kept_raw()
    {
        var unknownBits = SecurityDescriptor.Parse(Corpus["unknown control bits"], All);
        var rmControl = SecurityDescriptor.Parse(Corpus["resource-manager control byte"], All);

        Assert.Equal(0x8544, unknownBits.Control);
        Assert.Equal(0x5A, rmControl.Sbz1);
        Assert.Equal(1, rmControl.Revision);
    }

    [Fact]
    public void Common_and_object_aces_are_parsed()
    {
        var aces = SecurityDescriptor.Parse(Corpus["object ACEs with flags 0-3"], All).Dacl!.Aces;

        Assert.Collection(aces,
            ace =>
            {
                Assert.Equal(AceKind.ObjectAccess, ace.Kind);
                Assert.Equal(0x06, ace.AceType);
                Assert.Equal(0x20u, ace.AccessMask);
                Assert.Equal(2u, ace.ObjectFlags);
                Assert.Null(ace.ObjectType);
                Assert.Equal(G2, ace.InheritedObjectType);
                Assert.Equal("S-1-5-21-1-2-3-1002", ace.Sid!.ToString());
            },
            ace =>
            {
                Assert.Equal(AceKind.ObjectAccess, ace.Kind);
                Assert.Equal(0u, ace.ObjectFlags);
                Assert.Null(ace.ObjectType);
                Assert.Null(ace.InheritedObjectType);
            },
            ace => Assert.Equal(G1, ace.ObjectType),
            ace =>
            {
                Assert.Equal(0x02, ace.AceFlags);
                Assert.Equal(G1, ace.ObjectType);
                Assert.Equal(G2, ace.InheritedObjectType);
                Assert.Equal(0, ace.TrailingLength);
            });

        var audit = SecurityDescriptor.Parse(Corpus["SACL and DACL"], All).Sacl!.Aces.Single();
        Assert.Equal(AceKind.Audit, audit.Kind);
        Assert.Equal(0x40, audit.AceFlags);
    }

    [Fact]
    public void Present_all_zero_object_guid_keeps_its_presence()
    {
        var ace = SecurityDescriptor.Parse(Corpus["object ACE with present all-zero GUID"], All).Dacl!.Aces.Single();

        Assert.Equal(AceKind.ObjectAccess, ace.Kind);
        Assert.Equal(1u, ace.ObjectFlags);
        Assert.Equal(Guid.Empty, ace.ObjectType);
    }

    [Theory]
    [InlineData("callback ACE 0x09 with payload", 0x09)]
    [InlineData("callback object ACE 0x0B with payload", 0x0B)]
    [InlineData("unknown ACE type 0x20", 0x20)]
    [InlineData("unknown object flag 0x4", 0x05)]
    public void Unsupported_or_untrusted_layouts_are_opaque(string name, byte type)
    {
        var input = Corpus[name];
        var ace = SecurityDescriptor.Parse(input, All).Dacl!.Aces.Single();

        Assert.Equal(AceKind.Opaque, ace.Kind);
        Assert.Equal(type, ace.AceType);
        Assert.Null(ace.Sid);
        Assert.Equal(0u, ace.AccessMask);
        Assert.True(input.AsSpan().IndexOf(ace.RawBytes) >= 0);
    }

    [Fact]
    public void Ace_and_acl_trailing_bytes_are_reported_and_kept()
    {
        var ace = SecurityDescriptor.Parse(Corpus["ACE with trailing bytes"], All).Dacl!.Aces.Single();
        var acl = SecurityDescriptor.Parse(Corpus["ACL with trailing bytes"], All).Dacl!;

        Assert.Equal(AceKind.Access, ace.Kind);
        Assert.Equal(4, ace.TrailingLength);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, acl.Trailing.ToArray());
        Assert.Single(acl.Aces);
    }

    [Fact]
    public void Ace_list_cannot_be_cast_back_and_edited()
    {
        var input = Corpus["object ACEs with flags 0-3"];
        var acl = SecurityDescriptor.Parse(input, All).Dacl!;
        var first = acl.Aces[0];

        Assert.IsNotType<Ace[]>(acl.Aces);
        Assert.False(acl.Aces is IList<Ace> { IsReadOnly: false });
        Assert.Throws<NotSupportedException>(() => ((IList<Ace>)acl.Aces)[0] = acl.Aces[1]);
        Assert.Same(first, acl.Aces[0]);
    }

    [Fact]
    public void Returned_byte_arrays_are_independent_copies()
    {
        var descriptor = SecurityDescriptor.Parse(Corpus["SACL and DACL"], All);
        var output = descriptor.GetBinaryForm();
        var sid = descriptor.Owner!.ToArray();

        output[0] = 9;
        sid[0] = 9;

        Assert.Equal(Corpus["SACL and DACL"], descriptor.GetBinaryForm());
        Assert.Equal(1, descriptor.Owner!.AsSpan()[0]);
    }

    [Fact]
    public void Acl_revision_is_kept_even_with_object_aces()
    {
        var acl = SecurityDescriptor.Parse(Corpus["ACL revision 2 with object ACE"], All).Dacl!;

        Assert.Equal(2, acl.AclRevision);
        Assert.Equal(AceKind.ObjectAccess, acl.Aces.Single().Kind);
    }

    public static TheoryData<string> MalformedCases => new(Malformed.Keys);

    private static readonly Dictionary<string, Func<byte[]>> Malformed = new()
    {
        ["shorter than header"] = () => new byte[19],
        ["revision 2"] = () => With(Corpus["populated DACL"], d => d[0] = 2),
        ["absolute form"] = () => ClearControl(Corpus["populated DACL"], SelfRelative),
        ["owner offset inside header"] = () => WithOffset(Corpus["populated DACL"], 4, 8),
        ["owner offset at end"] = () => { var d = Corpus["populated DACL"]; return WithOffset(d, 4, (uint)d.Length); },
        ["owner offset huge"] = () => WithOffset(Corpus["populated DACL"], 4, uint.MaxValue),
        ["owner SID truncated"] = () => { var d = Corpus["populated DACL"]; return WithOffset(d, 4, (uint)d.Length - 4); },
        ["owner SID revision 2"] = () => With(Corpus["populated DACL"], d => d[20] = 2),
        ["owner SID with 16 sub-authorities"] = () => With(Corpus["populated DACL"], d => d[21] = 16),
        ["ACL header past end"] = () => { var d = Corpus["populated DACL"]; return WithOffset(d, 16, (uint)d.Length - 4); },
        ["ACL size below 8"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 2, 4)),
        ["ACL size past end"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 2, 500)),
        ["ACE count too large for ACL size"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 4, 100)),
        ["ACE count with missing ACE header"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 4, 2)),
        ["ACE size below 4"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 10, 3)),
        ["ACE size past ACL end"] = () => With(Corpus["populated DACL"], d => WriteU16(d, DaclAt(d) + 10, 200)),
        ["SACL offset inside header"] = () => WithOffset(Corpus["SACL and DACL"], 12, 19),
    };

    [Theory]
    [MemberData(nameof(MalformedCases))]
    public void Malformed_descriptors_fail_with_argument_exception_and_leave_input_unchanged(string name)
    {
        var input = Malformed[name]();
        var snapshot = input.ToArray();

        var error = Assert.Throws<ArgumentException>(() => SecurityDescriptor.Parse(input, All));

        Assert.Equal("binaryForm", error.ParamName);
        Assert.Equal(snapshot, input);
    }

    [Theory]
    [InlineData("populated DACL")]
    [InlineData("SACL and DACL")]
    [InlineData("object ACEs with flags 0-3")]
    [InlineData("Microsoft: deny/allow/object ordering (D1)")]
    public void Every_truncation_is_rejected(string name)
    {
        var input = Corpus[name];

        for (var length = 0; length < input.Length; length++)
        {
            var truncated = input[..length];
            var error = Assert.Throws<ArgumentException>(() => SecurityDescriptor.Parse(truncated, All));
            Assert.Equal("binaryForm", error.ParamName);
        }
    }

    [Theory]
    [MemberData(nameof(CorpusNames))]
    public void Random_corruption_either_round_trips_or_fails_cleanly(string name)
    {
        var input = Corpus[name];
        // HashCode and string.GetHashCode are randomized per process; derive a stable seed instead.
        var random = new Random(StableSeed(name));

        for (var iteration = 0; iteration < 300; iteration++)
        {
            var mutated = input.ToArray();
            for (var flips = random.Next(1, 4); flips > 0; flips--)
            {
                mutated[random.Next(mutated.Length)] = (byte)random.Next(256);
            }

            SecurityDescriptor descriptor;
            try
            {
                descriptor = SecurityDescriptor.Parse(mutated, All);
            }
            catch (ArgumentException error) when (error.ParamName == "binaryForm")
            {
                continue;
            }

            Assert.Equal(mutated, descriptor.GetBinaryForm());
        }
    }

    [Fact]
    public void Unknown_retrieved_section_flags_are_rejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => SecurityDescriptor.Parse(Corpus["populated DACL"], (SecurityMasks)16));

        Assert.Equal("retrievedSections", error.ParamName);
    }

    /// <summary>FNV-1a over the case name's UTF-16 code units: identical on every run and platform.</summary>
    private static int StableSeed(string name)
    {
        var hash = 2166136261u;
        foreach (var character in name)
        {
            hash = (hash ^ character) * 16777619u;
        }

        return unchecked((int)hash);
    }

    private static byte[] With(byte[] source, Action<byte[]> change)
    {
        var copy = source.ToArray();
        change(copy);
        return copy;
    }

    private static byte[] WithOffset(byte[] source, int field, uint offset) =>
        With(source, d => BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(field), offset));

    private static byte[] ClearControl(byte[] source, ushort bits) => With(source, d =>
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(2), (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(2)) & ~bits)));

    private static uint ReadU32(byte[] source, int at) => BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(at));

    private static int DaclAt(byte[] source) => (int)ReadU32(source, 16);

    private static void WriteU16(byte[] target, int at, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(target.AsSpan(at), value);
}
