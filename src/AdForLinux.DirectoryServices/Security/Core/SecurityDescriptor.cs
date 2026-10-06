using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>The state of a DACL or SACL slot. Absent, NULL and empty have different meanings.</summary>
internal enum AclState
{
    /// <summary>The read did not request this section, so its content is unknown.</summary>
    NotRetrieved,

    /// <summary>The present bit is clear: no ACL.</summary>
    Absent,

    /// <summary>The present bit is set with offset 0. For a DACL this allows everyone everything.</summary>
    Null,

    /// <summary>A present ACL with no ACEs. For a DACL this denies everyone (apart from implicit owner rights).</summary>
    Empty,

    /// <summary>A present ACL with at least one ACE.</summary>
    Populated,
}

/// <summary>
/// An immutable self-relative security descriptor. Parsing never reorders or normalizes:
/// component order and offsets, gaps, unknown control bits, reserved fields, opaque ACEs and
/// trailing bytes are all retained, and <see cref="GetBinaryForm"/> reproduces an accepted input
/// byte for byte. Components may share storage (Microsoft accepts this; oracle J6). Sections that
/// the read did not request are tracked separately from sections that are absent.
/// </summary>
internal sealed class SecurityDescriptor
{
    internal const int HeaderLength = 20;
    internal const ushort SelfRelative = 0x8000;
    internal const ushort DaclPresent = 0x0004;
    internal const ushort SaclPresent = 0x0010;
    private const SecurityMasks AllSections = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
    private const int OwnerField = 4;
    private const int GroupField = 8;
    private const int SaclField = 12;
    private const int DaclField = 16;

    private readonly Sid? _owner;
    private readonly Sid? _group;
    private readonly Acl? _sacl;
    private readonly Acl? _dacl;

    // Original layout: the input image supplies gap and trailing bytes; components are written
    // over it from the model at their original offsets (0 = component not stored).
    private readonly byte[] _image;
    private readonly int _ownerOffset;
    private readonly int _groupOffset;
    private readonly int _saclOffset;
    private readonly int _daclOffset;

    private SecurityDescriptor(byte[] image, SecurityMasks retrievedSections,
        Sid? owner, Sid? group, Acl? sacl, Acl? dacl, bool hasOverlappingComponents)
    {
        _image = image;
        Revision = image[0];
        Sbz1 = image[1];
        Control = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(2));
        RetrievedSections = retrievedSections;
        _owner = owner;
        _group = group;
        _sacl = sacl;
        _dacl = dacl;
        _ownerOffset = owner is null ? 0 : ReadOffset(image, OwnerField);
        _groupOffset = group is null ? 0 : ReadOffset(image, GroupField);
        _saclOffset = sacl is null ? 0 : ReadOffset(image, SaclField);
        _daclOffset = dacl is null ? 0 : ReadOffset(image, DaclField);
        HasOverlappingComponents = hasOverlappingComponents;
    }

    public byte Revision { get; }

    /// <summary>Gets the reserved byte, which carries resource-manager control bits when SE_RM_CONTROL_VALID is set.</summary>
    public byte Sbz1 { get; }

    /// <summary>Gets the raw control field, including bits the core does not interpret.</summary>
    public ushort Control { get; }

    /// <summary>Gets the sections the read requested. Only these have known content.</summary>
    public SecurityMasks RetrievedSections { get; }

    /// <summary>
    /// Gets whether two components share bytes, fully (equal offsets) or partially. Such a
    /// descriptor is valid and round-trips exactly, but an edit to one component cannot be
    /// spliced in place without also affecting the other.
    /// </summary>
    public bool HasOverlappingComponents { get; }

    /// <summary>Gets the owner, or null when absent or not retrieved (see <see cref="IsRetrieved"/>).</summary>
    public Sid? Owner => IsRetrieved(SecurityMasks.Owner) ? _owner : null;

    /// <summary>Gets the group, or null when absent or not retrieved (see <see cref="IsRetrieved"/>).</summary>
    public Sid? Group => IsRetrieved(SecurityMasks.Group) ? _group : null;

    public AclState DaclState => StateOf(SecurityMasks.Dacl, DaclPresent, _dacl);

    public AclState SaclState => StateOf(SecurityMasks.Sacl, SaclPresent, _sacl);

    /// <summary>Gets the DACL when its state is <see cref="AclState.Empty"/> or <see cref="AclState.Populated"/>; otherwise null.</summary>
    public Acl? Dacl => DaclState is AclState.Empty or AclState.Populated ? _dacl : null;

    /// <summary>Gets the SACL when its state is <see cref="AclState.Empty"/> or <see cref="AclState.Populated"/>; otherwise null.</summary>
    public Acl? Sacl => SaclState is AclState.Empty or AclState.Populated ? _sacl : null;

    /// <summary>
    /// Gets whether ACL bytes are referenced by a non-zero offset while the matching present bit
    /// is clear. Such data is kept for lossless output but is not exposed as an ACL.
    /// </summary>
    public bool HasAclDataWithoutPresentBit(SecurityMasks section) => section switch
    {
        SecurityMasks.Dacl => _dacl is not null && (Control & DaclPresent) == 0,
        SecurityMasks.Sacl => _sacl is not null && (Control & SaclPresent) == 0,
        _ => throw new ArgumentOutOfRangeException(nameof(section)),
    };

    public bool IsRetrieved(SecurityMasks section) => (RetrievedSections & section) == section;

    /// <summary>
    /// Parses a self-relative descriptor. <paramref name="retrievedSections"/> is the SD-flags
    /// mask the read used; it is recorded, never inferred from the bytes. Every failure is an
    /// <see cref="ArgumentException"/> with parameter name <c>binaryForm</c>.
    /// </summary>
    public static SecurityDescriptor Parse(ReadOnlySpan<byte> binaryForm, SecurityMasks retrievedSections)
    {
        if ((retrievedSections & ~AllSections) != 0)
        {
            throw new ArgumentException("Unknown section flags.", nameof(retrievedSections));
        }

        if (binaryForm.Length < HeaderLength)
        {
            throw Malformed("The security descriptor is shorter than its 20-byte header.");
        }

        if (binaryForm[0] != 1)
        {
            throw Malformed("The security descriptor revision is not 1.");
        }

        var control = BinaryPrimitives.ReadUInt16LittleEndian(binaryForm[2..]);
        if ((control & SelfRelative) == 0)
        {
            throw Malformed("The security descriptor is not in self-relative form.");
        }

        var regions = new List<(int Start, int End)>(4);
        var owner = ReadSid(binaryForm, OwnerField, regions);
        var group = ReadSid(binaryForm, GroupField, regions);
        var sacl = ReadAcl(binaryForm, SaclField, regions);
        var dacl = ReadAcl(binaryForm, DaclField, regions);

        regions.Sort((left, right) => left.Start.CompareTo(right.Start));
        var overlapping = false;
        for (var index = 1; index < regions.Count; index++)
        {
            overlapping |= regions[index].Start < regions[index - 1].End;
        }

        return new SecurityDescriptor(binaryForm.ToArray(), retrievedSections, owner, group, sacl, dacl, overlapping);
    }

    /// <summary>
    /// Serializes from the model in the original layout: header fields and every component are
    /// written from the parsed values at their original offsets over the original image, which
    /// supplies gap and trailing bytes. For a parsed, unmodified descriptor the result equals
    /// the parsed input; components that share storage write identical bytes.
    /// </summary>
    public byte[] GetBinaryForm()
    {
        var result = new byte[_image.Length];
        _image.CopyTo(result, 0);
        result[0] = Revision;
        result[1] = Sbz1;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(2), Control);
        WriteOffset(result, OwnerField, _ownerOffset);
        WriteOffset(result, GroupField, _groupOffset);
        WriteOffset(result, SaclField, _saclOffset);
        WriteOffset(result, DaclField, _daclOffset);
        _owner?.WriteTo(result.AsSpan(_ownerOffset));
        _group?.WriteTo(result.AsSpan(_groupOffset));
        _sacl?.WriteTo(result.AsSpan(_saclOffset));
        _dacl?.WriteTo(result.AsSpan(_daclOffset));
        return result;
    }

    internal static ArgumentException Malformed(string message) => new(message, "binaryForm");

    private AclState StateOf(SecurityMasks section, ushort presentBit, Acl? acl)
    {
        if (!IsRetrieved(section))
        {
            return AclState.NotRetrieved;
        }

        if ((Control & presentBit) == 0)
        {
            return AclState.Absent;
        }

        if (acl is null)
        {
            return AclState.Null;
        }

        return acl.Aces.Count == 0 ? AclState.Empty : AclState.Populated;
    }

    private static int ReadOffset(byte[] descriptor, int field) =>
        (int)BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(field));

    private static void WriteOffset(byte[] descriptor, int field, int offset) =>
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(field), checked((uint)offset));

    private static bool TryReadOffset(ReadOnlySpan<byte> descriptor, int field, out int offset)
    {
        var value = BinaryPrimitives.ReadUInt32LittleEndian(descriptor[field..]);
        if (value == 0)
        {
            offset = 0;
            return false;
        }

        // Offsets into the header itself are rejected; Microsoft's handling of them is untested.
        if (value < HeaderLength || value >= (uint)descriptor.Length)
        {
            throw Malformed("A security descriptor component offset is outside the descriptor.");
        }

        offset = (int)value;
        return true;
    }

    private static Sid? ReadSid(ReadOnlySpan<byte> descriptor, int field, List<(int, int)> regions)
    {
        if (!TryReadOffset(descriptor, field, out var offset))
        {
            return null;
        }

        if (!Sid.TryRead(descriptor[offset..], out var sid, out var consumed))
        {
            throw Malformed("An owner or group SID is invalid or truncated.");
        }

        regions.Add((offset, offset + consumed));
        return sid;
    }

    private static Acl? ReadAcl(ReadOnlySpan<byte> descriptor, int field, List<(int, int)> regions)
    {
        if (!TryReadOffset(descriptor, field, out var offset))
        {
            return null;
        }

        if (offset + Acl.HeaderLength > descriptor.Length)
        {
            throw Malformed("An ACL header extends past the end of the descriptor.");
        }

        var size = BinaryPrimitives.ReadUInt16LittleEndian(descriptor[(offset + 2)..]);
        if (size < Acl.HeaderLength || offset + size > descriptor.Length)
        {
            throw Malformed("An ACL size is invalid or extends past the end of the descriptor.");
        }

        var acl = Acl.Read(descriptor.Slice(offset, size));
        regions.Add((offset, offset + size));
        return acl;
    }
}
