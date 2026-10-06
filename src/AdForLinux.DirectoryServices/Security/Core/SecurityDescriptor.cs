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
/// component order, gaps, unknown control bits, reserved fields, opaque ACEs and trailing bytes
/// are all retained, and <see cref="GetBinaryForm"/> reproduces an accepted input byte for byte.
/// Sections that the read did not request are tracked separately from sections that are absent.
/// </summary>
internal sealed class SecurityDescriptor
{
    internal const int HeaderLength = 20;
    internal const ushort SelfRelative = 0x8000;
    internal const ushort DaclPresent = 0x0004;
    internal const ushort SaclPresent = 0x0010;
    private const SecurityMasks AllSections = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;

    private readonly Sid? _owner;
    private readonly Sid? _group;
    private readonly Acl? _sacl;
    private readonly Acl? _dacl;
    private readonly Segment[] _layout;

    private SecurityDescriptor(
        byte revision, byte sbz1, ushort control, SecurityMasks retrievedSections,
        Sid? owner, Sid? group, Acl? sacl, Acl? dacl, Segment[] layout)
    {
        Revision = revision;
        Sbz1 = sbz1;
        Control = control;
        RetrievedSections = retrievedSections;
        _owner = owner;
        _group = group;
        _sacl = sacl;
        _dacl = dacl;
        _layout = layout;
    }

    private enum Component
    {
        Gap,
        Owner,
        Group,
        Sacl,
        Dacl,
    }

    public byte Revision { get; }

    /// <summary>Gets the reserved byte, which carries resource-manager control bits when SE_RM_CONTROL_VALID is set.</summary>
    public byte Sbz1 { get; }

    /// <summary>Gets the raw control field, including bits the core does not interpret.</summary>
    public ushort Control { get; }

    /// <summary>Gets the sections the read requested. Only these have known content.</summary>
    public SecurityMasks RetrievedSections { get; }

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

        var regions = new List<(int Start, int End, Component Component)>(4);
        var owner = ReadSid(binaryForm, 4, Component.Owner, regions);
        var group = ReadSid(binaryForm, 8, Component.Group, regions);
        var sacl = ReadAcl(binaryForm, 12, Component.Sacl, regions);
        var dacl = ReadAcl(binaryForm, 16, Component.Dacl, regions);

        regions.Sort((left, right) => left.Start.CompareTo(right.Start));
        var layout = new List<Segment>(regions.Count * 2 + 1);
        var cursor = HeaderLength;
        foreach (var (start, end, component) in regions)
        {
            if (start < cursor)
            {
                throw Malformed("Security descriptor components overlap.");
            }

            if (start > cursor)
            {
                layout.Add(Segment.Gap(binaryForm[cursor..start].ToArray()));
            }

            layout.Add(new Segment(component, null));
            cursor = end;
        }

        if (cursor < binaryForm.Length)
        {
            layout.Add(Segment.Gap(binaryForm[cursor..].ToArray()));
        }

        return new SecurityDescriptor(
            binaryForm[0], binaryForm[1], control, retrievedSections,
            owner, group, sacl, dacl, layout.ToArray());
    }

    /// <summary>
    /// Serializes from the model, laying components out in their original order with original
    /// gaps. For a parsed, unmodified descriptor the result equals the parsed input.
    /// </summary>
    public byte[] GetBinaryForm()
    {
        var length = HeaderLength + _layout.Sum(SegmentLength);
        var result = new byte[length];
        result[0] = Revision;
        result[1] = Sbz1;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(2), Control);
        var cursor = HeaderLength;
        foreach (var segment in _layout)
        {
            var destination = result.AsSpan(cursor);
            switch (segment.Component)
            {
                case Component.Gap:
                    segment.Bytes!.CopyTo(destination);
                    break;
                case Component.Owner:
                    WriteOffset(result, 4, cursor);
                    _owner!.WriteTo(destination);
                    break;
                case Component.Group:
                    WriteOffset(result, 8, cursor);
                    _group!.WriteTo(destination);
                    break;
                case Component.Sacl:
                    WriteOffset(result, 12, cursor);
                    _sacl!.WriteTo(destination);
                    break;
                case Component.Dacl:
                    WriteOffset(result, 16, cursor);
                    _dacl!.WriteTo(destination);
                    break;
            }

            cursor += SegmentLength(segment);
        }

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

    private int SegmentLength(Segment segment) => segment.Component switch
    {
        Component.Gap => segment.Bytes!.Length,
        Component.Owner => _owner!.BinaryLength,
        Component.Group => _group!.BinaryLength,
        Component.Sacl => _sacl!.BinaryLength,
        Component.Dacl => _dacl!.BinaryLength,
        _ => throw new InvalidOperationException(),
    };

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

        if (value < HeaderLength || value >= (uint)descriptor.Length)
        {
            throw Malformed("A security descriptor component offset is outside the descriptor.");
        }

        offset = (int)value;
        return true;
    }

    private static Sid? ReadSid(
        ReadOnlySpan<byte> descriptor, int field, Component component, List<(int, int, Component)> regions)
    {
        if (!TryReadOffset(descriptor, field, out var offset))
        {
            return null;
        }

        if (!Sid.TryRead(descriptor[offset..], out var sid, out var consumed))
        {
            throw Malformed("An owner or group SID is invalid or truncated.");
        }

        regions.Add((offset, offset + consumed, component));
        return sid;
    }

    private static Acl? ReadAcl(
        ReadOnlySpan<byte> descriptor, int field, Component component, List<(int, int, Component)> regions)
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
        regions.Add((offset, offset + size, component));
        return acl;
    }

    private readonly record struct Segment(Component Component, byte[]? Bytes)
    {
        public static Segment Gap(byte[] bytes) => new(Component.Gap, bytes);
    }
}
