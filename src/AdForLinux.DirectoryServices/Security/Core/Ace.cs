using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>How much of an ACE the core understands.</summary>
internal enum AceKind
{
    /// <summary>Access-allowed (0x00) or access-denied (0x01): mask and SID.</summary>
    Access,

    /// <summary>System-audit (0x02): mask and SID; success/failure live in the ACE flags.</summary>
    Audit,

    /// <summary>Allowed-object (0x05) or denied-object (0x06): mask, object GUIDs and SID.</summary>
    ObjectAccess,

    /// <summary>System-audit-object (0x07): mask, object GUIDs and SID.</summary>
    ObjectAudit,

    /// <summary>
    /// Any other type (callback, label, alarm, unknown), or a known type whose layout cannot be
    /// trusted (unknown object flags, unreadable SID). Kept as raw bytes only.
    /// </summary>
    Opaque,
}

/// <summary>
/// One ACE, kept byte-exact. Parsed fields are a read-only view over the raw bytes, which are
/// what serialization writes back. All header bits, including unknown flags, are preserved.
/// </summary>
internal sealed class Ace
{
    internal const byte AccessAllowedType = 0x00;
    internal const byte AccessDeniedType = 0x01;
    internal const byte SystemAuditType = 0x02;
    internal const byte AccessAllowedObjectType = 0x05;
    internal const byte AccessDeniedObjectType = 0x06;
    internal const byte SystemAuditObjectType = 0x07;

    internal const uint ObjectTypePresent = 0x1;
    internal const uint InheritedObjectTypePresent = 0x2;

    private const int HeaderLength = 4;
    private const int CommonPrefixLength = 8;
    private const int ObjectPrefixLength = 12;

    private readonly byte[] _raw;

    private Ace(byte[] raw)
    {
        _raw = raw;
    }

    public byte AceType => _raw[0];

    public byte AceFlags => _raw[1];

    /// <summary>Gets the ACE size, which always equals the raw length.</summary>
    public int Size => _raw.Length;

    public AceKind Kind { get; private init; }

    /// <summary>Gets the access mask, or 0 for an opaque ACE.</summary>
    public uint AccessMask { get; private init; }

    /// <summary>Gets the raw object flags of an object ACE, or 0.</summary>
    public uint ObjectFlags { get; private init; }

    public Guid? ObjectType { get; private init; }

    public Guid? InheritedObjectType { get; private init; }

    /// <summary>Gets the trustee, or null for an opaque ACE.</summary>
    public Sid? Sid { get; private init; }

    /// <summary>
    /// Gets the number of bytes inside <see cref="Size"/> after the SID. These are application
    /// data for no supported kind, so a non-zero value marks the ACE as carrying unexplained data.
    /// </summary>
    public int TrailingLength { get; private init; }

    public ReadOnlySpan<byte> RawBytes => _raw;

    internal void WriteTo(Span<byte> destination) => _raw.CopyTo(destination);

    /// <summary>
    /// Creates an ACE from exactly its bytes. The caller has already checked that the ACE header
    /// size field matches <paramref name="ace"/>'s length and that the length is at least 4.
    /// </summary>
    internal static Ace Read(ReadOnlySpan<byte> ace)
    {
        var raw = ace.ToArray();
        return raw[0] switch
        {
            AccessAllowedType or AccessDeniedType => ReadCommon(raw, AceKind.Access),
            SystemAuditType => ReadCommon(raw, AceKind.Audit),
            AccessAllowedObjectType or AccessDeniedObjectType => ReadObject(raw, AceKind.ObjectAccess),
            SystemAuditObjectType => ReadObject(raw, AceKind.ObjectAudit),
            _ => Opaque(raw),
        };
    }

    private static Ace ReadCommon(byte[] raw, AceKind kind)
    {
        if (raw.Length < CommonPrefixLength
            || !Sid.TryRead(raw.AsSpan(CommonPrefixLength), out var sid, out var consumed))
        {
            return Opaque(raw);
        }

        return new Ace(raw)
        {
            Kind = kind,
            AccessMask = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(HeaderLength)),
            Sid = sid,
            TrailingLength = raw.Length - CommonPrefixLength - consumed,
        };
    }

    private static Ace ReadObject(byte[] raw, AceKind kind)
    {
        if (raw.Length < ObjectPrefixLength)
        {
            return Opaque(raw);
        }

        var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(CommonPrefixLength));
        if ((objectFlags & ~(ObjectTypePresent | InheritedObjectTypePresent)) != 0)
        {
            // Unknown object flags: the position of the SID cannot be trusted.
            return Opaque(raw);
        }

        var cursor = ObjectPrefixLength;
        Guid? objectType = null;
        Guid? inheritedObjectType = null;
        if ((objectFlags & ObjectTypePresent) != 0)
        {
            if (raw.Length < cursor + 16)
            {
                return Opaque(raw);
            }

            objectType = new Guid(raw.AsSpan(cursor, 16));
            cursor += 16;
        }

        if ((objectFlags & InheritedObjectTypePresent) != 0)
        {
            if (raw.Length < cursor + 16)
            {
                return Opaque(raw);
            }

            inheritedObjectType = new Guid(raw.AsSpan(cursor, 16));
            cursor += 16;
        }

        if (!Sid.TryRead(raw.AsSpan(cursor), out var sid, out var consumed))
        {
            return Opaque(raw);
        }

        return new Ace(raw)
        {
            Kind = kind,
            AccessMask = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(HeaderLength)),
            ObjectFlags = objectFlags,
            ObjectType = objectType,
            InheritedObjectType = inheritedObjectType,
            Sid = sid,
            TrailingLength = raw.Length - cursor - consumed,
        };
    }

    private static Ace Opaque(byte[] raw) => new(raw) { Kind = AceKind.Opaque };
}
