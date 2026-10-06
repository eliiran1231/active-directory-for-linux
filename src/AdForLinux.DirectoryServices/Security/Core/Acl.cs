using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>
/// An immutable ACL in original order. The revision and reserved fields are kept raw, and any
/// bytes inside the declared ACL size after the last counted ACE are kept as trailing data, so
/// serialization reproduces the input exactly.
/// </summary>
internal sealed class Acl
{
    internal const byte Revision = 2;
    internal const byte RevisionDS = 4;
    internal const int HeaderLength = 8;

    private readonly Ace[] _aces;
    private readonly byte[] _trailing;

    private Acl(byte revision, byte sbz1, ushort sbz2, Ace[] aces, byte[] trailing)
    {
        AclRevision = revision;
        Sbz1 = sbz1;
        Sbz2 = sbz2;
        _aces = aces;
        _trailing = trailing;

        // A wrapper, not the array itself: callers must not be able to cast back and edit.
        Aces = Array.AsReadOnly(aces);
    }

    public byte AclRevision { get; }

    public byte Sbz1 { get; }

    public ushort Sbz2 { get; }

    public IReadOnlyList<Ace> Aces { get; }

    public ReadOnlySpan<byte> Trailing => _trailing;

    public int BinaryLength => HeaderLength + _aces.Sum(ace => ace.Size) + _trailing.Length;

    internal void WriteTo(Span<byte> destination)
    {
        destination[0] = AclRevision;
        destination[1] = Sbz1;
        BinaryPrimitives.WriteUInt16LittleEndian(destination[2..], checked((ushort)BinaryLength));
        BinaryPrimitives.WriteUInt16LittleEndian(destination[4..], checked((ushort)_aces.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(destination[6..], Sbz2);
        var cursor = HeaderLength;
        foreach (var ace in _aces)
        {
            ace.WriteTo(destination[cursor..]);
            cursor += ace.Size;
        }

        _trailing.CopyTo(destination[cursor..]);
    }

    /// <summary>
    /// Reads an ACL whose declared size is exactly <paramref name="acl"/>'s length. Every bound
    /// is checked before any per-ACE allocation.
    /// </summary>
    internal static Acl Read(ReadOnlySpan<byte> acl)
    {
        if (acl.Length < HeaderLength)
        {
            throw SecurityDescriptor.Malformed("An ACL is shorter than its 8-byte header.");
        }

        var size = BinaryPrimitives.ReadUInt16LittleEndian(acl[2..]);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(acl[4..]);
        if (size != acl.Length)
        {
            throw SecurityDescriptor.Malformed("An ACL size does not match its component bounds.");
        }

        // Each ACE needs at least a 4-byte header; reject impossible counts before allocating.
        if (count * 4L > size - HeaderLength)
        {
            throw SecurityDescriptor.Malformed("An ACL declares more ACEs than its size can hold.");
        }

        var aces = new Ace[count];
        var cursor = HeaderLength;
        for (var index = 0; index < count; index++)
        {
            if (cursor + 4 > size)
            {
                throw SecurityDescriptor.Malformed("An ACE header extends past the end of its ACL.");
            }

            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(acl[(cursor + 2)..]);
            if (aceSize < 4 || cursor + aceSize > size)
            {
                throw SecurityDescriptor.Malformed("An ACE size is invalid or extends past the end of its ACL.");
            }

            aces[index] = Ace.Read(acl.Slice(cursor, aceSize));
            cursor += aceSize;
        }

        return new Acl(acl[0], acl[1], BinaryPrimitives.ReadUInt16LittleEndian(acl[6..]), aces, acl[cursor..].ToArray());
    }
}
