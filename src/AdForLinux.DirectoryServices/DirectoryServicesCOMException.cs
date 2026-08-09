using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Compatibility exception for code that exposes the classic DirectoryServices COM exception type.
/// LDAP protocol failures continue to surface as <see cref="System.DirectoryServices.Protocols.DirectoryOperationException"/>.
/// </summary>
[Serializable]
public class DirectoryServicesCOMException : COMException
{
    public DirectoryServicesCOMException()
    {
    }

    public DirectoryServicesCOMException(string? message)
        : base(message)
    {
    }

    public DirectoryServicesCOMException(string? message, Exception? inner)
        : base(message, inner)
    {
    }

    [Obsolete("Formatter-based serialization is obsolete and should not be used.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected DirectoryServicesCOMException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }

    internal DirectoryServicesCOMException(string? message, int extendedError, string? extendedErrorMessage)
        : base(message)
    {
        ExtendedError = extendedError;
        ExtendedErrorMessage = extendedErrorMessage;
    }

    public int ExtendedError { get; }

    public string? ExtendedErrorMessage { get; }

    [Obsolete("Formatter-based serialization is obsolete and should not be used.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void GetObjectData(SerializationInfo info, StreamingContext context) =>
        base.GetObjectData(info, context);
}
