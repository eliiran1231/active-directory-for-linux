using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The exception exposed by the classic DirectoryServices API when an LDAP
/// provider operation fails.
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

    internal DirectoryServicesCOMException(
        string? message,
        Exception inner,
        int errorCode,
        int extendedError,
        string? extendedErrorMessage)
        : base(message, inner)
    {
        HResult = errorCode;
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
