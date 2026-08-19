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

    [Obsolete(
        "This API supports obsolete formatter-based serialization. It should not be called or extended by application code.",
        DiagnosticId = "SYSLIB0051",
        UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
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

    [Obsolete(
        "This API supports obsolete formatter-based serialization. It should not be called or extended by application code.",
        DiagnosticId = "SYSLIB0051",
        UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext) =>
        base.GetObjectData(serializationInfo, streamingContext);
}
