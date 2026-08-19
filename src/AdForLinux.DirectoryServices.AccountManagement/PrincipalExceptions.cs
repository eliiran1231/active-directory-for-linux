using System.ComponentModel;
using System.Runtime.Serialization;

namespace AdForLinux.DirectoryServices.AccountManagement;

[Serializable]
public abstract class PrincipalException : SystemException
{
    internal PrincipalException() { }
    internal PrincipalException(string message) : base(message) { }
    internal PrincipalException(string message, Exception innerException) : base(message, innerException) { }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected PrincipalException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

[Serializable]
public class MultipleMatchesException : PrincipalException
{
    public MultipleMatchesException() { }
    public MultipleMatchesException(string message) : base(message) { }
    public MultipleMatchesException(string message, Exception innerException) : base(message, innerException) { }
    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected MultipleMatchesException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

[Serializable]
public class NoMatchingPrincipalException : PrincipalException
{
    public NoMatchingPrincipalException() { }
    public NoMatchingPrincipalException(string message) : base(message) { }
    public NoMatchingPrincipalException(string message, Exception innerException) : base(message, innerException) { }
    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected NoMatchingPrincipalException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

[Serializable]
public class PasswordException : PrincipalException
{
    public PasswordException() { }
    public PasswordException(string message) : base(message) { }
    public PasswordException(string message, Exception innerException) : base(message, innerException) { }
    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected PasswordException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

[Serializable]
public class PrincipalExistsException : PrincipalException
{
    public PrincipalExistsException() { }
    public PrincipalExistsException(string message) : base(message) { }
    public PrincipalExistsException(string message, Exception innerException) : base(message, innerException) { }
    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected PrincipalExistsException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

[Serializable]
public class PrincipalOperationException : PrincipalException
{
    public PrincipalOperationException() { }
    public PrincipalOperationException(string message) : base(message) { }
    public PrincipalOperationException(string message, Exception innerException) : base(message, innerException) { }
    public PrincipalOperationException(string message, int errorCode) : base(message) => ErrorCode = errorCode;
    public PrincipalOperationException(string message, Exception innerException, int errorCode) : base(message, innerException) => ErrorCode = errorCode;
    public int ErrorCode { get; }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected PrincipalOperationException(SerializationInfo info, StreamingContext context) : base(info, context) =>
        ErrorCode = info.GetInt32("errorCode");

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        base.GetObjectData(info, context);
        info.AddValue("errorCode", ErrorCode);
    }
}

[Serializable]
public class PrincipalServerDownException : PrincipalException
{
    private readonly int _errorCode;
    private readonly string? _serverName;

    public PrincipalServerDownException() { }
    public PrincipalServerDownException(string message) : base(message) { }
    public PrincipalServerDownException(string message, Exception innerException) : base(message, innerException) { }
    public PrincipalServerDownException(string message, int errorCode) : base(message) => _errorCode = errorCode;
    public PrincipalServerDownException(string message, Exception innerException, int errorCode) : base(message, innerException) => _errorCode = errorCode;
    public PrincipalServerDownException(string message, Exception innerException, int errorCode, string serverName) : base(message, innerException)
    {
        _errorCode = errorCode;
        _serverName = serverName;
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected PrincipalServerDownException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
        _errorCode = info.GetInt32("errorCode");
        _serverName = info.GetString("serverName");
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        base.GetObjectData(info, context);
        info.AddValue("errorCode", _errorCode);
        info.AddValue("serverName", _serverName, typeof(string));
    }
}
