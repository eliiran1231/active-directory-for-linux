// Adapted from dotnet/runtime v8.0.0 and v9.0.0 IdentityNotMappedException.cs.
// Copyright (c) .NET Foundation and Contributors. MIT license: ../AccessControl/RULES-LICENSE.txt.
using System.ComponentModel;
using System.Runtime.Serialization;

namespace AdForLinux.Security.Principal;

[Serializable]
public sealed class IdentityNotMappedException : SystemException
{
    private const string TranslationMessage = "Some or all identity references could not be translated.";
    private IdentityReferenceCollection? _unmappedIdentities;

    public IdentityNotMappedException() : base(TranslationMessage) { }
    public IdentityNotMappedException(string? message) : base(RuntimeMessage(message)) { }
    public IdentityNotMappedException(string? message, Exception? inner) : base(RuntimeMessage(message), inner) { }

    private static string? RuntimeMessage(string? message)
    {
#if NET10_0_OR_GREATER
        return message ?? TranslationMessage;
#else
        // .NET 8 delegates null to SystemException's generic type-name message.
        return message;
#endif
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    private IdentityNotMappedException(SerializationInfo info, StreamingContext context) : base(info, context) { }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
        => base.GetObjectData(serializationInfo, streamingContext);

    public IdentityReferenceCollection UnmappedIdentities => _unmappedIdentities ??= new IdentityReferenceCollection();
}
