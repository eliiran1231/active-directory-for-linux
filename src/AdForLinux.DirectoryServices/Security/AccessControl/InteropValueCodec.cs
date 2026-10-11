#pragma warning disable CA1416 // Actual framework identity construction has an explicit Windows guard.
using System.Security.AccessControl;
using System.Runtime.Versioning;
using P = AdForLinux.Security.Principal;
using M = System.Security.Principal;

namespace AdForLinux.Security.AccessControl;

// Staged internal companion implementation. These values carry fields, never resolvers,
// subtype behavior, callbacks, directory authority or descriptor provenance.
internal sealed class InteropIdentityValue
{
    private readonly byte[]? sid;
    internal InteropIdentityValue(byte[] sid)
    {
        this.sid = sid.ToArray();
        if (new P.SecurityIdentifier(this.sid, 0).BinaryLength != this.sid.Length)
            throw new NotSupportedException("Identity conversion cannot discard trailing SID storage.");
    }
    internal InteropIdentityValue(string name) { Name = new P.NTAccount(name).Value; }
    internal string? Name { get; }
    internal byte[]? Sid => sid?.ToArray();
    internal P.IdentityReference ToPortable() => sid is null ? new P.NTAccount(Name!) : new P.SecurityIdentifier(sid, 0);
    internal bool Same(InteropIdentityValue other) => Name == other.Name
        && (sid is null ? other.sid is null : other.sid is not null && sid.AsSpan().SequenceEqual(other.sid));
}

internal sealed record InteropRuleValue(InteropIdentityValue Identity, int Mask, bool IsInherited,
    InheritanceFlags Inheritance, PropagationFlags Propagation, bool IsAudit, bool IsObject,
    AccessControlType AccessType, AuditFlags Audit, Guid ObjectType, Guid InheritedObjectType, ObjectAceFlags ObjectFlags)
{
    internal bool Same(InteropRuleValue other) => Identity.Same(other.Identity)
        && (this with { Identity = other.Identity }) == other;
}

internal static class InteropValueCodec
{
    internal static InteropIdentityValue CaptureIdentity(P.IdentityReference source) => source switch
    {
        P.SecurityIdentifier sid => new(SidBytes(sid)),
        P.NTAccount name => new(name.Value),
        null => throw new ArgumentNullException(nameof(source)),
        _ => throw new NotSupportedException("Unknown identity subtypes cannot be converted by field inference.")
    };

    [SupportedOSPlatform("windows")]
    internal static M.IdentityReference ToMicrosoftIdentity(P.IdentityReference source)
    {
        var snapshot = CaptureIdentity(source);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Microsoft identity objects require Windows.");
        M.IdentityReference result = snapshot.Sid is { } sid ? new M.SecurityIdentifier(sid, 0) : new M.NTAccount(snapshot.Name!);
        if (!snapshot.Same(CaptureMicrosoftIdentity(result)))
            throw new NotSupportedException("Microsoft identity conversion changed the value.");
        return result;
    }

    [SupportedOSPlatform("windows")]
    internal static InteropIdentityValue CaptureMicrosoftIdentity(M.IdentityReference source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Microsoft identity objects require Windows.");
        return source switch
        {
            M.SecurityIdentifier sid => new(SidBytes(sid)),
            M.NTAccount name => new(name.Value),
            _ => throw new NotSupportedException("Unknown Microsoft identity subtypes are unsupported.")
        };
    }

    private static InteropRuleValue CaptureRule(AuthorizationRule source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source is not ValidationAccess and not ValidationAudit and not ValidationObjectAccess and not ValidationObjectAudit)
            throw new NotSupportedException("This rule subtype needs an explicit field-only conversion policy.");
        var identity = CaptureIdentity(source.IdentityReference);
        var audit = source is AuditRule;
        if (source is not AccessRule && !audit) throw new NotSupportedException("Unknown authorization rule family.");
        var objectType = source is ObjectAccessRule access ? access.ObjectType : source is ObjectAuditRule a ? a.ObjectType : Guid.Empty;
        var inheritedType = source is ObjectAccessRule access2 ? access2.InheritedObjectType : source is ObjectAuditRule a2 ? a2.InheritedObjectType : Guid.Empty;
        var objectFlags = source is ObjectAccessRule access3 ? access3.ObjectFlags : source is ObjectAuditRule a3 ? a3.ObjectFlags : ObjectAceFlags.None;
        return new(identity, source.AccessMask, source.IsInherited, source.InheritanceFlags, source.PropagationFlags,
            audit, source is ObjectAccessRule or ObjectAuditRule,
            source is AccessRule rule ? rule.AccessControlType : AccessControlType.Allow,
            source is AuditRule auditRule ? auditRule.AuditFlags : AuditFlags.None, objectType, inheritedType, objectFlags);
    }

    internal static void ValidateRuleFields(InteropRuleValue value) => _ = Materialize(value);

    private static AuthorizationRule Materialize(InteropRuleValue value)
    {
        ArgumentNullException.ThrowIfNull(value); ArgumentNullException.ThrowIfNull(value.Identity);
        var identity = value.Identity.ToPortable();
        AuthorizationRule result = value.IsObject
            ? value.IsAudit ? new ValidationObjectAudit(identity, value) : new ValidationObjectAccess(identity, value)
            : value.IsAudit ? new ValidationAudit(identity, value) : new ValidationAccess(identity, value);
        if (!value.Same(CaptureRule(result)))
            throw new NotSupportedException("The rule fields cannot be represented exactly, including GUID presence and normalized flags.");
        return result;
    }

    private static byte[] SidBytes(P.SecurityIdentifier sid)
    { var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes; }
    private static byte[] SidBytes(M.SecurityIdentifier sid)
    { var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes; }

    private sealed class ValidationAccess(P.IdentityReference id, InteropRuleValue v)
        : AccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.AccessType);
    private sealed class ValidationAudit(P.IdentityReference id, InteropRuleValue v)
        : AuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.Audit);
    private sealed class ValidationObjectAccess(P.IdentityReference id, InteropRuleValue v)
        : ObjectAccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.AccessType);
    private sealed class ValidationObjectAudit(P.IdentityReference id, InteropRuleValue v)
        : ObjectAuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.Audit);
}
