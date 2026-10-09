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
        if (!snapshot.Same(CaptureIdentity(FromMicrosoftIdentity(result))))
            throw new NotSupportedException("Microsoft identity conversion changed the value.");
        return result;
    }

    [SupportedOSPlatform("windows")]
    internal static P.IdentityReference FromMicrosoftIdentity(M.IdentityReference source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Microsoft identity objects require Windows.");
        return source switch
        {
            M.SecurityIdentifier sid => new P.SecurityIdentifier(SidBytes(sid), 0),
            M.NTAccount name => new P.NTAccount(name.Value),
            _ => throw new NotSupportedException("Unknown Microsoft identity subtypes are unsupported.")
        };
    }

    // Concrete AD types are not portable yet. Unknown consumer subclasses require an
    // explicit field-only opt-in; their behavior/state is never claimed to be cloned.
    internal static InteropRuleValue CaptureRule(AuthorizationRule source, bool allowFieldOnlySubclass = false)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!allowFieldOnlySubclass && source is not ImportedAccess and not ImportedAudit and not ImportedObjectAccess and not ImportedObjectAudit)
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

    internal static T ExportRule<T>(AuthorizationRule source, Func<InteropRuleValue, T> construct,
        Func<T, InteropRuleValue> inspect, bool allowFieldOnlySubclass = false)
        => ExportValue(CaptureRule(source, allowFieldOnlySubclass), construct, inspect);

    internal static AuthorizationRule ImportRule<T>(T source, Func<T, InteropRuleValue> inspect)
    {
        ArgumentNullException.ThrowIfNull(inspect);
        RequireOutsideGate();
        return Materialize(inspect(source));
    }

    internal static T[] ExportRules<T>(AuthorizationRuleCollection source, Func<InteropRuleValue, T> construct,
        Func<T, InteropRuleValue> inspect, bool allowFieldOnlySubclass = false)
    {
        ArgumentNullException.ThrowIfNull(source);
        // Validate all inputs before invoking any target factory. Preserve order and
        // multiplicity, return only a complete independently allocated collection.
        var values = Enumerable.Range(0, source.Count).Select(i => CaptureRule(source[i]!, allowFieldOnlySubclass)).ToArray();
        return values.Select(value => ExportValue(value, construct, inspect)).ToArray();
    }

    internal static AuthorizationRuleCollection ImportRules<T>(IEnumerable<T> source, Func<T, InteropRuleValue> inspect)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(inspect);
        RequireOutsideGate();
        var rules = source.Select(value => Materialize(inspect(value))).ToArray();
        var result = new AuthorizationRuleCollection();
        foreach (var rule in rules) result.AddRule(rule);
        return result;
    }

    private static T ExportValue<T>(InteropRuleValue value, Func<InteropRuleValue, T> construct, Func<T, InteropRuleValue> inspect)
    {
        ArgumentNullException.ThrowIfNull(construct); ArgumentNullException.ThrowIfNull(inspect);
        RequireOutsideGate();
        _ = Materialize(value); // exact flags/GUID presence must survive the portable constructor too
        var target = construct(value);
        if (!value.Same(inspect(target))) throw new NotSupportedException("The target rule lost or changed a field.");
        return target;
    }

    private static AuthorizationRule Materialize(InteropRuleValue value)
    {
        ArgumentNullException.ThrowIfNull(value); ArgumentNullException.ThrowIfNull(value.Identity);
        var identity = value.Identity.ToPortable();
        AuthorizationRule result = value.IsObject
            ? value.IsAudit ? new ImportedObjectAudit(identity, value) : new ImportedObjectAccess(identity, value)
            : value.IsAudit ? new ImportedAudit(identity, value) : new ImportedAccess(identity, value);
        if (!value.Same(CaptureRule(result)))
            throw new NotSupportedException("The rule fields cannot be represented exactly, including GUID presence and normalized flags.");
        return result;
    }

    private static void RequireOutsideGate()
    {
        if (Monitor.IsEntered(FacadeMutation.Gate)) throw new InvalidOperationException("External converters cannot execute inside the portable mutation gate.");
    }
    private static byte[] SidBytes(P.SecurityIdentifier sid)
    { var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes; }
    private static byte[] SidBytes(M.SecurityIdentifier sid)
    { var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes; }

    private sealed class ImportedAccess(P.IdentityReference id, InteropRuleValue v)
        : AccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.AccessType);
    private sealed class ImportedAudit(P.IdentityReference id, InteropRuleValue v)
        : AuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.Audit);
    private sealed class ImportedObjectAccess(P.IdentityReference id, InteropRuleValue v)
        : ObjectAccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.AccessType);
    private sealed class ImportedObjectAudit(P.IdentityReference id, InteropRuleValue v)
        : ObjectAuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.Audit);
}
