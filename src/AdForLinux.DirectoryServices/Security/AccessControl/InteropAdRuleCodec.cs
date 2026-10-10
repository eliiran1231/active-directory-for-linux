#pragma warning disable CA1416
using System.Runtime.Versioning;
using System.Security.AccessControl;
using D = AdForLinux.DirectoryServices;
using B = AdForLinux.Security.AccessControl;

namespace AdForLinux.Security.AccessControl;

internal enum InteropAdRuleKind { Access, Audit, ListChildren, CreateChild, DeleteChild, Property, PropertySet, ExtendedRight, DeleteTree }

// Data-only subtype metadata. This is not a second public AD rule hierarchy.
internal sealed record InteropAdRuleValue(InteropAdRuleKind Kind, InteropRuleValue Fields,
    D.ActiveDirectorySecurityInheritance InheritanceType)
{
    internal bool Same(InteropAdRuleValue other) => Kind == other.Kind && InheritanceType == other.InheritanceType
        && Fields.Same(other.Fields);
}

internal static class InteropAdRuleCodec
{
    internal static void Validate(InteropAdRuleValue value)
    {
        ArgumentNullException.ThrowIfNull(value); ArgumentNullException.ThrowIfNull(value.Fields);
        if (!Enum.IsDefined(value.Kind)) throw new NotSupportedException("Unknown AD rule subtype.");
        var f = value.Fields;
        _ = InteropValueCodec.ImportRule(f, fields => fields);
        if (!f.IsObject || f.IsAudit != (value.Kind == InteropAdRuleKind.Audit)
            || D.ActiveDirectoryInheritance.FromFlags(f.Inheritance, f.Propagation) != value.InheritanceType)
            throw new NotSupportedException("AD rule family or inheritance metadata is inconsistent.");
        if (value.Kind is InteropAdRuleKind.Access or InteropAdRuleKind.Audit) return;
        var requiredMask = value.Kind switch
        {
            InteropAdRuleKind.ListChildren => 4,
            InteropAdRuleKind.CreateChild => 1,
            InteropAdRuleKind.DeleteChild => 2,
            InteropAdRuleKind.Property or InteropAdRuleKind.PropertySet when f.Mask is 16 or 32 => f.Mask,
            InteropAdRuleKind.ExtendedRight => 256,
            InteropAdRuleKind.DeleteTree => 64,
            _ => throw new NotSupportedException("The specialized AD rule rights cannot be represented exactly.")
        };
        if (f.Mask != requiredMask || f.IsInherited
            || f.Inheritance != D.ActiveDirectoryInheritance.GetInheritanceFlags(value.InheritanceType)
            || f.Propagation != D.ActiveDirectoryInheritance.GetPropagationFlags(value.InheritanceType)
            || (value.Kind is InteropAdRuleKind.ListChildren or InteropAdRuleKind.DeleteTree && f.ObjectType != Guid.Empty))
            throw new NotSupportedException("The specialized AD constructor cannot preserve these fields.");
    }

    internal static T Export<T>(InteropAdRuleValue value, Func<InteropAdRuleValue, T> construct,
        Func<T, InteropAdRuleValue> inspect)
    {
        ArgumentNullException.ThrowIfNull(construct); ArgumentNullException.ThrowIfNull(inspect);
        RequireOutsideGate(); Validate(value);
        var result = construct(value);
        var actual = inspect(result); Validate(actual);
        if (!value.Same(actual)) throw new NotSupportedException("AD conversion changed a field or concrete subtype.");
        return result;
    }

    internal static InteropAdRuleValue Import<T>(T source, Func<T, InteropAdRuleValue> inspect)
    {
        ArgumentNullException.ThrowIfNull(inspect); RequireOutsideGate();
        var result = inspect(source); Validate(result); return result;
    }

    internal static InteropAdRuleValue CaptureCurrentRule(B.AuthorizationRule source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var kind = source.GetType() == typeof(D.ActiveDirectoryAccessRule) ? InteropAdRuleKind.Access
            : source.GetType() == typeof(D.ActiveDirectoryAuditRule) ? InteropAdRuleKind.Audit
            : source.GetType() == typeof(D.ListChildrenAccessRule) ? InteropAdRuleKind.ListChildren
            : source.GetType() == typeof(D.CreateChildAccessRule) ? InteropAdRuleKind.CreateChild
            : source.GetType() == typeof(D.DeleteChildAccessRule) ? InteropAdRuleKind.DeleteChild
            : source.GetType() == typeof(D.PropertyAccessRule) ? InteropAdRuleKind.Property
            : source.GetType() == typeof(D.PropertySetAccessRule) ? InteropAdRuleKind.PropertySet
            : source.GetType() == typeof(D.ExtendedRightAccessRule) ? InteropAdRuleKind.ExtendedRight
            : source.GetType() == typeof(D.DeleteTreeAccessRule) ? InteropAdRuleKind.DeleteTree
            : throw new NotSupportedException("Unknown AD rule subclasses cannot be converted implicitly.");
        var access = source as D.ActiveDirectoryAccessRule; var audit = source as D.ActiveDirectoryAuditRule;
        var fields = new InteropRuleValue(InteropValueCodec.CaptureIdentity(source.IdentityReference),
            (int)(access?.ActiveDirectoryRights ?? audit!.ActiveDirectoryRights), source.IsInherited,
            source.InheritanceFlags, source.PropagationFlags, audit is not null, true,
            access?.AccessControlType ?? AccessControlType.Allow, audit?.AuditFlags ?? AuditFlags.None,
            access?.ObjectType ?? audit!.ObjectType, access?.InheritedObjectType ?? audit!.InheritedObjectType,
            access?.ObjectFlags ?? audit!.ObjectFlags);
        var result = new InteropAdRuleValue(kind, fields, access?.InheritanceType ?? audit!.InheritanceType);
        Validate(result); return result;
    }

    internal static B.AuthorizationRule CreateCurrentRule(InteropAdRuleValue value)
    {
        Validate(value);
        var f = value.Fields; var id = f.Identity.ToPortable();
        var inheritance = value.InheritanceType; var type = f.AccessType;
        var property = f.Mask == 16 ? D.PropertyAccess.Read : D.PropertyAccess.Write;
        B.AuthorizationRule result = value.Kind switch
        {
            InteropAdRuleKind.Access => new D.ActiveDirectoryAccessRule(id, f.Mask, type, f.ObjectType,
                f.IsInherited, f.Inheritance, f.Propagation, f.InheritedObjectType),
            InteropAdRuleKind.Audit => new D.ActiveDirectoryAuditRule(id, f.Mask, f.Audit, f.ObjectType,
                f.IsInherited, f.Inheritance, f.Propagation, f.InheritedObjectType),
            InteropAdRuleKind.ListChildren => new D.ListChildrenAccessRule(id, type, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.CreateChild => new D.CreateChildAccessRule(id, type, f.ObjectType, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.DeleteChild => new D.DeleteChildAccessRule(id, type, f.ObjectType, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.Property => new D.PropertyAccessRule(id, type, property, f.ObjectType, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.PropertySet => new D.PropertySetAccessRule(id, type, property, f.ObjectType, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.ExtendedRight => new D.ExtendedRightAccessRule(id, type, f.ObjectType, inheritance, f.InheritedObjectType),
            InteropAdRuleKind.DeleteTree => new D.DeleteTreeAccessRule(id, type, inheritance, f.InheritedObjectType),
            _ => throw new NotSupportedException("Unknown AD rule subtype.")
        };
        if (!value.Same(CaptureCurrentRule(result))) throw new NotSupportedException("Current AD construction lost fields.");
        return result;
    }

    private static void RequireOutsideGate()
    {
        if (Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("External AD converters cannot run inside the portable mutation gate.");
    }
}
