using System.Runtime.Versioning;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
using M = System.DirectoryServices;
using MA = System.Security.AccessControl;
using MP = System.Security.Principal;

namespace AdForLinux.DirectoryServices.MicrosoftInterop;

/// <summary>Strict independent copies and optional checked edit-back at Microsoft API boundaries.</summary>
[SupportedOSPlatform("windows")]
public static class MicrosoftConversions
{
    public static MP.SecurityIdentifier ToMicrosoftObject(this P.SecurityIdentifier source)
        => (MP.SecurityIdentifier)ToMicrosoftObject((P.IdentityReference)source);
    public static P.SecurityIdentifier ToPortableObject(this MP.SecurityIdentifier source)
        => (P.SecurityIdentifier)ToPortableObject((MP.IdentityReference)source);
    public static MP.NTAccount ToMicrosoftObject(this P.NTAccount source)
        => (MP.NTAccount)ToMicrosoftObject((P.IdentityReference)source);
    public static P.NTAccount ToPortableObject(this MP.NTAccount source)
        => (P.NTAccount)ToPortableObject((MP.IdentityReference)source);
    public static MP.IdentityReference ToMicrosoftObject(this P.IdentityReference source)
        => A.InteropValueCodec.ToMicrosoftIdentity(source);
    public static P.IdentityReference ToPortableObject(this MP.IdentityReference source)
        => A.InteropValueCodec.FromMicrosoftIdentity(source);

    public static M.ActiveDirectoryAccessRule ToMicrosoftObject(this ActiveDirectoryAccessRule source)
        => (M.ActiveDirectoryAccessRule)ExportRule(source);
    public static ActiveDirectoryAccessRule ToPortableObject(this M.ActiveDirectoryAccessRule source)
        => (ActiveDirectoryAccessRule)ImportRule(source);
    public static M.ActiveDirectoryAuditRule ToMicrosoftObject(this ActiveDirectoryAuditRule source)
        => (M.ActiveDirectoryAuditRule)ExportRule(source);
    public static ActiveDirectoryAuditRule ToPortableObject(this M.ActiveDirectoryAuditRule source)
        => (ActiveDirectoryAuditRule)ImportRule(source);

    public static IReadOnlyList<MP.IdentityReference> ToMicrosoftObjects(this P.IdentityReferenceCollection source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        var values = source.Select(A.InteropValueCodec.CaptureIdentity).ToArray();
        return Array.AsReadOnly(values.Select(value => value.ToPortable().ToMicrosoftObject()).ToArray());
    }
    public static IReadOnlyList<P.IdentityReference> ToPortableObjects(this MP.IdentityReferenceCollection source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        return Array.AsReadOnly(source.Select(A.InteropValueCodec.FromMicrosoftIdentity).ToArray());
    }
    public static IReadOnlyList<MA.AuthorizationRule> ToMicrosoftObjects(this A.AuthorizationRuleCollection source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        var values = source.Cast<A.AuthorizationRule>().Select(A.InteropAdRuleCodec.CaptureCurrentRule).ToArray();
        return Array.AsReadOnly(values.Select(value => A.InteropAdRuleCodec.Export(value, ConstructRule, InspectRule)).ToArray());
    }
    public static IReadOnlyList<A.AuthorizationRule> ToPortableObjects(this MA.AuthorizationRuleCollection source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        var values = source.Cast<MA.AuthorizationRule>().Select(rule => A.InteropAdRuleCodec.Import(rule, InspectRule)).ToArray();
        return Array.AsReadOnly(values.Select(A.InteropAdRuleCodec.CreateCurrentRule).ToArray());
    }

    /// <summary>Copies the observable descriptor without linking subsequent edits or directory authority.</summary>
    public static M.ActiveDirectorySecurity ToMicrosoftObject(this ActiveDirectorySecurity source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        return source.ExportDetachedInterop(ConstructSecurity, value => value.GetSecurityDescriptorBinaryForm());
    }

    /// <summary>Imports detached data with explicit coverage; does not transfer pending intent or a connection.</summary>
    public static ActiveDirectorySecurity ToPortableObject(this M.ActiveDirectorySecurity source, SecurityMasks retrievedSections)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        const SecurityMasks all = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
        if ((retrievedSections & ~all) != 0) throw new ArgumentOutOfRangeException(nameof(retrievedSections));
        var bytes = source.GetSecurityDescriptorBinaryForm();
        var result = new ActiveDirectorySecurity(bytes, retrievedSections);
        A.ObjectSecurity.ValidateInteropImport(bytes, result.GetSecurityDescriptorBinaryForm());
        return result;
    }

    public static SecurityDescriptorSnapshot CaptureSnapshot(this ActiveDirectorySecurity source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return new(source.CaptureInteropSnapshot());
    }

    public static MicrosoftSecurityEdit ExportForEdit(this ActiveDirectorySecurity source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        var export = source.ExportInterop(ConstructSecurity, value => value.GetSecurityDescriptorBinaryForm());
        return new(export.Value, export.Provenance);
    }

    internal static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Microsoft DirectoryServices interoperability requires Windows.");
    }

    internal static M.ActiveDirectorySecurity ConstructSecurity(byte[] bytes, bool container, bool directory)
    {
        RequireWindows();
        if (!container || !directory) throw new NotSupportedException("The AD companion requires a directory container descriptor.");
        var result = new M.ActiveDirectorySecurity();
        result.SetSecurityDescriptorBinaryForm(bytes, MA.AccessControlSections.All);
        return result;
    }

    private static MA.AuthorizationRule ExportRule(A.AuthorizationRule source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        return A.InteropAdRuleCodec.Export(A.InteropAdRuleCodec.CaptureCurrentRule(source), ConstructRule, InspectRule);
    }
    private static A.AuthorizationRule ImportRule(MA.AuthorizationRule source)
    {
        ArgumentNullException.ThrowIfNull(source); RequireWindows();
        return A.InteropAdRuleCodec.CreateCurrentRule(A.InteropAdRuleCodec.Import(source, InspectRule));
    }

    private static A.InteropAdRuleValue InspectRule(MA.AuthorizationRule source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var type = source.GetType();
        var kind = type == typeof(M.ActiveDirectoryAccessRule) ? A.InteropAdRuleKind.Access
            : type == typeof(M.ActiveDirectoryAuditRule) ? A.InteropAdRuleKind.Audit
            : type == typeof(M.ListChildrenAccessRule) ? A.InteropAdRuleKind.ListChildren
            : type == typeof(M.CreateChildAccessRule) ? A.InteropAdRuleKind.CreateChild
            : type == typeof(M.DeleteChildAccessRule) ? A.InteropAdRuleKind.DeleteChild
            : type == typeof(M.PropertyAccessRule) ? A.InteropAdRuleKind.Property
            : type == typeof(M.PropertySetAccessRule) ? A.InteropAdRuleKind.PropertySet
            : type == typeof(M.ExtendedRightAccessRule) ? A.InteropAdRuleKind.ExtendedRight
            : type == typeof(M.DeleteTreeAccessRule) ? A.InteropAdRuleKind.DeleteTree
            : throw new NotSupportedException("Unknown Microsoft AD rule subclasses cannot be converted implicitly.");
        var access = source as M.ActiveDirectoryAccessRule;
        var audit = source as M.ActiveDirectoryAuditRule;
        var fields = new A.InteropRuleValue(A.InteropValueCodec.CaptureIdentity(source.IdentityReference.ToPortableObject()),
            (int)(access?.ActiveDirectoryRights ?? audit!.ActiveDirectoryRights), source.IsInherited,
            source.InheritanceFlags, source.PropagationFlags, audit is not null, true,
            access?.AccessControlType ?? MA.AccessControlType.Allow, audit?.AuditFlags ?? MA.AuditFlags.None,
            access?.ObjectType ?? audit!.ObjectType, access?.InheritedObjectType ?? audit!.InheritedObjectType,
            access?.ObjectFlags ?? audit!.ObjectFlags);
        return new(kind, fields, (ActiveDirectorySecurityInheritance)(access?.InheritanceType ?? audit!.InheritanceType));
    }

    private static MA.AuthorizationRule ConstructRule(A.InteropAdRuleValue value)
    {
        var f = value.Fields;
        var identity = f.Identity.ToPortable().ToMicrosoftObject();
        var inheritance = (M.ActiveDirectorySecurityInheritance)value.InheritanceType;
        var property = f.Mask == 16 ? M.PropertyAccess.Read : M.PropertyAccess.Write;
        return value.Kind switch
        {
            A.InteropAdRuleKind.Access => new M.ActiveDirectorySecurity().AccessRuleFactory(identity, f.Mask, f.IsInherited,
                f.Inheritance, f.Propagation, f.AccessType, f.ObjectType, f.InheritedObjectType),
            A.InteropAdRuleKind.Audit => new M.ActiveDirectorySecurity().AuditRuleFactory(identity, f.Mask, f.IsInherited,
                f.Inheritance, f.Propagation, f.Audit, f.ObjectType, f.InheritedObjectType),
            A.InteropAdRuleKind.ListChildren => new M.ListChildrenAccessRule(identity, f.AccessType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.CreateChild => new M.CreateChildAccessRule(identity, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.DeleteChild => new M.DeleteChildAccessRule(identity, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.Property => new M.PropertyAccessRule(identity, f.AccessType, property, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.PropertySet => new M.PropertySetAccessRule(identity, f.AccessType, property, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.ExtendedRight => new M.ExtendedRightAccessRule(identity, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.DeleteTree => new M.DeleteTreeAccessRule(identity, f.AccessType, inheritance, f.InheritedObjectType),
            _ => throw new NotSupportedException("Unknown AD rule subtype.")
        };
    }
}
