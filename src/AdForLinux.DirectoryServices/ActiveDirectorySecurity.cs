using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;

#pragma warning disable CA1416 // These APIs manipulate in-memory AD descriptors; no local OS ACL is accessed.

namespace AdForLinux.DirectoryServices;

[Flags]
public enum ActiveDirectoryRights
{
    CreateChild = 0x1,
    DeleteChild = 0x2,
    ListChildren = 0x4,
    Self = 0x8,
    ReadProperty = 0x10,
    WriteProperty = 0x20,
    DeleteTree = 0x40,
    ListObject = 0x80,
    ExtendedRight = 0x100,
    Delete = 0x10000,
    ReadControl = 0x20000,
    WriteDacl = 0x40000,
    WriteOwner = 0x80000,
    Synchronize = 0x100000,
    AccessSystemSecurity = 0x1000000,
    GenericRead = ReadControl | ListChildren | ReadProperty | ListObject,
    GenericWrite = ReadControl | Self | WriteProperty,
    GenericExecute = ReadControl | ListChildren,
    GenericAll = Delete | ReadControl | WriteDacl | WriteOwner | CreateChild | DeleteChild |
                 ListChildren | Self | ReadProperty | WriteProperty | DeleteTree | ListObject | ExtendedRight,
}

public enum ActiveDirectorySecurityInheritance
{
    None = 0,
    All = 1,
    Descendents = 2,
    SelfAndChildren = 3,
    Children = 4,
}

public enum PropertyAccess
{
    Read = 0,
    Write = 1,
}

/// <summary>An Active Directory security descriptor backed by the portable access-control model.</summary>
public class ActiveDirectorySecurity : DirectoryObjectSecurity
{
    private readonly SecurityMasks _retrievedMasks;

    public ActiveDirectorySecurity()
    {
        _retrievedMasks = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
    }

    internal ActiveDirectorySecurity(byte[] binaryForm, SecurityMasks retrievedMasks)
        : base(new CommonSecurityDescriptor(true, true, binaryForm, 0))
    {
        _retrievedMasks = retrievedMasks;
    }

    internal SecurityMasks RetrievedMasks => _retrievedMasks;

    internal bool IsModified()
    {
        ReadLock();
        try
        {
            return OwnerModified || GroupModified || AccessRulesModified || AuditRulesModified;
        }
        finally
        {
            ReadUnlock();
        }
    }

    public void AddAccessRule(ActiveDirectoryAccessRule rule)
    {
        RequireDacl();
        base.AddAccessRule(rule);
    }

    public void SetAccessRule(ActiveDirectoryAccessRule rule)
    {
        RequireDacl();
        base.SetAccessRule(rule);
    }

    public void ResetAccessRule(ActiveDirectoryAccessRule rule)
    {
        RequireDacl();
        base.ResetAccessRule(rule);
    }

    public void RemoveAccess(IdentityReference identity, AccessControlType type)
    {
        RequireDacl();
        base.RemoveAccessRuleAll(new ActiveDirectoryAccessRule(
            identity, ActiveDirectoryRights.GenericRead, type));
    }

    public bool RemoveAccessRule(ActiveDirectoryAccessRule rule)
    {
        RequireDacl();
        return base.RemoveAccessRule(rule);
    }

    public void RemoveAccessRuleSpecific(ActiveDirectoryAccessRule rule)
    {
        RequireDacl();
        base.RemoveAccessRuleSpecific(rule);
    }

    public override bool ModifyAccessRule(
        AccessControlModification modification, AccessRule rule, out bool modified)
    {
        RequireDacl();
        return base.ModifyAccessRule(modification, rule, out modified);
    }

    public override void PurgeAccessRules(IdentityReference identity)
    {
        RequireDacl();
        base.PurgeAccessRules(identity);
    }

    public void AddAuditRule(ActiveDirectoryAuditRule rule)
    {
        RequireSacl();
        base.AddAuditRule(rule);
    }

    public void SetAuditRule(ActiveDirectoryAuditRule rule)
    {
        RequireSacl();
        base.SetAuditRule(rule);
    }

    public void RemoveAudit(IdentityReference identity)
    {
        RequireSacl();
        base.RemoveAuditRuleAll(new ActiveDirectoryAuditRule(
            identity, ActiveDirectoryRights.GenericRead, AuditFlags.Success | AuditFlags.Failure));
    }

    public bool RemoveAuditRule(ActiveDirectoryAuditRule rule)
    {
        RequireSacl();
        return base.RemoveAuditRule(rule);
    }

    public void RemoveAuditRuleSpecific(ActiveDirectoryAuditRule rule)
    {
        RequireSacl();
        base.RemoveAuditRuleSpecific(rule);
    }

    public override bool ModifyAuditRule(
        AccessControlModification modification, AuditRule rule, out bool modified)
    {
        RequireSacl();
        return base.ModifyAuditRule(modification, rule, out modified);
    }

    public override void PurgeAuditRules(IdentityReference identity)
    {
        RequireSacl();
        base.PurgeAuditRules(identity);
    }

    public sealed override AccessRule AccessRuleFactory(
        IdentityReference identityReference,
        int accessMask,
        bool isInherited,
        InheritanceFlags inheritanceFlags,
        PropagationFlags propagationFlags,
        AccessControlType type) =>
        new ActiveDirectoryAccessRule(
            identityReference, accessMask, type, Guid.Empty, isInherited,
            inheritanceFlags, propagationFlags, Guid.Empty);

    public sealed override AccessRule AccessRuleFactory(
        IdentityReference identityReference,
        int accessMask,
        bool isInherited,
        InheritanceFlags inheritanceFlags,
        PropagationFlags propagationFlags,
        AccessControlType type,
        Guid objectGuid,
        Guid inheritedObjectGuid) =>
        new ActiveDirectoryAccessRule(
            identityReference, accessMask, type, objectGuid, isInherited,
            inheritanceFlags, propagationFlags, inheritedObjectGuid);

    public sealed override AuditRule AuditRuleFactory(
        IdentityReference identityReference,
        int accessMask,
        bool isInherited,
        InheritanceFlags inheritanceFlags,
        PropagationFlags propagationFlags,
        AuditFlags flags) =>
        new ActiveDirectoryAuditRule(
            identityReference, accessMask, flags, Guid.Empty, isInherited,
            inheritanceFlags, propagationFlags, Guid.Empty);

    public sealed override AuditRule AuditRuleFactory(
        IdentityReference identityReference,
        int accessMask,
        bool isInherited,
        InheritanceFlags inheritanceFlags,
        PropagationFlags propagationFlags,
        AuditFlags flags,
        Guid objectGuid,
        Guid inheritedObjectGuid) =>
        new ActiveDirectoryAuditRule(
            identityReference, accessMask, flags, objectGuid, isInherited,
            inheritanceFlags, propagationFlags, inheritedObjectGuid);

    public override Type AccessRightType => typeof(ActiveDirectoryRights);

    public override Type AccessRuleType => typeof(ActiveDirectoryAccessRule);

    public override Type AuditRuleType => typeof(ActiveDirectoryAuditRule);

    private void RequireDacl()
    {
        if ((_retrievedMasks & SecurityMasks.Dacl) == 0)
        {
            throw new InvalidOperationException("The discretionary ACL was not retrieved and cannot be modified.");
        }
    }

    private void RequireSacl()
    {
        if ((_retrievedMasks & SecurityMasks.Sacl) == 0)
        {
            throw new InvalidOperationException("The system ACL was not retrieved and cannot be modified.");
        }
    }
}

internal static class ActiveDirectoryInheritance
{
    internal static InheritanceFlags GetInheritanceFlags(ActiveDirectorySecurityInheritance inheritanceType)
    {
        Validate(inheritanceType);
        return inheritanceType == ActiveDirectorySecurityInheritance.None
            ? InheritanceFlags.None
            : InheritanceFlags.ContainerInherit;
    }

    internal static PropagationFlags GetPropagationFlags(ActiveDirectorySecurityInheritance inheritanceType)
    {
        Validate(inheritanceType);
        return inheritanceType switch
        {
            ActiveDirectorySecurityInheritance.None or ActiveDirectorySecurityInheritance.All =>
                PropagationFlags.None,
            ActiveDirectorySecurityInheritance.Descendents => PropagationFlags.InheritOnly,
            ActiveDirectorySecurityInheritance.SelfAndChildren => PropagationFlags.NoPropagateInherit,
            ActiveDirectorySecurityInheritance.Children =>
                PropagationFlags.InheritOnly | PropagationFlags.NoPropagateInherit,
            _ => throw new ArgumentOutOfRangeException(nameof(inheritanceType)),
        };
    }

    internal static ActiveDirectorySecurityInheritance FromFlags(
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
    {
        if ((inheritanceFlags & InheritanceFlags.ContainerInherit) == 0)
        {
            return ActiveDirectorySecurityInheritance.None;
        }

        return propagationFlags switch
        {
            PropagationFlags.None => ActiveDirectorySecurityInheritance.All,
            PropagationFlags.InheritOnly => ActiveDirectorySecurityInheritance.Descendents,
            PropagationFlags.NoPropagateInherit => ActiveDirectorySecurityInheritance.SelfAndChildren,
            PropagationFlags.InheritOnly | PropagationFlags.NoPropagateInherit =>
                ActiveDirectorySecurityInheritance.Children,
            _ => throw new ArgumentException("Invalid propagation flags.", nameof(propagationFlags)),
        };
    }

    private static void Validate(ActiveDirectorySecurityInheritance value)
    {
        if (value < ActiveDirectorySecurityInheritance.None || value > ActiveDirectorySecurityInheritance.Children)
        {
            throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ActiveDirectorySecurityInheritance));
        }
    }
}

public class ActiveDirectoryAccessRule : ObjectAccessRule
{
    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type)
        : this(identity, (int)adRights, type, Guid.Empty, false,
            InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
    {
    }

    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, Guid objectType)
        : this(identity, (int)adRights, type, objectType, false,
            InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
    {
    }

    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type,
        ActiveDirectorySecurityInheritance inheritanceType)
        : this(identity, (int)adRights, type, Guid.Empty, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), Guid.Empty)
    {
    }

    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type,
        Guid objectType, ActiveDirectorySecurityInheritance inheritanceType)
        : this(identity, (int)adRights, type, objectType, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), Guid.Empty)
    {
    }

    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : this(identity, (int)adRights, type, Guid.Empty, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), inheritedObjectType)
    {
    }

    public ActiveDirectoryAccessRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type,
        Guid objectType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : this(identity, (int)adRights, type, objectType, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), inheritedObjectType)
    {
    }

    internal ActiveDirectoryAccessRule(
        IdentityReference identity, int accessMask, AccessControlType type, Guid objectType,
        bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags,
        Guid inheritedObjectType)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags,
            objectType, inheritedObjectType, type)
    {
    }

    public ActiveDirectoryRights ActiveDirectoryRights => (ActiveDirectoryRights)AccessMask;

    public ActiveDirectorySecurityInheritance InheritanceType =>
        ActiveDirectoryInheritance.FromFlags(InheritanceFlags, PropagationFlags);
}

public sealed class ListChildrenAccessRule : ActiveDirectoryAccessRule
{
    public ListChildrenAccessRule(IdentityReference identity, AccessControlType type)
        : base(identity, ActiveDirectoryRights.ListChildren, type) { }

    public ListChildrenAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.ListChildren, type, inheritanceType) { }

    public ListChildrenAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType,
        Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.ListChildren, type, inheritanceType, inheritedObjectType) { }
}

public sealed class CreateChildAccessRule : ActiveDirectoryAccessRule
{
    public CreateChildAccessRule(IdentityReference identity, AccessControlType type)
        : base(identity, ActiveDirectoryRights.CreateChild, type) { }

    public CreateChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType)
        : base(identity, ActiveDirectoryRights.CreateChild, type, childType) { }

    public CreateChildAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.CreateChild, type, inheritanceType) { }

    public CreateChildAccessRule(
        IdentityReference identity, AccessControlType type, Guid childType,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.CreateChild, type, childType, inheritanceType) { }

    public CreateChildAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType,
        Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.CreateChild, type, inheritanceType, inheritedObjectType) { }

    public CreateChildAccessRule(
        IdentityReference identity, AccessControlType type, Guid childType,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.CreateChild, type, childType, inheritanceType, inheritedObjectType) { }
}

public sealed class DeleteChildAccessRule : ActiveDirectoryAccessRule
{
    public DeleteChildAccessRule(IdentityReference identity, AccessControlType type)
        : base(identity, ActiveDirectoryRights.DeleteChild, type) { }

    public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType)
        : base(identity, ActiveDirectoryRights.DeleteChild, type, childType) { }

    public DeleteChildAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.DeleteChild, type, inheritanceType) { }

    public DeleteChildAccessRule(
        IdentityReference identity, AccessControlType type, Guid childType,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.DeleteChild, type, childType, inheritanceType) { }

    public DeleteChildAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType,
        Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.DeleteChild, type, inheritanceType, inheritedObjectType) { }

    public DeleteChildAccessRule(
        IdentityReference identity, AccessControlType type, Guid childType,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.DeleteChild, type, childType, inheritanceType, inheritedObjectType) { }
}

public sealed class PropertyAccessRule : ActiveDirectoryAccessRule
{
    public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access)
        : base(identity, Rights(access), type) { }

    public PropertyAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType)
        : base(identity, Rights(access), type, propertyType) { }

    public PropertyAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, Rights(access), type, inheritanceType) { }

    public PropertyAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, Rights(access), type, propertyType, inheritanceType) { }

    public PropertyAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, Rights(access), type, inheritanceType, inheritedObjectType) { }

    public PropertyAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, Rights(access), type, propertyType, inheritanceType, inheritedObjectType) { }

    private static ActiveDirectoryRights Rights(PropertyAccess access) => access switch
    {
        PropertyAccess.Read => ActiveDirectoryRights.ReadProperty,
        PropertyAccess.Write => ActiveDirectoryRights.WriteProperty,
        _ => throw new InvalidEnumArgumentException(nameof(access), (int)access, typeof(PropertyAccess)),
    };
}

public sealed class PropertySetAccessRule : ActiveDirectoryAccessRule
{
    public PropertySetAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType)
        : base(identity, Rights(access), type, propertySetType) { }

    public PropertySetAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, Rights(access), type, propertySetType, inheritanceType) { }

    public PropertySetAccessRule(
        IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, Rights(access), type, propertySetType, inheritanceType, inheritedObjectType) { }

    private static ActiveDirectoryRights Rights(PropertyAccess access) => access switch
    {
        PropertyAccess.Read => ActiveDirectoryRights.ReadProperty,
        PropertyAccess.Write => ActiveDirectoryRights.WriteProperty,
        _ => throw new InvalidEnumArgumentException(nameof(access), (int)access, typeof(PropertyAccess)),
    };
}

public sealed class ExtendedRightAccessRule : ActiveDirectoryAccessRule
{
    public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type) { }

    public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, Guid extendedRightType)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type, extendedRightType) { }

    public ExtendedRightAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type, inheritanceType) { }

    public ExtendedRightAccessRule(
        IdentityReference identity, AccessControlType type, Guid extendedRightType,
        ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type, extendedRightType, inheritanceType) { }

    public ExtendedRightAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType,
        Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type, inheritanceType, inheritedObjectType) { }

    public ExtendedRightAccessRule(
        IdentityReference identity, AccessControlType type, Guid extendedRightType,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.ExtendedRight, type, extendedRightType, inheritanceType, inheritedObjectType) { }
}

public sealed class DeleteTreeAccessRule : ActiveDirectoryAccessRule
{
    public DeleteTreeAccessRule(IdentityReference identity, AccessControlType type)
        : base(identity, ActiveDirectoryRights.DeleteTree, type) { }

    public DeleteTreeAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
        : base(identity, ActiveDirectoryRights.DeleteTree, type, inheritanceType) { }

    public DeleteTreeAccessRule(
        IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType,
        Guid inheritedObjectType)
        : base(identity, ActiveDirectoryRights.DeleteTree, type, inheritanceType, inheritedObjectType) { }
}

public class ActiveDirectoryAuditRule : ObjectAuditRule
{
    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags)
        : this(identity, (int)adRights, auditFlags, Guid.Empty, false,
            InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
    {
    }

    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, Guid objectType)
        : this(identity, (int)adRights, auditFlags, objectType, false,
            InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
    {
    }

    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags,
        ActiveDirectorySecurityInheritance inheritanceType)
        : this(identity, (int)adRights, auditFlags, Guid.Empty, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), Guid.Empty)
    {
    }

    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags,
        Guid objectType, ActiveDirectorySecurityInheritance inheritanceType)
        : this(identity, (int)adRights, auditFlags, objectType, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), Guid.Empty)
    {
    }

    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags,
        ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : this(identity, (int)adRights, auditFlags, Guid.Empty, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), inheritedObjectType)
    {
    }

    public ActiveDirectoryAuditRule(
        IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags,
        Guid objectType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
        : this(identity, (int)adRights, auditFlags, objectType, false,
            ActiveDirectoryInheritance.GetInheritanceFlags(inheritanceType),
            ActiveDirectoryInheritance.GetPropagationFlags(inheritanceType), inheritedObjectType)
    {
    }

    internal ActiveDirectoryAuditRule(
        IdentityReference identity, int accessMask, AuditFlags auditFlags, Guid objectType,
        bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags,
        Guid inheritedObjectType)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags,
            objectType, inheritedObjectType, auditFlags)
    {
    }

    public ActiveDirectoryRights ActiveDirectoryRights => (ActiveDirectoryRights)AccessMask;

    public ActiveDirectorySecurityInheritance InheritanceType =>
        ActiveDirectoryInheritance.FromFlags(InheritanceFlags, PropagationFlags);
}
