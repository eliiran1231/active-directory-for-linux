#pragma warning disable CA1416 // Framework access-control enums are values; no Windows APIs are invoked.
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// Portable implementation of the contracts in dotnet/runtime v9.0.0 Rules.cs:
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/Rules.cs
// Changes: portable identities, shared GUID-scope calculation, local exception text.
// See RULES-LICENSE.txt for the upstream license.

using System.Collections;
using System.Security.AccessControl;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

/// <summary>A detached authorization rule with a portable identity and a validated access mask.</summary>
public abstract class AuthorizationRule
{
    protected internal AuthorizationRule(IdentityReference identity, int accessMask, bool isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
    {
        // Preserve constructor validation precedence, including propagation validation before
        // the no-inheritance normalization. Construction does not resolve account names.
        ArgumentNullException.ThrowIfNull(identity);
        if (accessMask == 0) throw new ArgumentException("The access mask must be nonzero.", nameof(accessMask));
        if ((uint)inheritanceFlags > 3) throw new ArgumentOutOfRangeException(nameof(inheritanceFlags));
        if ((uint)propagationFlags > 3) throw new ArgumentOutOfRangeException(nameof(propagationFlags));
        if (!identity.IsValidTargetType(typeof(SecurityIdentifier)))
            throw new ArgumentException("The identity cannot represent a security identifier.", nameof(identity));
        IdentityReference = identity;
        AccessMask = accessMask;
        IsInherited = isInherited;
        InheritanceFlags = inheritanceFlags;
        PropagationFlags = inheritanceFlags == InheritanceFlags.None ? PropagationFlags.None : propagationFlags;
    }

    public IdentityReference IdentityReference { get; }
    protected internal int AccessMask { get; }
    public bool IsInherited { get; }
    public InheritanceFlags InheritanceFlags { get; }
    public PropagationFlags PropagationFlags { get; }
}

/// <summary>A detached allow or deny rule.</summary>
public abstract class AccessRule : AuthorizationRule
{
    protected AccessRule(IdentityReference identity, int accessMask, bool isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags)
    {
        if (type is not (AccessControlType.Allow or AccessControlType.Deny))
            throw new ArgumentOutOfRangeException(nameof(type));
        AccessControlType = type;
    }

    public AccessControlType AccessControlType { get; }
}

/// <summary>A detached success and/or failure audit rule.</summary>
public abstract class AuditRule : AuthorizationRule
{
    protected AuditRule(IdentityReference identity, int accessMask, bool isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags auditFlags)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags)
    {
        if (auditFlags == AuditFlags.None)
            throw new ArgumentException("At least one audit flag is required.", nameof(auditFlags));
        if ((auditFlags & ~(AuditFlags.Success | AuditFlags.Failure)) != 0)
            throw new ArgumentOutOfRangeException(nameof(auditFlags));
        AuditFlags = auditFlags;
    }

    public AuditFlags AuditFlags { get; }
}

/// <summary>An access rule qualified by directory object and inherited-object types.</summary>
public abstract class ObjectAccessRule : AccessRule
{
    protected ObjectAccessRule(IdentityReference identity, int accessMask, bool isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Guid objectType,
        Guid inheritedObjectType, AccessControlType type)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, type)
    {
        (ObjectType, InheritedObjectType, ObjectFlags) = ObjectRuleScope.Create(accessMask,
            inheritanceFlags, objectType, inheritedObjectType);
    }

    public Guid ObjectType { get; }
    public Guid InheritedObjectType { get; }
    public ObjectAceFlags ObjectFlags { get; }
}

/// <summary>An audit rule qualified by directory object and inherited-object types.</summary>
public abstract class ObjectAuditRule : AuditRule
{
    protected ObjectAuditRule(IdentityReference identity, int accessMask, bool isInherited,
        InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Guid objectType,
        Guid inheritedObjectType, AuditFlags auditFlags)
        : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, auditFlags)
    {
        (ObjectType, InheritedObjectType, ObjectFlags) = ObjectRuleScope.Create(accessMask,
            inheritanceFlags, objectType, inheritedObjectType);
    }

    public Guid ObjectType { get; }
    public Guid InheritedObjectType { get; }
    public ObjectAceFlags ObjectFlags { get; }
}

internal static class ObjectRuleScope
{
    // Directory create/delete child, validated write, read/write property and control access.
    private const int ObjectQualifiedRights = 0x13b;

    internal static (Guid Object, Guid InheritedObject, ObjectAceFlags Flags) Create(int mask,
        InheritanceFlags inheritance, Guid objectType, Guid inheritedObjectType)
    {
        var own = (mask & ObjectQualifiedRights) != 0 ? objectType : Guid.Empty;
        var inherited = (inheritance & InheritanceFlags.ContainerInherit) != 0 ? inheritedObjectType : Guid.Empty;
        var flags = (own != Guid.Empty ? ObjectAceFlags.ObjectAceTypePresent : ObjectAceFlags.None)
            | (inherited != Guid.Empty ? ObjectAceFlags.InheritedObjectAceTypePresent : ObjectAceFlags.None);
        return (own, inherited, flags);
    }
}

/// <summary>A detached rule collection. Adding rules never modifies a security descriptor.</summary>
public sealed class AuthorizationRuleCollection : ReadOnlyCollectionBase
{
    public AuthorizationRuleCollection() { }
    public void AddRule(AuthorizationRule? rule) => InnerList.Add(rule);
    public AuthorizationRule? this[int index] => InnerList[index] as AuthorizationRule;
    public void CopyTo(AuthorizationRule[] rules, int index) => ((ICollection)this).CopyTo(rules, index);
}
