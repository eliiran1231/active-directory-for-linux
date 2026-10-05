// Deliberately incomplete research scaffolding. NOT an ACL implementation or shipping API.
// All security-descriptor operations fail explicitly; only value construction is exercised.
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.Security.Principal
{
    public abstract class IdentityReference
    {
        internal IdentityReference() { }
        public abstract string Value { get; }
    }
    public sealed class SecurityIdentifier : IdentityReference
    {
        private readonly byte[] bytes;
        public SecurityIdentifier(string value) => bytes = SidCodec.Parse(value);
        public SecurityIdentifier(byte[] value, int offset)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (offset < 0 || offset > value.Length - 8) throw new ArgumentOutOfRangeException(nameof(offset));
            var length = 8 + 4 * value[offset + 1];
            if (length > value.Length - offset) throw new ArgumentException("Truncated SID.", nameof(value));
            bytes = value.AsSpan(offset, length).ToArray();
            _ = SidCodec.Format(bytes); // Validates revision/count using existing helper.
        }
        public override string Value => SidCodec.Format(bytes); // Decimal authority, consistent with managed SID source; complete parser parity unproven.
        public int BinaryLength => bytes.Length;
        public void GetBinaryForm(byte[] destination, int offset) => bytes.CopyTo(destination, offset);
    }
}
namespace AdForLinux.DirectoryServices
{
    // Source-compatible fixture for the only enum needed from DirectoryEntryConfiguration.cs.
    // Exact values are checked by the runner; no DirectoryEntry/LDAP implementation is linked.
    [Flags] public enum SecurityMasks { None = 0, Owner = 1, Group = 2, Dacl = 4, Sacl = 8 }
}
namespace AdForLinux.Security.AccessControl
{
    public abstract class AuthorizationRule
    {
        protected AuthorizationRule(IdentityReference identity, int mask, bool inherited,
            InheritanceFlags inheritance, PropagationFlags propagation)
        {
            IdentityReference = identity ?? throw new ArgumentNullException(nameof(identity));
            AccessMask = mask; IsInherited = inherited; InheritanceFlags = inheritance; PropagationFlags = propagation;
        }
        public IdentityReference IdentityReference { get; }
        protected int AccessMask { get; }
        public bool IsInherited { get; }
        public InheritanceFlags InheritanceFlags { get; }
        public PropagationFlags PropagationFlags { get; }
    }
    public abstract class AccessRule : AuthorizationRule
    {
        protected AccessRule(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance,
            PropagationFlags propagation, AccessControlType type) : base(identity, mask, inherited, inheritance, propagation) => AccessControlType = type;
        public AccessControlType AccessControlType { get; }
    }
    public abstract class AuditRule : AuthorizationRule
    {
        protected AuditRule(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance,
            PropagationFlags propagation, AuditFlags flags) : base(identity, mask, inherited, inheritance, propagation) => AuditFlags = flags;
        public AuditFlags AuditFlags { get; }
    }
    public abstract class ObjectAccessRule : AccessRule
    {
        protected ObjectAccessRule(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance,
            PropagationFlags propagation, Guid objectType, Guid inheritedObjectType, AccessControlType type)
            : base(identity, mask, inherited, inheritance, propagation, type)
        {
            ObjectType = objectType; InheritedObjectType = inheritedObjectType;
            ObjectFlags = (objectType == Guid.Empty ? 0 : ObjectAceFlags.ObjectAceTypePresent)
                | (inheritedObjectType == Guid.Empty ? 0 : ObjectAceFlags.InheritedObjectAceTypePresent);
        }
        public Guid ObjectType { get; }
        public Guid InheritedObjectType { get; }
        public ObjectAceFlags ObjectFlags { get; }
    }
    public abstract class ObjectAuditRule : AuditRule
    {
        protected ObjectAuditRule(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance,
            PropagationFlags propagation, Guid objectType, Guid inheritedObjectType, AuditFlags flags)
            : base(identity, mask, inherited, inheritance, propagation, flags)
        {
            ObjectType = objectType; InheritedObjectType = inheritedObjectType;
            ObjectFlags = (objectType == Guid.Empty ? 0 : ObjectAceFlags.ObjectAceTypePresent)
                | (inheritedObjectType == Guid.Empty ? 0 : ObjectAceFlags.InheritedObjectAceTypePresent);
        }
        public Guid ObjectType { get; }
        public Guid InheritedObjectType { get; }
        public ObjectAceFlags ObjectFlags { get; }
    }
    // Only satisfies the existing internal constructor's compile dependency. Not a proposed public type.
    public sealed class CommonSecurityDescriptor
    {
        public CommonSecurityDescriptor(bool container, bool ds, byte[] binary, int offset) => throw Unsupported();
        internal static NotSupportedException Unsupported() => new("Research scaffold: descriptor operations are not implemented.");
    }
    public abstract class ObjectSecurity
    {
        protected bool OwnerModified => false;
        protected bool GroupModified => false;
        protected bool AccessRulesModified => false;
        protected bool AuditRulesModified => false;
        protected void ReadLock() => throw CommonSecurityDescriptor.Unsupported();
        protected void ReadUnlock() => throw CommonSecurityDescriptor.Unsupported();
        public abstract Type AccessRightType { get; }
        public abstract Type AccessRuleType { get; }
        public abstract Type AuditRuleType { get; }
        public virtual bool ModifyAccessRule(AccessControlModification modification, AccessRule rule, out bool modified) => throw CommonSecurityDescriptor.Unsupported();
        public virtual bool ModifyAuditRule(AccessControlModification modification, AuditRule rule, out bool modified) => throw CommonSecurityDescriptor.Unsupported();
        public virtual void PurgeAccessRules(IdentityReference identity) => throw CommonSecurityDescriptor.Unsupported();
        public virtual void PurgeAuditRules(IdentityReference identity) => throw CommonSecurityDescriptor.Unsupported();
        public abstract AccessRule AccessRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type);
        public abstract AuditRule AuditRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags);
    }
    public abstract class DirectoryObjectSecurity : ObjectSecurity
    {
        protected DirectoryObjectSecurity() { }
        protected DirectoryObjectSecurity(CommonSecurityDescriptor descriptor) => throw CommonSecurityDescriptor.Unsupported();
        protected void AddAccessRule(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void SetAccessRule(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void ResetAccessRule(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected bool RemoveAccessRule(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void RemoveAccessRuleAll(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void RemoveAccessRuleSpecific(ObjectAccessRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void AddAuditRule(ObjectAuditRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void SetAuditRule(ObjectAuditRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected bool RemoveAuditRule(ObjectAuditRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void RemoveAuditRuleAll(ObjectAuditRule rule) => throw CommonSecurityDescriptor.Unsupported();
        protected void RemoveAuditRuleSpecific(ObjectAuditRule rule) => throw CommonSecurityDescriptor.Unsupported();
        public abstract AccessRule AccessRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type, Guid objectType, Guid inheritedObjectType);
        public abstract AuditRule AuditRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags, Guid objectType, Guid inheritedObjectType);
    }
}
