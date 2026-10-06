// RESEARCH ONLY: controlled subclass dispatch + one fixed descriptor fixture, not an ACL engine.
using System.Runtime.InteropServices;
using System.Security.AccessControl;
namespace AdForLinux.Security.Principal
{
    public sealed class NTAccount : IdentityReference
    {
        public NTAccount(string name) => Value = name ?? throw new ArgumentNullException(nameof(name));
        public override string Value { get; }
    }
}
namespace AdForLinux.Security.AccessControl
{
    // Limited descriptor adapter demonstrates protected constructor/property type closure only.
    public sealed class CommonSecurityDescriptor
    {
        internal static byte[] Fixture => Convert.FromHexString("01000480000000000000000000000000140000000200080000000000");
        private readonly byte[] bytes;
        public CommonSecurityDescriptor(bool container, bool ds, byte[] binary, int offset)
        {
            ArgumentNullException.ThrowIfNull(binary);
            var expected = Fixture;
            if (binary.Length == expected.Length && binary[20] == 4) expected[20] = 4;
            if (offset != 0 || !binary.AsSpan().SequenceEqual(expected))
                throw new NotSupportedException("Research descriptor adapter accepts only its empty-DACL fixture.");
            bytes = binary.ToArray(); IsContainer = container; IsDS = ds;
        }
        public bool IsContainer { get; }
        public bool IsDS { get; }
        internal byte[] CopyBytes() => bytes.ToArray();
        internal static NotSupportedException Unsupported() => new("Research scaffold: general descriptor operations are not implemented.");
    }
    public abstract class ObjectSecurity
    {
        private readonly ReaderWriterLockSlim gate = new(LockRecursionPolicy.SupportsRecursion);
        private CommonSecurityDescriptor? descriptor;
        private readonly bool[] flags = new bool[4];
        protected ObjectSecurity() { }
        protected ObjectSecurity(bool isContainer, bool isDS)
            : this(new CommonSecurityDescriptor(isContainer, isDS, CommonSecurityDescriptor.Fixture, 0)) { }
        protected ObjectSecurity(CommonSecurityDescriptor descriptor) => this.descriptor = descriptor;
        protected CommonSecurityDescriptor SecurityDescriptor => descriptor ?? throw CommonSecurityDescriptor.Unsupported();
        protected bool IsContainer => SecurityDescriptor.IsContainer;
        protected bool IsDS => SecurityDescriptor.IsDS;
        protected void ReadLock() => gate.EnterReadLock();
        protected void ReadUnlock() => gate.ExitReadLock();
        protected void WriteLock() => gate.EnterWriteLock();
        protected void WriteUnlock() => gate.ExitWriteLock();
        private bool ReadFlag(int i)
        {
            if (!gate.IsReadLockHeld && !gate.IsWriteLockHeld) throw new InvalidOperationException("Read/write lock required.");
            return flags[i];
        }
        private void WriteFlag(int i, bool value)
        {
            if (!gate.IsWriteLockHeld) throw new InvalidOperationException("Write lock required.");
            flags[i] = value;
        }
        protected bool OwnerModified { get => ReadFlag(0); set => WriteFlag(0, value); }
        protected bool GroupModified { get => ReadFlag(1); set => WriteFlag(1, value); }
        protected bool AccessRulesModified { get => ReadFlag(2); set => WriteFlag(2, value); }
        protected bool AuditRulesModified { get => ReadFlag(3); set => WriteFlag(3, value); }
        public byte[] GetSecurityDescriptorBinaryForm() => SecurityDescriptor.CopyBytes();
        public void SetSecurityDescriptorBinaryForm(byte[] binary) => descriptor = new CommonSecurityDescriptor(true, true, binary, 0);
        // No permission persistence. Signatures demonstrate overridability, not default BCL exception parity.
        protected virtual void Persist(string name, AccessControlSections sections) => throw CommonSecurityDescriptor.Unsupported();
        protected virtual void Persist(SafeHandle handle, AccessControlSections sections) => throw CommonSecurityDescriptor.Unsupported();
        protected virtual void Persist(bool ownership, string name, AccessControlSections sections)
        {
            if (ownership) throw new PlatformNotSupportedException("Research base does not enable native ownership privilege.");
            Persist(name, sections);
        }
        public abstract Type AccessRightType { get; }
        public abstract Type AccessRuleType { get; }
        public abstract Type AuditRuleType { get; }
        protected abstract bool ModifyAccess(AccessControlModification modification, AccessRule rule, out bool modified);
        protected abstract bool ModifyAudit(AccessControlModification modification, AuditRule rule, out bool modified);
        public virtual bool ModifyAccessRule(AccessControlModification modification, AccessRule rule, out bool modified)
        {
            ArgumentNullException.ThrowIfNull(rule);
            if (!AccessRuleType.IsAssignableFrom(rule.GetType())) throw new ArgumentException("Rule type.", nameof(rule));
            WriteLock(); try { return ModifyAccess(modification, rule, out modified); } finally { WriteUnlock(); }
        }
        public virtual bool ModifyAuditRule(AccessControlModification modification, AuditRule rule, out bool modified)
        {
            ArgumentNullException.ThrowIfNull(rule);
            if (!AuditRuleType.IsAssignableFrom(rule.GetType())) throw new ArgumentException("Rule type.", nameof(rule));
            WriteLock(); try { return ModifyAudit(modification, rule, out modified); } finally { WriteUnlock(); }
        }
        public virtual void PurgeAccessRules(IdentityReference identity) => throw CommonSecurityDescriptor.Unsupported();
        public virtual void PurgeAuditRules(IdentityReference identity) => throw CommonSecurityDescriptor.Unsupported();
        public abstract AccessRule AccessRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type);
        public abstract AuditRule AuditRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags);
    }
    public abstract class DirectoryObjectSecurity : ObjectSecurity
    {
        protected DirectoryObjectSecurity() : base(true, true) { }
        protected DirectoryObjectSecurity(CommonSecurityDescriptor descriptor) : base(descriptor) { }
        protected override bool ModifyAccess(AccessControlModification modification, AccessRule rule, out bool modified) => throw CommonSecurityDescriptor.Unsupported();
        protected override bool ModifyAudit(AccessControlModification modification, AuditRule rule, out bool modified) => throw CommonSecurityDescriptor.Unsupported();
        // Source inspection shows these helpers do NOT dispatch through the protected virtual hook.
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
        public virtual AccessRule AccessRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type, Guid objectType, Guid inheritedObjectType) => throw CommonSecurityDescriptor.Unsupported();
        public virtual AuditRule AuditRuleFactory(IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags, Guid objectType, Guid inheritedObjectType) => throw CommonSecurityDescriptor.Unsupported();
    }
}
