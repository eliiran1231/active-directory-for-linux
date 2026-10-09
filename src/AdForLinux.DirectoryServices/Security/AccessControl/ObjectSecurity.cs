#pragma warning disable CA1416 // Shared framework enum values only.
// Adapted from dotnet/runtime v9.0.0; see DESCRIPTORS-LICENSE.txt.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ObjectSecurity.cs
// Portable identity/facade types; no implicit persistence or privilege adjustment.
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*============================================================
**
** Classes:  Object Security family of classes
**
**
===========================================================*/

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using AdForLinux.Security.Principal;
using System.Security.AccessControl;
using System.Threading;
using AdForLinux.DirectoryServices;
using C = AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.Security.AccessControl
{

    public abstract partial class ObjectSecurity
    {
        #region Private Members

        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);

        internal readonly CommonSecurityDescriptor _securityDescriptor = null!;

        // Data-only read context is local to this wrapper. It contains no resolver,
        // credentials, connections, persistence capability or ambient authority.
        private sealed record ReadContext(C.SecurityDescriptor Original, long Version, IdentityReadOrigin? Origin = null);
        private ReadContext? _readContext;
        internal bool HasRawReadContext { get; private set; }
        internal IdentityReadOrigin? RawReadOrigin => _readContext?.Origin;
        internal long ReadVersion => _readContext?.Version ?? 0;
        internal void SetRawReadContext(SecurityMasks retrieved, DirectoryIdentityResolver source)
        {
            if ((retrieved & ~(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl)) != 0 || retrieved == SecurityMasks.None)
                throw new ArgumentOutOfRangeException(nameof(retrieved));
            source.Checked(() =>
            {
                lock (FacadeMutation.Gate)
                {
                if (_securityDescriptor.MutationVersion != 0) throw new InvalidOperationException("A read context cannot replace pending edits.");
                _readContext = new ReadContext(C.SecurityDescriptor.Parse(_securityDescriptor.MutationState.Descriptor.GetBinaryForm(), retrieved), 0, source.GetReadOrigin());
                HasRawReadContext = true;
                identityAttachment++;
                return true;
                }
            });
        }
        internal C.SecurityDescriptor? OriginalReadSnapshot => _readContext?.Original;
        internal SecurityMasks RetrievedSections => _readContext?.Original.RetrievedSections ?? SecurityMasks.None;
        internal SecurityMasks PendingWriteSections => _readContext is null ? SecurityMasks.None
            : _securityDescriptor.ChangesSince(_readContext.Version) & RetrievedSections;

        private bool _ownerModified;
        private bool _groupModified;
        private bool _saclModified;
        private bool _daclModified;

        // only these SACL control flags will be automatically carry forward
        // when update with new security descriptor.
        private const ControlFlags SACL_CONTROL_FLAGS =
            ControlFlags.SystemAclPresent |
            ControlFlags.SystemAclAutoInherited |
            ControlFlags.SystemAclProtected;

        // only these DACL control flags will be automatically carry forward
        // when update with new security descriptor
        private const ControlFlags DACL_CONTROL_FLAGS =
            ControlFlags.DiscretionaryAclPresent |
            ControlFlags.DiscretionaryAclAutoInherited |
            ControlFlags.DiscretionaryAclProtected;

        #endregion

        #region Constructors

        protected ObjectSecurity()
        {
        }

        protected ObjectSecurity(bool isContainer, bool isDS)
            : this()
        {
            // we will create an empty DACL, denying anyone any access as the default. 5 is the capacity.
            DiscretionaryAcl dacl = new DiscretionaryAcl(isContainer, isDS, 5);
            _securityDescriptor = new CommonSecurityDescriptor(isContainer, isDS, ControlFlags.None, null, null, null, dacl);
            lock (FacadeMutation.Gate) _readContext = new ReadContext(_securityDescriptor.MutationState.Descriptor, _securityDescriptor.MutationVersion);
        }

        protected ObjectSecurity(CommonSecurityDescriptor securityDescriptor)
            : this()
        {
            ArgumentNullException.ThrowIfNull(securityDescriptor);

            _securityDescriptor = securityDescriptor;
            lock (FacadeMutation.Gate) _readContext = new ReadContext(_securityDescriptor.MutationState.Descriptor, _securityDescriptor.MutationVersion);
        }

        #endregion

        #region Private methods

        private void UpdateWithNewSecurityDescriptor(RawSecurityDescriptor newOne, AccessControlSections includeSections) => FacadeMutation.Run(() =>
        {
            RequireRetrievedSection(RawSecurityWritePreparation.Masks(includeSections & AccessControlSections.All));
            FacadeMutation.ValidateSectionImport(newOne);
            CaptureDirtyFlags();
            UpdateWithNewSecurityDescriptorCore(newOne, includeSections);
        });

        internal void CaptureDirtyFlags()
        {
            FacadeMutation.Capture(this, () =>
            {
                var owner = _ownerModified; var group = _groupModified; var access = _daclModified; var audit = _saclModified;
                return () => { _ownerModified = owner; _groupModified = group; _daclModified = access; _saclModified = audit; };
            });
        }

        private void UpdateWithNewSecurityDescriptorCore(RawSecurityDescriptor newOne, AccessControlSections includeSections)
        {
            Debug.Assert(newOne != null, "Must not supply a null parameter here");

            if ((includeSections & AccessControlSections.Owner) != 0)
            {
                _ownerModified = true;
                _securityDescriptor.Owner = newOne!.Owner;
            }

            if ((includeSections & AccessControlSections.Group) != 0)
            {
                _groupModified = true;
                _securityDescriptor.Group = newOne!.Group;
            }

            if ((includeSections & AccessControlSections.Audit) != 0)
            {
                _saclModified = true;
                if (newOne!.SystemAcl != null)
                {
                    _securityDescriptor.SystemAcl = new SystemAcl(IsContainer, IsDS, newOne.SystemAcl, true);
                }
                else
                {
                    _securityDescriptor.SystemAcl = null;
                }
                // carry forward the SACL related control flags
                _securityDescriptor.UpdateControlFlags(SACL_CONTROL_FLAGS, (ControlFlags)(newOne.ControlFlags & SACL_CONTROL_FLAGS));
            }

            if ((includeSections & AccessControlSections.Access) != 0)
            {
                _daclModified = true;
                if (newOne!.DiscretionaryAcl != null)
                {
                    _securityDescriptor.DiscretionaryAcl = new DiscretionaryAcl(IsContainer, IsDS, newOne.DiscretionaryAcl, true);
                }
                else
                {
                    _securityDescriptor.DiscretionaryAcl = null;
                }
                // by the following property set, the _securityDescriptor's control flags
                // may contains DACL present flag. That needs to be carried forward! Therefore, we OR
                // the current _securityDescriptor.s DACL present flag.
                ControlFlags daclFlag = (_securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent);

                _securityDescriptor.UpdateControlFlags(DACL_CONTROL_FLAGS,
                    (ControlFlags)((newOne.ControlFlags | daclFlag) & DACL_CONTROL_FLAGS));
            }
        }

        #endregion

        #region Protected Properties and Methods

        /// <summary>
        /// Gets the security descriptor for this instance.
        /// </summary>
        protected CommonSecurityDescriptor SecurityDescriptor => _securityDescriptor;

        protected void ReadLock()
        {
            _lock.EnterReadLock();
        }

        protected void ReadUnlock()
        {
            _lock.ExitReadLock();
        }

        protected void WriteLock()
        {
            _lock.EnterWriteLock();
        }

        protected void WriteUnlock()
        {
            _lock.ExitWriteLock();
        }

        protected bool OwnerModified
        {
            get
            {
                if (!(_lock.IsReadLockHeld || _lock.IsWriteLockHeld))
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForReadOrWrite");
                }

                return _ownerModified;
            }

            set
            {
                if (!_lock.IsWriteLockHeld)
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForWrite");
                }

                _ownerModified = value;
            }
        }

        protected bool GroupModified
        {
            get
            {
                if (!(_lock.IsReadLockHeld || _lock.IsWriteLockHeld))
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForReadOrWrite");
                }

                return _groupModified;
            }

            set
            {
                if (!_lock.IsWriteLockHeld)
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForWrite");
                }

                _groupModified = value;
            }
        }

        protected bool AuditRulesModified
        {
            get
            {
                if (!(_lock.IsReadLockHeld || _lock.IsWriteLockHeld))
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForReadOrWrite");
                }

                return _saclModified;
            }

            set
            {
                if (!_lock.IsWriteLockHeld)
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForWrite");
                }

                _saclModified = value;
            }
        }

        protected bool AccessRulesModified
        {
            get
            {
                if (!(_lock.IsReadLockHeld || _lock.IsWriteLockHeld))
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForReadOrWrite");
                }

                return _daclModified;
            }

            set
            {
                if (!_lock.IsWriteLockHeld)
                {
                    throw new InvalidOperationException("InvalidOperation_MustLockForWrite");
                }

                _daclModified = value;
            }
        }

        protected bool IsContainer
        {
            get { return _securityDescriptor.IsContainer; }
        }

        protected bool IsDS
        {
            get { return _securityDescriptor.IsDS; }
        }

        //
        // Persists the changes made to the object
        //
        // This overloaded method takes a name of an existing object
        //

        protected virtual void Persist(string name, AccessControlSections includeSections)
        {
            throw new NotImplementedException();
        }

        //
        // The false path forwards to the virtual name hook. Privilege adjustment is
        // not a detached operation; a platform persistence implementation must override
        // the true path explicitly. No implicit persistence or credential lookup occurs.
        //
        protected virtual void Persist(bool enableOwnershipPrivilege, string name, AccessControlSections includeSections)
        {
            if (enableOwnershipPrivilege)
                throw new NotSupportedException("Privilege adjustment requires an explicit platform persistence implementation.");
            Persist(name, includeSections);
        }

        //
        // Persists the changes made to the object
        //
        // This overloaded method takes a handle to an existing object
        //

        protected virtual void Persist(SafeHandle handle, AccessControlSections includeSections)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region Public Methods

        //
        // Sets and retrieves the owner of this object
        //

        public IdentityReference? GetOwner(System.Type targetType)
        {
            RequireRetrievedSection(SecurityMasks.Owner);
            SecurityIdentifier? identity;
            IdentityRead read;
            ReadLock();
            try
            {
                lock (FacadeMutation.Gate)
                {
                    identity = _securityDescriptor.Owner;
                    read = CaptureIdentityRead();
                }
            }
            finally { ReadUnlock(); }
            if (identity is null) return null;
            if (targetType == typeof(SecurityIdentifier)) return identity;
            return ResolveRead(read, [identity], targetType)[0];
        }

        public void SetOwner(IdentityReference identity)
        {
            RequireRetrievedSection(SecurityMasks.Owner);
            ArgumentNullException.ThrowIfNull(identity);

            using var prepared = PrepareIdentityMutation(identity);
            WriteLock();

            try
            {
                prepared.Run(() => { CaptureDirtyFlags(); _securityDescriptor.Owner = prepared.Sid; _ownerModified = true; });
            }
            finally
            {
                WriteUnlock();
            }
        }

        //
        // Sets and retrieves the group of this object
        //

        public IdentityReference? GetGroup(System.Type targetType)
        {
            RequireRetrievedSection(SecurityMasks.Group);
            SecurityIdentifier? identity;
            IdentityRead read;
            ReadLock();
            try
            {
                lock (FacadeMutation.Gate)
                {
                    identity = _securityDescriptor.Group;
                    read = CaptureIdentityRead();
                }
            }
            finally { ReadUnlock(); }
            if (identity is null) return null;
            if (targetType == typeof(SecurityIdentifier)) return identity;
            return ResolveRead(read, [identity], targetType)[0];
        }

        public void SetGroup(IdentityReference identity)
        {
            RequireRetrievedSection(SecurityMasks.Group);
            ArgumentNullException.ThrowIfNull(identity);

            using var prepared = PrepareIdentityMutation(identity);
            WriteLock();

            try
            {
                prepared.Run(() => { CaptureDirtyFlags(); _securityDescriptor.Group = prepared.Sid; _groupModified = true; });
            }
            finally
            {
                WriteUnlock();
            }
        }

        public virtual void PurgeAccessRules(IdentityReference identity)
        {
            RequireRetrievedSection(SecurityMasks.Dacl);
            ArgumentNullException.ThrowIfNull(identity);

            using var prepared = PrepareIdentityMutation(identity);
            WriteLock();

            try
            {
                prepared.Run(() => { CaptureDirtyFlags(); _securityDescriptor.PurgeAccessControl(prepared.Sid); _daclModified = true; });
            }
            finally
            {
                WriteUnlock();
            }
        }

        public virtual void PurgeAuditRules(IdentityReference identity)
        {
            RequireRetrievedSection(SecurityMasks.Sacl);
            ArgumentNullException.ThrowIfNull(identity);

            using var prepared = PrepareIdentityMutation(identity);
            WriteLock();

            try
            {
                prepared.Run(() => { CaptureDirtyFlags(); _securityDescriptor.PurgeAudit(prepared.Sid); _saclModified = true; });
            }
            finally
            {
                WriteUnlock();
            }
        }

        public bool AreAccessRulesProtected
        {
            get
            {
                ReadLock();

                try
                {
                lock (FacadeMutation.Gate)
                {
                    return ((_securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
                                }
            }
                finally
                {
                    ReadUnlock();
                }
            }
        }

        public void SetAccessRuleProtection(bool isProtected, bool preserveInheritance)
        {
            RequireRetrievedSection(SecurityMasks.Dacl);
            WriteLock();

            try
            {
                _securityDescriptor.SetDiscretionaryAclProtection(isProtected, preserveInheritance);
                _daclModified = true;
            }
            finally
            {
                WriteUnlock();
            }
        }

        public bool AreAuditRulesProtected
        {
            get
            {
                ReadLock();

                try
                {
                lock (FacadeMutation.Gate)
                {
                    return ((_securityDescriptor.ControlFlags & ControlFlags.SystemAclProtected) != 0);
                                }
            }
                finally
                {
                    ReadUnlock();
                }
            }
        }

        public void SetAuditRuleProtection(bool isProtected, bool preserveInheritance)
        {
            RequireRetrievedSection(SecurityMasks.Sacl);
            WriteLock();

            try
            {
                _securityDescriptor.SetSystemAclProtection(isProtected, preserveInheritance);
                _saclModified = true;
            }
            finally
            {
                WriteUnlock();
            }
        }

        public bool AreAccessRulesCanonical
        {
            get
            {
                ReadLock();

                try
                {
                lock (FacadeMutation.Gate)
                {
                    return _securityDescriptor.IsDiscretionaryAclCanonical;
                                }
            }
                finally
                {
                    ReadUnlock();
                }
            }
        }

        public bool AreAuditRulesCanonical
        {
            get
            {
                ReadLock();

                try
                {
                lock (FacadeMutation.Gate)
                {
                    return _securityDescriptor.IsSystemAclCanonical;
                                }
            }
                finally
                {
                    ReadUnlock();
                }
            }
        }

        public static bool IsSddlConversionSupported()
        {
            return true; // SDDL to binary conversions are supported on Windows 2000 and higher
        }

        public string GetSecurityDescriptorSddlForm(AccessControlSections includeSections)
        {
            ReadLock();

            try
            {
                lock (FacadeMutation.Gate)
                {
                return _securityDescriptor.GetSddlForm(includeSections);
                            }
            }
            finally
            {
                ReadUnlock();
            }
        }

        public void SetSecurityDescriptorSddlForm(string sddlForm)
        {
            SetSecurityDescriptorSddlForm(sddlForm, AccessControlSections.All);
        }

        public void SetSecurityDescriptorSddlForm(string sddlForm, AccessControlSections includeSections)
        {
            ArgumentNullException.ThrowIfNull(sddlForm);

            if ((includeSections & AccessControlSections.All) == 0)
            {
                throw new ArgumentException(
                    "Arg_EnumAtLeastOneFlag",
                    nameof(includeSections));
            }

            WriteLock();

            try
            {
                UpdateWithNewSecurityDescriptor(new RawSecurityDescriptor(sddlForm), includeSections);
            }
            finally
            {
                WriteUnlock();
            }
        }

        public byte[] GetSecurityDescriptorBinaryForm()
        {
            ReadLock();

            try
            {
                lock (FacadeMutation.Gate)
                {
                byte[] result = new byte[_securityDescriptor.BinaryLength];

                _securityDescriptor.GetBinaryForm(result, 0);

                return result;
                            }
            }
            finally
            {
                ReadUnlock();
            }
        }

        public void SetSecurityDescriptorBinaryForm(byte[] binaryForm)
        {
            SetSecurityDescriptorBinaryForm(binaryForm, AccessControlSections.All);
        }

        public void SetSecurityDescriptorBinaryForm(byte[] binaryForm, AccessControlSections includeSections)
        {
            ArgumentNullException.ThrowIfNull(binaryForm);

            if ((includeSections & AccessControlSections.All) == 0)
            {
                throw new ArgumentException(
                    "Arg_EnumAtLeastOneFlag",
                    nameof(includeSections));
            }

            WriteLock();

            try
            {
                UpdateWithNewSecurityDescriptor(new RawSecurityDescriptor(binaryForm, 0), includeSections);
            }
            finally
            {
                WriteUnlock();
            }
        }

        public abstract Type AccessRightType { get; }
        public abstract Type AccessRuleType { get; }
        public abstract Type AuditRuleType { get; }

        protected abstract bool ModifyAccess(AccessControlModification modification, AccessRule rule, out bool modified);
        protected abstract bool ModifyAudit(AccessControlModification modification, AuditRule rule, out bool modified);

        public virtual bool ModifyAccessRule(AccessControlModification modification, AccessRule rule, out bool modified)
        {
            ArgumentNullException.ThrowIfNull(rule);

            if (!this.AccessRuleType.IsAssignableFrom(rule.GetType()))
            {
                throw new ArgumentException(
                    "AccessControl_InvalidAccessRuleType",
                    nameof(rule));
            }

            EnterLibraryWriteLock();

            try
            {
                // Invoke extension hooks outside the shared transaction gate. The
                // concrete base mutation owns its transaction; user overrides retain
                // native wrapper-lock discipline without blocking peer-wrapper work.
                return ModifyAccess(modification, rule, out modified);
            }
            finally
            {
                ExitLibraryWriteLock();
            }
        }

        public virtual bool ModifyAuditRule(AccessControlModification modification, AuditRule rule, out bool modified)
        {
            ArgumentNullException.ThrowIfNull(rule);

            if (!this.AuditRuleType.IsAssignableFrom(rule.GetType()))
            {
                throw new ArgumentException(
                    "AccessControl_InvalidAuditRuleType",
                    nameof(rule));
            }

            EnterLibraryWriteLock();

            try
            {
                // Invoke extension hooks outside the shared transaction gate. The
                // concrete base mutation owns its transaction; user overrides retain
                // native wrapper-lock discipline without blocking peer-wrapper work.
                return ModifyAudit(modification, rule, out modified);
            }
            finally
            {
                ExitLibraryWriteLock();
            }
        }

        public abstract AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type);

        public abstract AuditRule AuditRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags);
        #endregion
    }
}
