using System.Runtime.InteropServices;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using Research.MicrosoftInterop;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;

Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; {RuntimeInformation.RuntimeIdentifier}");
Console.WriteLine($"Microsoft assembly: {typeof(System.DirectoryServices.ActiveDirectorySecurity).Assembly.GetName()}");
Console.WriteLine($"ACL assembly: {typeof(System.Security.AccessControl.ObjectSecurity).Assembly.GetName()}");
Console.WriteLine($"Directory base assembly: {typeof(System.Security.AccessControl.DirectoryObjectSecurity).Assembly.GetName()}");
Console.WriteLine($"Identity assembly: {typeof(System.Security.Principal.SecurityIdentifier).Assembly.GetName()}");
var sid = new P.SecurityIdentifier("S-1-1-0");
var name = new P.NTAccount("EXAMPLE\\alice");
var guid = Guid.Parse("11111111-1111-1111-1111-111111111111");
var descriptor = new ActiveDirectorySecurity();
var access = (ActiveDirectoryAccessRule)descriptor.AccessRuleFactory(sid, (int)ActiveDirectoryRights.ReadProperty,
    true, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow, guid, guid);
var audit = (ActiveDirectoryAuditRule)descriptor.AuditRuleFactory(sid, (int)ActiveDirectoryRights.ReadProperty,
    true, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AuditFlags.Success | AuditFlags.Failure, guid, guid);
IReadOnlyList<A.AuthorizationRule> rules = new A.AuthorizationRule[] { access, audit };
var hook = new HookSecurity();
A.ObjectSecurity baseView = hook;
Check(baseView.ModifyAccessRule(AccessControlModification.Add, access, out var changed) && changed, "access hook result");
Check(baseView.ModifyAuditRule(AccessControlModification.Add, audit, out changed) && changed, "audit hook result");
Check(hook.AccessCalls == 1 && hook.AuditCalls == 1 && hook.Flags(), "base-typed protected dispatch/flags");
Expect<InvalidOperationException>(hook.ReadFlagsWithoutLock, "modified flag read requires lock");
Expect<InvalidOperationException>(hook.WriteFlagsWithoutLock, "modified flag write requires lock");
hook.ThrowFromHook = true;
Expect<InvalidOperationException>(() => baseView.ModifyAccessRule(AccessControlModification.Add, access, out _), "subclass exception propagates");
Expect<InvalidOperationException>(hook.ReadFlagsWithoutLock, "outer and recursive write locks released after exception");
hook.ThrowFromHook = false;
var before = hook.AccessCalls;
Expect<NotSupportedException>(() => hook.AddAccessRule(access), "typed helper reaches unimplemented private path");
Check(hook.AccessCalls == before, "typed Add helper does not dispatch protected ModifyAccess");
using var handle = new EmptyHandle();
hook.CallPersist("fixture"); hook.CallPersist(handle); hook.CallPersist(true, "fixture");
Check(hook.NameCalls == 1 && hook.HandleCalls == 1 && hook.BoolCalls == 1, "all Persist overrides dispatch without I/O");
hook.CallBasePersist(false, "fixture");
Check(hook.NameCalls == 2, "base false-ownership Persist forwards to name override");
Expect<PlatformNotSupportedException>(() => hook.CallBasePersist(true, "fixture"), "research base refuses native privilege path");
var factory = new FactorySecurity();
A.ObjectSecurity factoryBase = factory;
Check(factoryBase.AccessRuleFactory(sid, 16, false, 0, 0, AccessControlType.Allow) is ActiveDirectoryAccessRule && factory.FactoryCalls == 1, "custom DirectoryObjectSecurity factory dispatch");
_ = new ObjectCtorProbe(); _ = new ObjectCtorProbe(true, true);
_ = new ObjectCtorProbe(new A.CommonSecurityDescriptor(true, true, A.CommonSecurityDescriptor.Fixture, 0));
_ = new FactorySecurity(new A.CommonSecurityDescriptor(true, true, A.CommonSecurityDescriptor.Fixture, 0));
Check(new ObjectCtorProbe(true, true).ContainerAndDs(), "protected bool constructor properties");
Check(new FactorySecurity().ContainerAndDs(), "directory default constructor flags");
var snapshot = descriptor.GetSecurityDescriptorBinaryForm(); snapshot[0] = 99;
Check(descriptor.GetSecurityDescriptorBinaryForm()[0] == 1, "portable fixture byte snapshot is detached");
Console.WriteLine("PASS portable hooks: dispatch, recursive locks, writable flags, factories, base constructors, Persist overloads, helper bypass, detached fixture.");

if (!OperatingSystem.IsWindows())
{
    Expect<PlatformNotSupportedException>(() => sid.ToMicrosoftObject(), "SID export");
    Expect<PlatformNotSupportedException>(() => name.ToMicrosoftObject(), "NTAccount export");
    Expect<PlatformNotSupportedException>(() => access.ToMicrosoftObject(), "access rule export");
    Expect<PlatformNotSupportedException>(() => audit.ToMicrosoftObject(), "audit rule export");
    Expect<PlatformNotSupportedException>(() => descriptor.ToMicrosoftObject(), "descriptor export");
    Expect<PlatformNotSupportedException>(() => rules.ToMicrosoftObject(), "collection export");
    Console.WriteLine("Windows bidirectional conversion branch: NOT EXECUTED on Linux.");
}
else
{
    MicrosoftHookProbe.Run();
    // Offline only: future Windows execution can verify these limited field/snapshot cases.
    var msSid = sid.ToMicrosoftObject();
    Check(Conversions.FromMicrosoftObject(msSid).Value == sid.Value, "SID round-trip");
    Check(Conversions.FromMicrosoftObject(name.ToMicrosoftObject()).Value == name.Value, "NTAccount value-only round-trip");
    var msAccess = access.ToMicrosoftObject();
    var returnedAccess = Conversions.FromMicrosoftObject(msAccess);
    Check(returnedAccess.IsInherited && returnedAccess.ObjectType == guid && returnedAccess.InheritedObjectType == guid
        && returnedAccess.ActiveDirectoryRights == access.ActiveDirectoryRights && returnedAccess.ObjectFlags == access.ObjectFlags
        && returnedAccess.InheritanceFlags == access.InheritanceFlags && returnedAccess.PropagationFlags == access.PropagationFlags, "access fields");
    var returnedAudit = Conversions.FromMicrosoftObject(audit.ToMicrosoftObject());
    Check(returnedAudit.AuditFlags == audit.AuditFlags && returnedAudit.IsInherited && returnedAudit.ObjectType == guid, "audit fields");
    Check(Conversions.FromMicrosoftObject(rules.ToMicrosoftObject()).Count == 2, "collection round-trip");
    var msDescriptor = descriptor.ToMicrosoftObject();
    const SecurityMasks all = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
    var returnedDescriptor = Conversions.FromMicrosoftObject(msDescriptor, all);
    Check(!ReferenceEquals(returnedDescriptor, descriptor), "descriptor detached copy");
    var original = descriptor.GetSecurityDescriptorBinaryForm();
    msDescriptor.SetOwner(msSid); // In-memory, no directory or OS permission write.
    Check(descriptor.GetSecurityDescriptorBinaryForm().AsSpan().SequenceEqual(original), "Microsoft mutation not reflected in portable source");
    Console.WriteLine("PASS Windows limited conversion branch (not a general ACL parity suite).");
}
void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
void Expect<T>(Action action, string label) where T : Exception
{
    try { action(); } catch (T ex) when (ex.GetType() == typeof(T)) { Console.WriteLine($"EXPECTED {typeof(T).Name}: {label}: {ex.Message}"); return; }
    throw new Exception("Missing expected exception: " + label);
}

sealed class EmptyHandle : SafeHandle
{
    public EmptyHandle() : base(IntPtr.Zero, false) { }
    public override bool IsInvalid => true;
    protected override bool ReleaseHandle() => true;
}
class HookSecurity : ActiveDirectorySecurity
{
    public int AccessCalls, AuditCalls, NameCalls, HandleCalls, BoolCalls;
    public bool ThrowFromHook;
    protected override bool ModifyAccess(AccessControlModification modification, A.AccessRule rule, out bool modified)
    {
        AccessCalls++; WriteLock();
        try { AccessRulesModified = true; if (ThrowFromHook) throw new InvalidOperationException("Probe hook failure."); modified = true; return true; }
        finally { WriteUnlock(); }
    }
    protected override bool ModifyAudit(AccessControlModification modification, A.AuditRule rule, out bool modified)
    { AuditCalls++; AuditRulesModified = true; modified = true; return true; }
    public bool Flags() { ReadLock(); try { return AccessRulesModified && AuditRulesModified; } finally { ReadUnlock(); } }
    public void ReadFlagsWithoutLock() => _ = AccessRulesModified;
    public void WriteFlagsWithoutLock() => OwnerModified = true;
    protected override void Persist(string name, AccessControlSections sections) => NameCalls++;
    protected override void Persist(SafeHandle handle, AccessControlSections sections) => HandleCalls++;
    protected override void Persist(bool ownership, string name, AccessControlSections sections) => BoolCalls++;
    public void CallPersist(string name) => Persist(name, AccessControlSections.Access);
    public void CallPersist(SafeHandle handle) => Persist(handle, AccessControlSections.Access);
    public void CallPersist(bool ownership, string name) => Persist(ownership, name, AccessControlSections.Access);
    public void CallBasePersist(bool ownership, string name) => base.Persist(ownership, name, AccessControlSections.Access);
}
class FactorySecurity : A.DirectoryObjectSecurity
{
    public FactorySecurity() { }
    public FactorySecurity(A.CommonSecurityDescriptor descriptor) : base(descriptor) { }
    public bool ContainerAndDs() => IsContainer && IsDS;
    public int FactoryCalls;
    public override Type AccessRightType => typeof(ActiveDirectoryRights);
    public override Type AccessRuleType => typeof(ActiveDirectoryAccessRule);
    public override Type AuditRuleType => typeof(ActiveDirectoryAuditRule);
    public override A.AccessRule AccessRuleFactory(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type)
    { FactoryCalls++; return new ActiveDirectorySecurity().AccessRuleFactory(identity, mask, inherited, inheritance, propagation, type); }
    public override A.AuditRule AuditRuleFactory(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags) => new ActiveDirectorySecurity().AuditRuleFactory(identity, mask, inherited, inheritance, propagation, flags);
    public override A.AccessRule AccessRuleFactory(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type, Guid objectType, Guid inheritedType) => new ActiveDirectorySecurity().AccessRuleFactory(identity, mask, inherited, inheritance, propagation, type, objectType, inheritedType);
    public override A.AuditRule AuditRuleFactory(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags, Guid objectType, Guid inheritedType) => new ActiveDirectorySecurity().AuditRuleFactory(identity, mask, inherited, inheritance, propagation, flags, objectType, inheritedType);
}
class ObjectCtorProbe : A.ObjectSecurity
{
    public ObjectCtorProbe() { }
    public ObjectCtorProbe(bool container, bool ds) : base(container, ds) { }
    public ObjectCtorProbe(A.CommonSecurityDescriptor descriptor) : base(descriptor) { }
    public bool ContainerAndDs() => IsContainer && IsDS;
    public override Type AccessRightType => typeof(ActiveDirectoryRights);
    public override Type AccessRuleType => typeof(ActiveDirectoryAccessRule);
    public override Type AuditRuleType => typeof(ActiveDirectoryAuditRule);
    protected override bool ModifyAccess(AccessControlModification m, A.AccessRule r, out bool modified) => throw new NotSupportedException();
    protected override bool ModifyAudit(AccessControlModification m, A.AuditRule r, out bool modified) => throw new NotSupportedException();
    public override A.AccessRule AccessRuleFactory(P.IdentityReference i, int m, bool h, InheritanceFlags f, PropagationFlags p, AccessControlType t) => new ActiveDirectorySecurity().AccessRuleFactory(i,m,h,f,p,t);
    public override A.AuditRule AuditRuleFactory(P.IdentityReference i, int m, bool h, InheritanceFlags f, PropagationFlags p, AuditFlags t) => new ActiveDirectorySecurity().AuditRuleFactory(i,m,h,f,p,t);
}
#if SEALED_FACTORY
class InvalidFactoryOverride : ActiveDirectorySecurity
{
    public override A.AccessRule AccessRuleFactory(P.IdentityReference i, int m, bool h, InheritanceFlags f, PropagationFlags p, AccessControlType t) => throw new NotSupportedException();
}
#endif
