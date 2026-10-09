#pragma warning disable CA1416 // Framework enum values; portable replay uses no Windows APIs.
// Detached wrapper probes. Numeric identities only; no directory I/O or privilege changes.
// Persist(false) only dispatches to a recording override; base unsupported paths never write.
using System.Security.AccessControl;
using System.Runtime.InteropServices;
#if PORTABLE_FACADE
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
#else
using A = System.Security.AccessControl;
using P = System.Security.Principal;
#endif

internal static class FacadeContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        foreach (var (op, count) in new[] { ("FacadeConstruction", 6), ("FacadeLocks", 32),
            ("FacadeSharing", 9), ("FacadeDirty", 12), ("FacadeDispatch", 16),
            ("FacadeModify", 84), ("FacadeEnumeration", 16), ("FacadeReplace", 36),
            ("FacadeValidation", 12), ("FacadePersist", 4), ("FacadeIndependentLocks", 2), ("FacadeFactoryDefaults", 4), ("FacadeEnumerationObjects", 16) })
            for (var i = 0; i < count; i++)
            { var scenario = i; record(op, new { Scenario = i }, () => Execute(op, scenario)); }
    }

    internal static object? Execute(string op, int scenario)
    {
        var descriptor = Descriptor();
        var wrapper = new Wrapper(descriptor);
        switch (op)
        {
            case "FacadeConstruction":
                if (scenario == 0) return Snapshot(new Wrapper());
                if (scenario == 1) return Snapshot(new Wrapper(null!));
                if (scenario == 2) return Snapshot(new Wrapper(new A.CommonSecurityDescriptor(false, false, "D:")));
                if (scenario == 3) return new Bare().DescriptorIsNull;
                if (scenario == 4) return new Bare().Container;
                return new { Same = ReferenceEquals(descriptor, wrapper.Descriptor), wrapper.Container, wrapper.Directory };
            case "FacadeLocks":
                var flag = scenario % 4; var mode = scenario / 4;
                var other = new Wrapper(descriptor);
                if (mode is 1 or 3 or 4) wrapper.EnterRead();
                if (mode is 2 or 5 or 6 or 7) wrapper.EnterWrite();
                try
                {
                    if (mode == 3) wrapper.EnterWrite(); // native read-to-write recursion refusal
                    if (mode == 4) { wrapper.EnterRead(); wrapper.ExitRead(); }
                    if (mode == 5) { wrapper.EnterWrite(); wrapper.ExitWrite(); wrapper.EnterRead(); wrapper.ExitRead(); }
                    if (mode == 6) return Error(() => other.Flag(flag));
                    if (mode == 7) return Error(() => { other.SetFlag(flag, true); return null; });
                    return new { Read = Error(() => wrapper.Flag(flag)), Write = Error(() => { wrapper.SetFlag(flag, true); return wrapper.Flag(flag); }) };
                }
                finally { if (mode is 1 or 3 or 4) wrapper.ExitRead(); if (mode is 2 or 5 or 6 or 7) wrapper.ExitWrite(); }
            case "FacadeSharing":
                var second = new Wrapper(descriptor);
                var dacl = descriptor.DiscretionaryAcl;
                switch (scenario)
                {
                    case 0: descriptor.Owner = Sid(2); break;
                    case 1: descriptor.Group = Sid(2); break;
                    case 2: descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, Sid(2), 32, 0, 0); break;
                    case 3: descriptor.SystemAcl = null; break;
                    case 4: wrapper.SetOwner(Sid(2)); break;
                    case 5: wrapper.PurgeAccessRules(Sid(1)); break;
                    case 6: wrapper.SetSecurityDescriptorSddlForm("O:SYD:(A;;WP;;;WD)", AccessControlSections.Owner | AccessControlSections.Access); break;
                    case 7: var ace = (A.KnownAce)descriptor.DiscretionaryAcl![0]; ace.AccessMask = 127; break;
                    case 8: descriptor.DiscretionaryAcl = new A.DiscretionaryAcl(true, true, 1); break;
                }
                return new { First = Snapshot(wrapper), Second = Snapshot(second), SameDescriptor = ReferenceEquals(wrapper.Descriptor, second.Descriptor), SameAcl = ReferenceEquals(dacl, descriptor.DiscretionaryAcl) };
            case "FacadeDirty":
                switch (scenario)
                {
                    case 0: wrapper.SetOwner(Sid(1)); break;
                    case 1: wrapper.SetGroup(Sid(1)); break;
                    case 2: wrapper.PurgeAccessRules(Sid(9)); break;
                    case 3: wrapper.PurgeAuditRules(Sid(9)); break;
                    case 4: wrapper.SetAccessRuleProtection(false, true); break;
                    case 5: wrapper.SetAuditRuleProtection(false, true); break;
                    case 6: wrapper.SetOwner(null!); break;
                    case 7: wrapper.SetGroup(null!); break;
                    case 8: wrapper.SetSecurityDescriptorSddlForm("O:WD", AccessControlSections.Owner); break;
                    case 9: wrapper.SetSecurityDescriptorSddlForm("G:WD", AccessControlSections.Group); break;
                    case 10: wrapper.SetSecurityDescriptorSddlForm("D:", AccessControlSections.Access); break;
                    case 11: wrapper.SetSecurityDescriptorSddlForm("S:", AccessControlSections.Audit); break;
                }
                return Snapshot(wrapper);
            case "FacadeDispatch":
                wrapper.TraceHooks = true;
                var audit = scenario >= 8; var route = scenario % 8;
                var result = Error(() => audit ? wrapper.AuditRoute(route, Audit()) : wrapper.AccessRoute(route, Access()));
                return new { Result = result, wrapper.Calls, State = Snapshot(wrapper) };
            case "FacadeModify":
                var isAudit = scenario >= 42; var modification = (AccessControlModification)(scenario % 7); var initial = scenario / 7 % 6;
                if (initial == 1) descriptor.SystemAcl = null;
                if (initial == 2) descriptor.DiscretionaryAcl = null;
                if (initial == 3) descriptor.DiscretionaryAcl = new A.DiscretionaryAcl(true, true, new A.RawAcl(2, 1));
                if (initial == 4) descriptor.SystemAcl = new A.SystemAcl(true, true, new A.RawAcl(2, 1));
                var guid = initial == 5 ? Guid.Parse("00112233-4455-6677-8899-aabbccddeeff") : Guid.Empty;
                var modified = false;
                var outcome = Error(() => isAudit ? wrapper.ModifyAuditRule(modification, Audit(guid), out modified)
                    : wrapper.ModifyAccessRule(modification, Access(guid), out modified));
                return new { Result = outcome, Modified = modified, State = Snapshot(wrapper) };
            case "FacadeEnumerationObjects":
                scenario += 16; goto case "FacadeEnumeration";
            case "FacadeEnumeration":
                if (scenario >= 16)
                {
                    var accessAcl = new A.RawAcl(4, 4); var auditAcl = new A.RawAcl(4, 4);
                    for (var i = 0; i < 3; i++)
                    {
                        var flags = i == 2 ? AceFlags.Inherited | AceFlags.ContainerInherit : AceFlags.None;
                        accessAcl.InsertAce(i, i == 1
                            ? new A.ObjectAce(flags, AceQualifier.AccessAllowed, 16, Sid(1), ObjectAceFlags.ObjectAceTypePresent, Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), Guid.Empty, false, null)
                            : new A.CommonAce(flags, AceQualifier.AccessAllowed, 32, Sid(1), i == 0, null));
                        auditAcl.InsertAce(i, i == 1
                            ? new A.ObjectAce(flags | AceFlags.SuccessfulAccess, AceQualifier.SystemAudit, 16, Sid(1), ObjectAceFlags.ObjectAceTypePresent, Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), Guid.Empty, false, null)
                            : new A.CommonAce(flags | AceFlags.SuccessfulAccess, AceQualifier.SystemAudit, 32, Sid(1), i == 0, null));
                    }
                    descriptor = new A.CommonSecurityDescriptor(true, true, new A.RawSecurityDescriptor((ControlFlags)20, Sid(1), Sid(1), auditAcl, accessAcl));
                    wrapper = new Wrapper(descriptor);
                }
                var includeExplicit = (scenario & 1) != 0; var includeInherited = (scenario & 2) != 0;
                if ((scenario & 8) != 0) { descriptor.DiscretionaryAcl = null; descriptor.SystemAcl = null; }
                wrapper.Calls.Clear();
                var rules = (scenario & 4) == 0 ? wrapper.GetAccessRules(includeExplicit, includeInherited, typeof(P.SecurityIdentifier))
                    : wrapper.GetAuditRules(includeExplicit, includeInherited, typeof(P.SecurityIdentifier));
                if (scenario >= 16) return new { Rules = rules.Cast<A.AuthorizationRule>().Select(r => new { Sid = r.IdentityReference.Value, Mask = r is AR a ? a.Mask : ((UR)r).Mask, r.IsInherited, Inheritance = (int)r.InheritanceFlags, Propagation = (int)r.PropagationFlags, ObjectType = r is AR ar ? ar.ObjectType : ((UR)r).ObjectType }).ToArray(), wrapper.Calls, State = Snapshot(wrapper) };
                return new { Rules = rules.Cast<A.AuthorizationRule>().Select(r => new { Sid = r.IdentityReference.Value, r.IsInherited, Inheritance = (int)r.InheritanceFlags, Propagation = (int)r.PropagationFlags }).ToArray(), wrapper.Calls, State = Snapshot(wrapper) };
            case "FacadeReplace":
                var sections = (AccessControlSections)new[] { 0, 1, 2, 4, 8, 15, 16, 17, -1 }[scenario % 9];
                var form = scenario / 9;
                var failure = Error(() => { if (form < 2) wrapper.SetSecurityDescriptorSddlForm(form == 0 ? "O:SYG:BAD:PS:AI" : "bad", sections);
                    else wrapper.SetSecurityDescriptorBinaryForm(form == 2 ? Bytes(new A.RawSecurityDescriptor("O:SYG:BAD:PS:AI")) : new byte[3], sections); return null; });
                return new { Result = failure, State = Snapshot(wrapper) };
            case "FacadeValidation":
                switch (scenario)
                {
                    case 0: return wrapper.GetOwner(null!);
                    case 1: return wrapper.GetGroup(typeof(string));
                    case 2: descriptor.Owner = null; return wrapper.GetOwner(null!);
                    case 3: descriptor.Group = null; return wrapper.GetGroup(typeof(string));
                    case 4: return wrapper.GetAccessRules(false, false, null!);
                    case 5: return wrapper.GetAuditRules(false, false, typeof(string));
                    case 6: return wrapper.ModifyAccessRule((AccessControlModification)99, null!, out _);
                    case 7: return wrapper.ModifyAuditRule((AccessControlModification)99, null!, out _);
                    case 8: wrapper.EnterRead(); try { return wrapper.GetSecurityDescriptorBinaryForm().Length; } finally { wrapper.ExitRead(); }
                    case 9: wrapper.ExitRead(); return null;
                    case 10: wrapper.ExitWrite(); return null;
                    default: wrapper.TraceHooks = true; wrapper.ThrowHook = true; var caught = Error(() => wrapper.ModifyAccessRule(AccessControlModification.Add, Access(), out _)); return new { Failure = caught, Unlocked = Error(() => wrapper.Flag(0)), State = Snapshot(wrapper) };
                }
            case "FacadeFactoryDefaults":
                return wrapper.BaseFactory(scenario);
            case "FacadeIndependentLocks":
                var peer = new Wrapper(descriptor);
                using (var done = new ManualResetEventSlim())
                {
                    Exception? threadFailure = null;
                    var thread = new Thread(() => { try { peer.EnterWrite(); try { peer.SetFlag(0, true); } finally { peer.ExitWrite(); } } catch (Exception e) { threadFailure = e; } finally { done.Set(); } });
                    if (scenario == 0) wrapper.EnterRead(); else wrapper.EnterWrite();
                    bool independent;
                    try { thread.Start(); independent = done.Wait(TimeSpan.FromSeconds(5)); }
                    finally { if (scenario == 0) wrapper.ExitRead(); else wrapper.ExitWrite(); }
                    thread.Join();
                    return new { Independent = independent, ExceptionType = threadFailure?.GetType().FullName, First = wrapper.Flags(), Second = peer.Flags() };
                }
            case "FacadePersist":
                return wrapper.Persistence(scenario);
            default: throw new ArgumentOutOfRangeException(nameof(op));
        }
    }
    private static object Error(Func<object?> action)
    { try { return new { Value = action(), ExceptionType = (string?)null, ParamName = (string?)null }; } catch (Exception e) { return new { Value = (object?)null, ExceptionType = e.GetType().FullName, ParamName = (e as ArgumentException)?.ParamName }; } }
    private static object Snapshot(Wrapper w) => new { Hex = Convert.ToHexString(w.GetSecurityDescriptorBinaryForm()), Flags = w.Flags(), w.AreAccessRulesProtected, w.AreAuditRulesProtected, w.AreAccessRulesCanonical, w.AreAuditRulesCanonical };
    private static byte[] Bytes(A.GenericSecurityDescriptor d) { var b = new byte[d.BinaryLength]; d.GetBinaryForm(b, 0); return b; }
    private static P.SecurityIdentifier Sid(int n) => new(n == 1 ? "S-1-1-0" : $"S-1-5-21-1-2-3-{n}");
    private static A.CommonSecurityDescriptor Descriptor() => new(true, true, "O:WDG:WDD:(A;;RP;;;WD)(A;CIID;WP;;;SY)S:(AU;SA;RP;;;WD)");
    private static AR Access(Guid g = default) => new(Sid(1), 16, false, 0, 0, AccessControlType.Allow, g, Guid.Empty);
    private static UR Audit(Guid g = default) => new(Sid(1), 16, false, 0, 0, AuditFlags.Success, g, Guid.Empty);
    internal sealed class AR(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AccessControlType type, Guid obj, Guid child)
        : A.ObjectAccessRule(id, mask, inherited, inf, prop, obj, child, type) { internal int Mask => AccessMask; }
    internal sealed class UR(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AuditFlags flags, Guid obj, Guid child)
        : A.ObjectAuditRule(id, mask, inherited, inf, prop, obj, child, flags) { internal int Mask => AccessMask; }
    internal class Wrapper : A.DirectoryObjectSecurity
    {
        internal Wrapper() { }
        internal Wrapper(A.CommonSecurityDescriptor d) : base(d) { }
        internal A.CommonSecurityDescriptor Descriptor => SecurityDescriptor;
        internal bool Container => IsContainer;
        internal bool Directory => IsDS;
        internal bool TraceHooks, ThrowHook;
        internal List<string> Calls = new();
        internal void EnterRead() => ReadLock(); internal void ExitRead() => ReadUnlock();
        internal void EnterWrite() => WriteLock(); internal void ExitWrite() => WriteUnlock();
        internal bool Flag(int n) => n switch { 0 => OwnerModified, 1 => GroupModified, 2 => AccessRulesModified, _ => AuditRulesModified };
        internal void SetFlag(int n, bool value) { switch (n) { case 0: OwnerModified = value; break; case 1: GroupModified = value; break; case 2: AccessRulesModified = value; break; default: AuditRulesModified = value; break; } }
        internal bool[] Flags() { ReadLock(); try { return Enumerable.Range(0, 4).Select(Flag).ToArray(); } finally { ReadUnlock(); } }
        public override Type AccessRightType => typeof(int);
        public override Type AccessRuleType => typeof(AR);
        public override Type AuditRuleType => typeof(UR);
        public override A.AccessRule AccessRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AccessControlType type)
        { Calls.Add("access-common"); return new AR(id, mask, inherited, inf, prop, type, Guid.Empty, Guid.Empty); }
        public override A.AuditRule AuditRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AuditFlags flags)
        { Calls.Add("audit-common"); return new UR(id, mask, inherited, inf, prop, flags, Guid.Empty, Guid.Empty); }
        public override A.AccessRule AccessRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AccessControlType type, Guid obj, Guid child)
        { Calls.Add("access-object"); return new AR(id, mask, inherited, inf, prop, type, obj, child); }
        public override A.AuditRule AuditRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AuditFlags flags, Guid obj, Guid child)
        { Calls.Add("audit-object"); return new UR(id, mask, inherited, inf, prop, flags, obj, child); }
        public override bool ModifyAccessRule(AccessControlModification m, A.AccessRule r, out bool changed) { if (TraceHooks) Calls.Add("public-access"); return base.ModifyAccessRule(m, r, out changed); }
        public override bool ModifyAuditRule(AccessControlModification m, A.AuditRule r, out bool changed) { if (TraceHooks) Calls.Add("public-audit"); return base.ModifyAuditRule(m, r, out changed); }
        protected override bool ModifyAccess(AccessControlModification m, A.AccessRule r, out bool changed)
        { if (TraceHooks) { Calls.Add("protected-access"); if (ThrowHook) throw new InvalidOperationException(); changed = false; return false; } return base.ModifyAccess(m, r, out changed); }
        protected override bool ModifyAudit(AccessControlModification m, A.AuditRule r, out bool changed)
        { if (TraceHooks) { Calls.Add("protected-audit"); changed = false; return false; } return base.ModifyAudit(m, r, out changed); }
        internal object? AccessRoute(int n, AR r) { switch(n) { case 0: return ModifyAccessRule(AccessControlModification.Add,r,out _); case 1: AddAccessRule(r); break; case 2: SetAccessRule(r); break; case 3: ResetAccessRule(r); break; case 4: return RemoveAccessRule(r); case 5: RemoveAccessRuleAll(r); break; case 6: RemoveAccessRuleSpecific(r); break; default: return ModifyAccess(AccessControlModification.Add,r,out _); } return null; }
        internal object? AuditRoute(int n, UR r) { switch(n) { case 0: return ModifyAuditRule(AccessControlModification.Add,r,out _); case 1: AddAuditRule(r); break; case 2: SetAuditRule(r); break; case 3: return ModifyAuditRule(AccessControlModification.Reset,r,out _); case 4: return RemoveAuditRule(r); case 5: RemoveAuditRuleAll(r); break; case 6: RemoveAuditRuleSpecific(r); break; default: return ModifyAudit(AccessControlModification.Add,r,out _); } return null; }
        internal object BaseFactory(int n) => n < 2
            ? base.AccessRuleFactory(n == 0 ? Sid(1) : null!, 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty)
            : base.AuditRuleFactory(n == 2 ? Sid(1) : null!, 16, false, 0, 0, AuditFlags.Success, Guid.Empty, Guid.Empty);
        protected override void Persist(string name, AccessControlSections sections) { Calls.Add($"persist:{name}:{(int)sections}"); }
        internal object? Persistence(int n) { if(n == 0) base.Persist(false,"detached",AccessControlSections.All); else if(n == 1) base.Persist("detached",AccessControlSections.All); else if(n == 2) base.Persist((SafeHandle)null!,AccessControlSections.All); else base.Persist(false,null!,0); return Calls; }
    }
    private sealed class Bare : A.ObjectSecurity
    {
        internal bool DescriptorIsNull => SecurityDescriptor is null;
        internal bool Container => IsContainer;
        public override Type AccessRightType => typeof(int); public override Type AccessRuleType => typeof(AR); public override Type AuditRuleType => typeof(UR);
        public override A.AccessRule AccessRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AccessControlType type) => Access();
        public override A.AuditRule AuditRuleFactory(P.IdentityReference id, int mask, bool inherited, InheritanceFlags inf, PropagationFlags prop, AuditFlags flags) => Audit();
        protected override bool ModifyAccess(AccessControlModification m,A.AccessRule r,out bool changed) { changed=false; return false; }
        protected override bool ModifyAudit(AccessControlModification m,A.AuditRule r,out bool changed) { changed=false; return false; }
    }
}
