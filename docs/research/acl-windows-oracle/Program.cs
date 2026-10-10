// RESEARCH ORACLE. Records Microsoft System.DirectoryServices 9.0.0 in-memory descriptor behavior.
// Every object is a detached in-memory ActiveDirectorySecurity: no DirectoryEntry, LDAP, AD writes,
// Persist calls, token or privilege changes. Outputs are observations, not a parity verdict.
using System.Runtime.InteropServices;
using static Sd;
using B = System.Security.Principal;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("Windows-only oracle: nothing executed on this platform.");
    return 2;
}

// Separate opt-in boundary batches leave the normal 4,308-row closure recorder unchanged.
if (args.Length == 4 && args[0] == "--sddl-replacement-states-jsonl")
{
    SddlReplacementStates.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-replacement-jsonl")
{
    SddlReplacementContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-alarm-jsonl")
{
    SddlAlarmContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-raw-contract-jsonl")
{
    SddlRawContractContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-composition-jsonl")
{
    SddlCompositionContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-retained-export-jsonl")
{
    SddlExportContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 4 && args[0] == "--sddl-mixed-jsonl")
{
    SddlMixedContracts.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture),
        int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture));
    return 0;
}
if (args.Length == 1 && args[0] is "--sddl-layer-count" or "--sddl-ace-size-count")
{
    Console.WriteLine((args[0] == "--sddl-ace-size-count" ? SddlAceSizeInputs.Create() : SddlNativeLayers.Inputs()).Count());
    return 0;
}
if (args.Length == 3 && args[0] is "--sddl-layer-jsonl" or "--sddl-ace-size-jsonl")
{
    SddlNativeLayers.Write(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture), args[0] == "--sddl-ace-size-jsonl");
    return 0;
}
if (args.Length > 0 && args[0] is "--sddl-boundary-jsonl" or "--sddl-size-followup-jsonl")
{
    if (args.Length is not (2 or 4)) throw new ArgumentException("Usage: --sddl-boundary-jsonl PATH [START COUNT]");
    var start = args.Length == 4 ? int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : 0;
    var count = args.Length == 4 ? int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture) : 8;
    SddlBoundaryContracts.Write(args[1], start, count, args[0] == "--sddl-size-followup-jsonl");
    return 0;
}

Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; {RuntimeInformation.RuntimeIdentifier}");
Console.WriteLine($"OS: {RuntimeInformation.OSDescription}");
Console.WriteLine($"Microsoft assembly: {typeof(M.ActiveDirectorySecurity).Assembly.GetName()}");
Console.WriteLine($"ACL assembly: {typeof(E.ObjectSecurity).Assembly.GetName()}");
Console.WriteLine($"Directory base assembly: {typeof(E.DirectoryObjectSecurity).Assembly.GetName()}");
Console.WriteLine($"Identity assembly: {typeof(B.SecurityIdentifier).Assembly.GetName()}");

var everyone = new B.SecurityIdentifier(Everyone, 0);
var u1 = new B.SecurityIdentifier(U1, 0);
var u2 = new B.SecurityIdentifier(U2, 0);
const M.ActiveDirectoryRights RP = M.ActiveDirectoryRights.ReadProperty;
const M.ActiveDirectoryRights WP = M.ActiveDirectoryRights.WriteProperty;
const M.ActiveDirectoryRights XR = M.ActiveDirectoryRights.ExtendedRight;
const M.ActiveDirectoryRights LC = M.ActiveDirectoryRights.ListChildren;
var allow = E.AccessControlType.Allow;
var deny = E.AccessControlType.Deny;
var all = M.ActiveDirectorySecurityInheritance.All;

M.ActiveDirectoryAccessRule R(B.SecurityIdentifier sid, M.ActiveDirectoryRights rights, E.AccessControlType type,
    Guid? objectType = null, M.ActiveDirectorySecurityInheritance inheritance = M.ActiveDirectorySecurityInheritance.None,
    Guid? inheritedType = null) =>
    new(sid, rights, type, objectType ?? Guid.Empty, inheritance, inheritedType ?? Guid.Empty);

M.ActiveDirectoryAuditRule A(B.SecurityIdentifier sid, M.ActiveDirectoryRights rights, E.AuditFlags flags,
    M.ActiveDirectorySecurityInheritance inheritance = M.ActiveDirectorySecurityInheritance.None) =>
    new(sid, rights, flags, Guid.Empty, inheritance, Guid.Empty);

byte[] EmptyDacl() => Build(Admins, Admins, Acl(4));
byte[] WithDacl(params byte[][] aces) => Build(Admins, Admins, Acl(4, aces));

// ---------------------------------------------------------------- A. initial state
Case("A1 new ActiveDirectorySecurity()", () => Snap("initial", new Probe()));

// ---------------------------------------------------------------- B. ACL states
var daclStates = new (string Name, byte[] Bytes)[]
{
    ("absent DACL", Build(Admins, Admins, null)),
    ("NULL DACL", Build(Admins, Admins, null, nullDacl: true)),
    ("empty DACL", EmptyDacl()),
    ("populated DACL", WithDacl(Ace(0x00, 0, 0x10, Everyone))),
};
foreach (var (name, bytes) in daclStates)
{
    Case($"B1 {name}: import", () => Snap("import", Load(bytes), bytes));
    Case($"B2 {name}: AddAccessRule(allow U1 RP)", () =>
    {
        var p = Load(bytes);
        Step("add", () => p.AddAccessRule(R(u1, RP, allow)));
        Snap("after", p);
    });
    Case($"B3 {name}: RemoveAccess(Everyone, Allow)", () =>
    {
        var p = Load(bytes);
        Step("remove", () => p.RemoveAccess(everyone, allow));
        Snap("after", p);
    });
    Case($"B4 {name}: SetAccessRuleProtection(true, true)", () =>
    {
        var p = Load(bytes);
        Step("protect", () => p.SetAccessRuleProtection(true, true));
        Snap("after", p);
    });
}
var saclAbsent = Build(Admins, Admins, Acl(4));
var saclEmpty = Build(Admins, Admins, Acl(4), sacl: Acl(4));
foreach (var (name, bytes) in new[] { ("absent SACL", saclAbsent), ("empty SACL", saclEmpty) })
{
    Case($"B5 {name}: import + AddAuditRule(U1 RP Success)", () =>
    {
        var p = Load(bytes);
        Snap("import", p, bytes);
        Step("add audit", () => p.AddAuditRule(A(u1, RP, E.AuditFlags.Success)));
        Snap("after", p);
    });
}

// ---------------------------------------------------------------- B6. per-operation DACL-state matrix
// Each op runs on a freshly loaded object whose modified flags were reset first, so the
// recorded flags and bytes show only that operation's effect.
var everyoneFull = (M.ActiveDirectoryAccessRule)new M.ActiveDirectorySecurity().AccessRuleFactory(
    everyone, -1, false, E.InheritanceFlags.ContainerInherit | E.InheritanceFlags.ObjectInherit,
    E.PropagationFlags.None, allow);
var stateOps = new (string Name, Func<Probe, string> Op)[]
{
    ("getters only (bytes, rules, SDDL, canonical)", p =>
    {
        _ = p.GetSecurityDescriptorBinaryForm(); _ = p.GetAccessRules(true, true, typeof(B.SecurityIdentifier));
        _ = p.GetSecurityDescriptorSddlForm(E.AccessControlSections.All); _ = p.AreAccessRulesCanonical; return "done";
    }),
    ("SetOwner(U1)", p => { p.SetOwner(u1); return "done"; }),
    ("SetGroup(U1)", p => { p.SetGroup(u1); return "done"; }),
    ("AddAuditRule(U1 RP Success) [SACL only]", p => { p.AddAuditRule(A(u1, RP, E.AuditFlags.Success)); return "done"; }),
    ("SetAccessRuleProtection(false, true) [already unprotected]", p => { p.SetAccessRuleProtection(false, true); return "done"; }),
    ("SetAccessRuleProtection(true, false)", p => { p.SetAccessRuleProtection(true, false); return "done"; }),
    ("AddAccessRule(Everyone 0xFFFFFFFF CI|OI) [identical to implied rule]", p => { p.AddAccessRule(everyoneFull); return "done"; }),
    ("AddAccessRule(deny U1 RP)", p => { p.AddAccessRule(R(u1, RP, deny)); return "done"; }),
    ("SetAccessRule(allow U1 RP)", p => { p.SetAccessRule(R(u1, RP, allow)); return "done"; }),
    ("ResetAccessRule(allow U1 RP)", p => { p.ResetAccessRule(R(u1, RP, allow)); return "done"; }),
    ("RemoveAccessRule(allow U2 RP) [no match]", p => $"returned={p.RemoveAccessRule(R(u2, RP, allow))}"),
    ("RemoveAccessRuleSpecific(allow U2 RP) [no match]", p => { p.RemoveAccessRuleSpecific(R(u2, RP, allow)); return "done"; }),
    ("RemoveAccess(U2, Allow) [no match]", p => { p.RemoveAccess(u2, allow); return "done"; }),
    ("RemoveAccess(Everyone, Deny) [no match]", p => { p.RemoveAccess(everyone, deny); return "done"; }),
    ("PurgeAccessRules(U2) [no match]", p => { p.PurgeAccessRules(u2); return "done"; }),
    ("PurgeAccessRules(Everyone)", p => { p.PurgeAccessRules(everyone); return "done"; }),
    ("RemoveAccessRule(allow Everyone RP) [partial]", p => $"returned={p.RemoveAccessRule(R(everyone, RP, allow))}"),
    ("RemoveAccessRuleSpecific(Everyone 0xFFFFFFFF CI|OI) [exact]", p => { p.RemoveAccessRuleSpecific(everyoneFull); return "done"; }),
    ("AddAccessRule(null) [failed call]", p => { p.AddAccessRule(null!); return "done"; }),
    ("ModifyAccessRule(Add, null) [failed call]", p => $"returned={p.ModifyAccessRule(E.AccessControlModification.Add, null!, out _)}"),
};
foreach (var (state, bytes) in daclStates.Where(s => s.Name != "populated DACL"))
{
    foreach (var (opName, op) in stateOps)
    {
        Case($"B6 {state}: {opName}", () =>
        {
            var p = Load(bytes);
            p.ResetFlags();
            try { Console.WriteLine($"  op: {op(p)}"); }
            catch (Exception ex) { Console.WriteLine($"  op: EXC {Ex(ex)}"); }
            Snap("after", p, bytes);
        });
    }
}

// ---------------------------------------------------------------- C. merging
var mergeCases = new (string Name, M.ActiveDirectoryAccessRule First, M.ActiveDirectoryAccessRule Second)[]
{
    ("RP + WP, same scope", R(u1, RP, allow), R(u1, WP, allow)),
    ("identical rule twice", R(u1, RP, allow), R(u1, RP, allow)),
    ("RP None + RP All", R(u1, RP, allow), R(u1, RP, allow, inheritance: all)),
    ("RP None + RP Descendents (complementary scopes)", R(u1, RP, allow),
        R(u1, RP, allow, inheritance: M.ActiveDirectorySecurityInheritance.Descendents)),
    ("RP Children + RP SelfAndChildren", R(u1, RP, allow, inheritance: M.ActiveDirectorySecurityInheritance.Children),
        R(u1, RP, allow, inheritance: M.ActiveDirectorySecurityInheritance.SelfAndChildren)),
    ("RP no GUID + RP G1", R(u1, RP, allow), R(u1, RP, allow, G1)),
    ("RP G1 + WP G1", R(u1, RP, allow, G1), R(u1, WP, allow, G1)),
    ("RP G1 + RP G2", R(u1, RP, allow, G1), R(u1, RP, allow, G2)),
    ("RP G1/All/inh G2 + RP G1/All", R(u1, RP, allow, G1, all, G2), R(u1, RP, allow, G1, all)),
    ("allow RP + deny RP", R(u1, RP, allow), R(u1, RP, deny)),
};
foreach (var (name, first, second) in mergeCases)
{
    Case($"C1 merge: {name}", () =>
    {
        var p = Load(EmptyDacl());
        p.AddAccessRule(first);
        Snap("after first", p);
        Step2("ModifyAccessRule(Add, second)", () => (p.ModifyAccessRule(E.AccessControlModification.Add, second, out var m), m));
        Snap("after second", p);
    });
}
Case("C2 audit merge: Success + Failure same mask", () =>
{
    var p = Load(saclEmpty);
    p.AddAuditRule(A(u1, RP, E.AuditFlags.Success));
    p.AddAuditRule(A(u1, RP, E.AuditFlags.Failure));
    Snap("after", p);
});
Case("C3 audit merge: Success RP + Success WP", () =>
{
    var p = Load(saclEmpty);
    p.AddAuditRule(A(u1, RP, E.AuditFlags.Success));
    p.AddAuditRule(A(u1, WP, E.AuditFlags.Success));
    Snap("after", p);
});

// ---------------------------------------------------------------- D. ordering
Case("D1 order of added explicit rules", () =>
{
    var p = Load(EmptyDacl());
    p.AddAccessRule(R(u1, RP, allow));
    p.AddAccessRule(R(u2, RP, deny));
    p.AddAccessRule(R(u2, RP, allow, G1));
    p.AddAccessRule(R(u1, WP, deny, G1));
    p.AddAccessRule(R(u2, LC, allow, inheritance: all));
    Snap("after", p);
});
Case("D2 explicit added to DACL holding inherited ACEs", () =>
{
    var input = WithDacl(Ace(0x00, Inherited | Ci, 0x10, Everyone), Ace(0x01, Inherited, 0x20, U2));
    var p = Load(input);
    Snap("import", p, input);
    p.AddAccessRule(R(u1, RP, allow));
    p.AddAccessRule(R(u1, WP, deny));
    Snap("after", p);
});

// ---------------------------------------------------------------- E. removal and splitting
void SplitCase(string name, M.ActiveDirectoryAccessRule start, Action<Probe> remove)
{
    Case($"E1 {name}", () =>
    {
        var p = Load(EmptyDacl());
        p.AddAccessRule(start);
        Snap("start", p);
        remove(p);
        Snap("after", p);
    });
}
SplitCase("RemoveAccessRule(WP None) from RP|WP All", R(u1, RP | WP, allow, inheritance: all),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, WP, allow))));
SplitCase("RemoveAccessRule(RP Children) from RP|WP All", R(u1, RP | WP, allow, inheritance: all),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, RP, allow, inheritance: M.ActiveDirectorySecurityInheritance.Children))));
SplitCase("RemoveAccessRule(RP|WP Descendents) from RP|WP All", R(u1, RP | WP, allow, inheritance: all),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, RP | WP, allow, inheritance: M.ActiveDirectorySecurityInheritance.Descendents))));
SplitCase("RemoveAccessRule(RP G1) from non-object RP", R(u1, RP, allow),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, RP, allow, G1))));
SplitCase("RemoveAccessRule(RP) from object RP G1", R(u1, RP, allow, G1),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, RP, allow))));
SplitCase("RemoveAccessRuleSpecific(RP All) from RP|WP All (inexact)", R(u1, RP | WP, allow, inheritance: all),
    p => Step("remove specific", () => p.RemoveAccessRuleSpecific(R(u1, RP, allow, inheritance: all))));
SplitCase("RemoveAccessRuleSpecific(RP|WP All) exact", R(u1, RP | WP, allow, inheritance: all),
    p => Step("remove specific", () => p.RemoveAccessRuleSpecific(R(u1, RP | WP, allow, inheritance: all))));
SplitCase("RemoveAccessRule(RP) when absent", R(u1, WP, allow),
    p => StepBool("remove", () => p.RemoveAccessRule(R(u1, RP, allow))));
Case("E2 audit split: RemoveAuditRule(Failure) from Success|Failure", () =>
{
    var p = Load(saclEmpty);
    p.AddAuditRule(A(u1, RP, E.AuditFlags.Success | E.AuditFlags.Failure, all));
    Snap("start", p);
    StepBool("remove", () => p.RemoveAuditRule(A(u1, RP, E.AuditFlags.Failure)));
    Snap("after", p);
});

// ---------------------------------------------------------------- F. Set / Reset / Purge scope
byte[] ScopeFixture() => WithDacl(
    ObjAce(0x06, 0, 0x100, 1, G2, null, U1),
    ObjAce(0x05, 0, 0x10, 1, G1, null, U1),
    Ace(0x00, 0, 0x20, U1),
    Ace(0x00, 0, 0x10, U2),
    Ace(0x00, Inherited, 0x10, U1));
var scopeOps = new (string Name, Action<Probe> Op)[]
{
    ("SetAccessRule(allow U1 XR G2)", p => p.SetAccessRule(R(u1, XR, allow, G2))),
    ("SetAccessRule(allow U1 RP no GUID)", p => p.SetAccessRule(R(u1, RP, allow))),
    ("ResetAccessRule(allow U1 LC)", p => p.ResetAccessRule(R(u1, LC, allow))),
    ("PurgeAccessRules(U1)", p => p.PurgeAccessRules(u1)),
    ("RemoveAccess(U1, Allow)", p => p.RemoveAccess(u1, allow)),
    ("RemoveAccess(U1, Deny)", p => p.RemoveAccess(u1, deny)),
};
foreach (var (name, op) in scopeOps)
{
    Case($"F1 {name}", () =>
    {
        var input = ScopeFixture();
        var p = Load(input);
        Snap("import", p, input);
        Step("op", () => op(p));
        Snap("after", p);
    });
}

// ---------------------------------------------------------------- G. non-canonical input
var nonCanonical = new (string Name, byte[] Bytes)[]
{
    ("explicit allow before explicit deny", WithDacl(Ace(0x00, 0, 0x10, U1), Ace(0x01, 0, 0x10, U2))),
    ("inherited before explicit", WithDacl(Ace(0x00, Inherited, 0x10, U1), Ace(0x00, 0, 0x20, U2))),
};
foreach (var (name, bytes) in nonCanonical)
{
    Case($"G1 {name}: import", () => Snap("import", Load(bytes), bytes));
    Case($"G2 {name}: AddAccessRule(allow U2 WP)", () =>
    {
        var p = Load(bytes);
        Step("add", () => p.AddAccessRule(R(u2, WP, allow)));
        Snap("after", p);
    });
    Case($"G3 {name}: PurgeAccessRules(U2)", () =>
    {
        var p = Load(bytes);
        Step("purge", () => p.PurgeAccessRules(u2));
        Snap("after", p);
    });
}

// ---------------------------------------------------------------- H. unusual payloads
var mandatoryLabel = Sid("S-1-16-8192");
var appData = new byte[] { 0x61, 0x72, 0x74, 0x78 }; // "artx" conditional-expression marker
var unusual = new (string Name, byte[] Bytes)[]
{
    ("callback allow ACE (0x09) with app data", WithDacl(Ace(0x09, 0, 0x10, U1, appData))),
    ("callback allow object ACE (0x0B) with app data", WithDacl(ObjAce(0x0B, 0, 0x10, 1, G1, null, U1, appData))),
    ("unknown ACE type 0x20", WithDacl(Ace(0x20, 0, 0x10, U1))),
    ("allow ACE with 4 trailing bytes", WithDacl(Ace(0x00, 0, 0x10, U1, new byte[4]))),
    ("ACL revision 2 holding object ACE", Build(Admins, Admins, Acl(2, ObjAce(0x05, 0, 0x10, 1, G1, null, U1)))),
    ("object ACE with object flags 0", WithDacl(ObjAce(0x05, 0, 0x10, 0, null, null, U1))),
    ("object ACE with present all-zero GUID", WithDacl(ObjAce(0x05, 0, 0x10, 1, Guid.Empty, null, U1))),
    ("object ACE with unknown object flag 0x4", WithDacl(ObjAce(0x05, 0, 0x10, 5, G1, null, U1))),
    ("unknown ACE flag bit 0x20", WithDacl(Ace(0x00, 0x20, 0x10, U1))),
    ("auto-inherit control bits 0x0500", Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)), extraControl: 0x0500)),
    ("mandatory label ACE in SACL", Build(Admins, Admins, Acl(4), sacl: Acl(2, Ace(0x11, 0, 1, mandatoryLabel)))),
    ("audit ACE inside DACL", WithDacl(Ace(0x02, Success, 0x10, U1))),
    ("generic-read bit 0x80000000 in mask", WithDacl(Ace(0x00, 0, 0x80000000, U1))),
};
foreach (var (name, bytes) in unusual)
{
    Case($"H1 {name}: import", () => Snap("import", Load(bytes), bytes));
    Case($"H2 {name}: unrelated AddAccessRule(allow U2 WP)", () =>
    {
        var p = Load(bytes);
        Step("add", () => p.AddAccessRule(R(u2, WP, allow)));
        Snap("after", p);
    });
}

// ---------------------------------------------------------------- I. InheritanceType getter
var inheritanceFlags = new (string Name, byte Flags)[]
{
    ("OI only", Oi), ("OI|CI", (byte)(Oi | Ci)), ("CI|NP", (byte)(Ci | Np)),
    ("CI|IO|NP", (byte)(Ci | Io | Np)), ("IO only", Io), ("NP only", Np),
};
foreach (var (name, flags) in inheritanceFlags)
    Case($"I1 imported ACE flags {name}", () => { var b = WithDacl(Ace(0x00, flags, 0x10, U1)); Snap("import", Load(b), b); });

// ---------------------------------------------------------------- I2. inactive InheritOnly matrix
// "Inactive" = InheritOnly set, neither ContainerInherit nor ObjectInherit. Each target ACE sits
// between two neighbor ACEs so neighbor survival and order are visible. CI controls show the
// same ACE kind with an active inheritance flag. Callback/unknown rows are recorded only; they
// are excluded from any allowlist regardless of outcome.
const byte IO = Io, CI = Ci, INH = Inherited, S = Success, F = Failure;
var ioCases = new (string Group, string Name, bool Sacl, byte[] Target)[]
{
    ("DACL common", "Allow IO (baseline)", false, Ace(0x00, IO, 0x10, U1)),
    ("DACL common", "Allow IO|CI (control)", false, Ace(0x00, (byte)(IO | CI), 0x10, U1)),
    ("DACL common", "Allow IO|NP", false, Ace(0x00, (byte)(IO | Np), 0x10, U1)),
    ("DACL common", "Allow IO|INHERITED", false, Ace(0x00, (byte)(IO | INH), 0x10, U1)),
    ("DACL common", "Deny IO", false, Ace(0x01, IO, 0x10, U1)),
    ("DACL common", "Deny IO|CI (control)", false, Ace(0x01, (byte)(IO | CI), 0x10, U1)),
    ("DACL common", "Deny IO|INHERITED", false, Ace(0x01, (byte)(IO | INH), 0x10, U1)),
    ("DACL object", "AllowObj IO of=0", false, ObjAce(0x05, IO, 0x10, 0, null, null, U1)),
    ("DACL object", "AllowObj IO of=1 ot=G1", false, ObjAce(0x05, IO, 0x10, 1, G1, null, U1)),
    ("DACL object", "AllowObj IO of=2 it=G2", false, ObjAce(0x05, IO, 0x10, 2, null, G2, U1)),
    ("DACL object", "AllowObj IO of=3 ot=G1 it=G2", false, ObjAce(0x05, IO, 0x10, 3, G1, G2, U1)),
    ("DACL object", "AllowObj IO|CI of=2 it=G2 (control)", false, ObjAce(0x05, (byte)(IO | CI), 0x10, 2, null, G2, U1)),
    ("DACL object", "DenyObj IO of=1 ot=G1", false, ObjAce(0x06, IO, 0x10, 1, G1, null, U1)),
    ("DACL object", "DenyObj IO of=2 it=G2", false, ObjAce(0x06, IO, 0x10, 2, null, G2, U1)),
    ("DACL object", "DenyObj IO of=3 ot=G1 it=G2", false, ObjAce(0x06, IO, 0x10, 3, G1, G2, U1)),
    ("DACL object", "AllowObj IO|INHERITED of=1 ot=G1", false, ObjAce(0x05, (byte)(IO | INH), 0x10, 1, G1, null, U1)),
    ("SACL audit", "Audit IO|S", true, Ace(0x02, (byte)(IO | S), 0x10, U1)),
    ("SACL audit", "Audit IO|F", true, Ace(0x02, (byte)(IO | F), 0x10, U1)),
    ("SACL audit", "Audit IO|S|F", true, Ace(0x02, (byte)(IO | S | F), 0x10, U1)),
    ("SACL audit", "Audit IO (no audit flags)", true, Ace(0x02, IO, 0x10, U1)),
    ("SACL audit", "Audit IO|CI|S (control)", true, Ace(0x02, (byte)(IO | CI | S), 0x10, U1)),
    ("SACL audit", "Audit IO|S|INHERITED", true, Ace(0x02, (byte)(IO | S | INH), 0x10, U1)),
    ("SACL audit", "AuditObj IO|S of=1 ot=G1", true, ObjAce(0x07, (byte)(IO | S), 0x10, 1, G1, null, U1)),
    ("SACL audit", "AuditObj IO|S of=2 it=G2", true, ObjAce(0x07, (byte)(IO | S), 0x10, 2, null, G2, U1)),
    ("SACL audit", "AuditObj IO|S|F of=3 ot=G1 it=G2", true, ObjAce(0x07, (byte)(IO | S | F), 0x10, 3, G1, G2, U1)),
    ("Excluded (record only)", "Allow IO with unknown flag 0x20", false, Ace(0x00, (byte)(IO | 0x20), 0x10, U1)),
    ("Excluded (record only)", "AllowObj IO unknown object flag 0x4", false, ObjAce(0x05, IO, 0x10, 5, G1, null, U1)),
    ("Excluded (record only)", "Allow IO with 4 trailing bytes", false, Ace(0x00, IO, 0x10, U1, new byte[4])),
    ("Excluded (record only)", "AllowCallback IO with app data", false, Ace(0x09, IO, 0x10, U1, appData)),
    ("Excluded (record only)", "AllowCallbackObj IO with app data", false, ObjAce(0x0B, IO, 0x10, 1, G1, null, U1, appData)),
    ("Excluded (record only)", "Unknown type 0x20 with IO", false, Ace(0x20, IO, 0x10, U1)),
};
var verdicts = new List<string>();
foreach (var (group, name, sacl, target) in ioCases)
{
    Case($"I2 {group}: {name}", () =>
    {
        // Neighbors: canonical explicit deny/allow (DACL) or two audits (SACL) around the target.
        var before = sacl ? Ace(0x02, S, 0x20, U2) : Ace(0x01, 0, 0x20, U2);
        var after = sacl ? Ace(0x02, F, 0x04, U2) : Ace(0x00, 0, 0x04, U2);
        var aclBytes = Acl(4, before, target, after);
        var input = sacl ? Build(Admins, Admins, Acl(4), sacl: aclBytes) : Build(Admins, Admins, aclBytes);
        Probe p;
        try { p = Load(input); }
        catch (Exception ex)
        {
            Console.WriteLine($"  import: EXC {Ex(ex)}");
            verdicts.Add($"{group} | {name} | REJECTED on import ({ex.GetType().Name}) | - | -");
            return;
        }
        var output = p.GetSecurityDescriptorBinaryForm();
        Snap("import", p, input);
        var importVerdict = Verdict(output, target, before, after, sacl);
        Console.WriteLine($"  verdict(import): {importVerdict}");
        // Unrelated edit in the same ACL, then re-check.
        string editVerdict;
        try
        {
            if (sacl) p.AddAuditRule(A(everyone, XR, E.AuditFlags.Success)); else p.AddAccessRule(R(everyone, XR, allow)); // distinct SID: cannot merge with neighbors
            var edited = p.GetSecurityDescriptorBinaryForm();
            Snap("after unrelated add", p);
            editVerdict = Verdict(edited, target, before, after, sacl);
        }
        catch (Exception ex) { editVerdict = $"edit REJECTED ({ex.GetType().Name})"; Console.WriteLine($"  edit: EXC {Ex(ex)}"); }
        Console.WriteLine($"  verdict(after unrelated add): {editVerdict}");
        verdicts.Add($"{group} | {name} | {importVerdict} | {editVerdict} | canonical={p.AreAccessRulesCanonical}/{p.AreAuditRulesCanonical}");
    });
}
Console.WriteLine("== I2 SUMMARY (group | case | import | after unrelated add | canonical access/audit)");
foreach (var line in verdicts) Console.WriteLine("  " + line);

// ---------------------------------------------------------------- J. binary setters and dirty flags
Case("J1 section-limited SetSecurityDescriptorBinaryForm(bytes, Access) keeps owner?", () =>
{
    var p = Load(WithDacl(Ace(0x00, 0, 0x10, Everyone)));
    p.SetOwner(u1);
    Snap("after SetOwner(U1)", p);
    p.ResetFlags();
    Console.WriteLine($"  flags reset: {p.Flags()}");
    Step("set Access only", () => p.SetSecurityDescriptorBinaryForm(Build(U2, U2, Acl(4, Ace(0x00, 0, 0x20, U2))), E.AccessControlSections.Access));
    Console.WriteLine($"  flags immediately after Access-only set: {p.Flags()}");
    Snap("after", p);
});
// Flag effects of each binary setter in isolation: fresh or reset object, one call, then flags only.
var flagInput = Build(Admins, Admins, Acl(4, Ace(0x00, 0, 0x10, U1)), sacl: Acl(4));
foreach (var (name, sections) in new (string, E.AccessControlSections?)[]
{
    ("All (1-arg overload)", null), ("Access", E.AccessControlSections.Access), ("Audit", E.AccessControlSections.Audit),
    ("Owner", E.AccessControlSections.Owner), ("Group", E.AccessControlSections.Group),
})
{
    Case($"J5 flags from SetSecurityDescriptorBinaryForm {name}", () =>
    {
        var fresh = new Probe();
        Console.WriteLine($"  fresh: {fresh.Flags()}");
        Step("set", () => { if (sections is { } s) fresh.SetSecurityDescriptorBinaryForm(flagInput, s); else fresh.SetSecurityDescriptorBinaryForm(flagInput); });
        Console.WriteLine($"  after set on fresh object: {fresh.Flags()}");
        var reset = Load(flagInput);
        reset.ResetFlags();
        Console.WriteLine($"  loaded then reset: {reset.Flags()}");
        Step("set again", () => { if (sections is { } s) reset.SetSecurityDescriptorBinaryForm(flagInput, s); else reset.SetSecurityDescriptorBinaryForm(flagInput); });
        Console.WriteLine($"  after set on reset object: {reset.Flags()}");
        _ = reset.GetSecurityDescriptorBinaryForm();
        _ = reset.GetAccessRules(true, true, typeof(B.SecurityIdentifier));
        Console.WriteLine($"  after Get/GetAccessRules only: {reset.Flags()}");
    });
}
Case("J2 SetSecurityDescriptorBinaryForm(All) from input lacking owner/group", () =>
{
    var p = Load(WithDacl(Ace(0x00, 0, 0x10, Everyone)));
    var input = Build(null, null, Acl(4, Ace(0x00, 0, 0x20, U2)));
    Step("set All", () => p.SetSecurityDescriptorBinaryForm(input));
    Snap("after", p, input);
});
Case("J3 dirty flags (reset before each op): failed remove, no-op add", () =>
{
    var p = Load(WithDacl(Ace(0x00, 0, 0x10, U1)));
    Snap("import only", p);
    var fresh = Load(WithDacl(Ace(0x00, 0, 0x10, U1)));
    fresh.ResetFlags();
    Console.WriteLine($"  fresh reset: {fresh.Flags()}");
    StepBool("remove absent rule", () => fresh.RemoveAccessRule(R(u2, WP, allow)));
    Snap("after failed remove", fresh);
    var noop = Load(WithDacl(Ace(0x00, 0, 0x10, U1)));
    noop.ResetFlags();
    Console.WriteLine($"  noop reset: {noop.Flags()}");
    Step2("add existing rule", () => (noop.ModifyAccessRule(E.AccessControlModification.Add, R(u1, RP, allow), out var m), m));
    Snap("after no-op add", noop);
});
// J6: descriptors whose components share bytes. The portable codec currently rejects any
// overlap; this records whether Microsoft accepts them (managed ActiveDirectorySecurity and
// RawSecurityDescriptor) and what it re-emits.
byte[] WithOffsets(byte[] source, params (int Field, int Offset)[] patches)
{
    var copy = source.ToArray();
    foreach (var (field, offset) in patches)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(field), (uint)offset);
    return copy;
}
int OffsetOf(byte[] sd, int field) => (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(field));
var shareBase = Build(Admins, U2, Acl(4, Ace(0x00, 0, 0x10, U1)), sacl: Acl(4));
var sharedEmpty = Build(Admins, Admins, Acl(4), sacl: Acl(4));
var sharedPopulated = Build(Admins, Admins, Acl(4, Ace(0x02, Success, 0x10, U1)), sacl: Acl(4, Ace(0x02, Success, 0x10, U1)));
var shareCases = new (string Name, byte[] Bytes)[]
{
    ("owner offset == group offset (identical SID storage)", WithOffsets(shareBase, (8, OffsetOf(shareBase, 4)))),
    ("SACL offset == DACL offset (shared empty ACL)", WithOffsets(sharedEmpty, (12, OffsetOf(sharedEmpty, 16)))),
    ("SACL offset == DACL offset (shared ACL with one audit ACE)", WithOffsets(sharedPopulated, (12, OffsetOf(sharedPopulated, 16)))),
    ("group SID read from inside the DACL's ACE (partial overlap)", WithOffsets(shareBase, (8, OffsetOf(shareBase, 16) + 8 + 8))),
    ("owner SID read from inside the DACL's ACE (partial overlap)", WithOffsets(shareBase, (4, OffsetOf(shareBase, 16) + 8 + 8))),
};
foreach (var (name, bytes) in shareCases)
{
    Case($"J6 shared storage: {name}", () =>
    {
        Console.WriteLine($"    input={Convert.ToHexString(bytes)}");
        try
        {
            var raw = new E.RawSecurityDescriptor(bytes, 0);
            var rawOut = new byte[raw.BinaryLength];
            raw.GetBinaryForm(rawOut, 0);
            Console.WriteLine($"  RawSecurityDescriptor: accepted; {Describe(rawOut)}; output-equals-input={rawOut.AsSpan().SequenceEqual(bytes)}");
        }
        catch (Exception ex) { Console.WriteLine($"  RawSecurityDescriptor: EXC {Ex(ex)}"); }

        Probe p;
        try { p = Load(bytes); }
        catch (Exception ex) { Console.WriteLine($"  ActiveDirectorySecurity: EXC {Ex(ex)}"); return; }
        Console.WriteLine("  ActiveDirectorySecurity: accepted");
        Snap("import", p, bytes);
    });
}

Case("J4 component order DACL-before-owner round trip", () =>
{
    var forward = WithDacl(Ace(0x00, 0, 0x10, U1));
    // Rebuild with DACL placed directly after the header and owner/group after it.
    var acl = Acl(4, Ace(0x00, 0, 0x10, U1));
    var bytes = new byte[20 + acl.Length + Admins.Length * 2];
    bytes[0] = 1;
    System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), SelfRelative | DaclPresent);
    acl.CopyTo(bytes, 20);
    Admins.CopyTo(bytes, 20 + acl.Length);
    Admins.CopyTo(bytes, 20 + acl.Length + Admins.Length);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)(20 + acl.Length));
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), (uint)(20 + acl.Length + Admins.Length));
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16), 20);
    Snap("import", Load(bytes), bytes);
    Console.WriteLine($"    equals forward-order bytes after export: {Load(bytes).GetSecurityDescriptorBinaryForm().AsSpan().SequenceEqual(forward)}");
});

Console.WriteLine("END");
// Optional deterministic sequence recording is separate from the historical text transcript.
var sequenceArgument = Array.IndexOf(args, "--sequence-json");
if (sequenceArgument >= 0)
{
    if (sequenceArgument + 1 >= args.Length) throw new ArgumentException("--sequence-json requires an output path");
    SeededSequences.Record(args[sequenceArgument + 1]);
}
foreach (var option in new[] { "--foundation-json", "--surface-json", "--closure-json" })
{
    var argument = Array.IndexOf(args, option);
    if (argument < 0) continue;
    if (argument + 1 >= args.Length) throw new ArgumentException(option + " requires an output path");
    if (option == "--foundation-json") FoundationContracts.Write(args[argument + 1]);
    else if (option == "--surface-json") RequiredSurface.Write(args[argument + 1]);
    else ClosureContracts.Write(args[argument + 1]);
}
return 0;

// ---------------------------------------------------------------- helpers
Probe Load(byte[] bytes)
{
    var p = new Probe();
    p.SetSecurityDescriptorBinaryForm(bytes);
    return p;
}

void Case(string name, Action body)
{
    Console.WriteLine($"== {name}");
    try { body(); }
    catch (Exception ex) { Console.WriteLine($"  CASE EXC {Ex(ex)}"); }
}

void Step(string label, Action action)
{
    try { action(); Console.WriteLine($"  {label}: ok"); }
    catch (Exception ex) { Console.WriteLine($"  {label}: EXC {Ex(ex)}"); }
}

void StepBool(string label, Func<bool> action)
{
    try { Console.WriteLine($"  {label}: returned={action()}"); }
    catch (Exception ex) { Console.WriteLine($"  {label}: EXC {Ex(ex)}"); }
}

void Step2(string label, Func<(bool Result, bool Modified)> action)
{
    try { var (r, m) = action(); Console.WriteLine($"  {label}: returned={r} modified={m}"); }
    catch (Exception ex) { Console.WriteLine($"  {label}: EXC {Ex(ex)}"); }
}

void Snap(string label, Probe p, byte[]? input = null)
{
    var bytes = p.GetSecurityDescriptorBinaryForm();
    Console.WriteLine($"  [{label}] {Describe(bytes)}");
    if (input is not null)
    {
        var reimported = Load(bytes).GetSecurityDescriptorBinaryForm();
        Console.WriteLine($"    input-bytes-preserved={bytes.AsSpan().SequenceEqual(input)} reexport-stable={reimported.AsSpan().SequenceEqual(bytes)}");
        if (!bytes.AsSpan().SequenceEqual(input)) Console.WriteLine($"    input={Convert.ToHexString(input)}");
    }
    Console.WriteLine($"    hex={Convert.ToHexString(bytes)}");
    Console.WriteLine($"    canonical(access/audit)={p.AreAccessRulesCanonical}/{p.AreAuditRulesCanonical} protected={p.AreAccessRulesProtected} {p.Flags()}");
    Console.WriteLine($"    sddl={Try(() => p.GetSecurityDescriptorSddlForm(E.AccessControlSections.All))}");
    foreach (E.AuthorizationRule rule in p.GetAccessRules(true, true, typeof(B.SecurityIdentifier)))
        Console.WriteLine($"    rule {Rule(rule)}");
    foreach (E.AuthorizationRule rule in p.GetAuditRules(true, true, typeof(B.SecurityIdentifier)))
        Console.WriteLine($"    audit {Rule(rule)}");
}

// Classifies the target ACE against the parsed ACEs of the ACL it was placed in.
// PRESERVED = an ACE byte-identical to the target exists; MODIFIED = no identical ACE, but one
// with the same access mask whose body contains U1's SID (flags/type/payload changed);
// DROPPED = neither. Neighbors are checked for exact survival and relative order.
string Verdict(byte[] output, byte[] target, byte[] before, byte[] after, bool sacl)
{
    var aces = AceList(output, sacl);
    int Index(byte[] ace) => aces.FindIndex(a => a.AsSpan().SequenceEqual(ace));
    var targetState = Index(target) >= 0 ? "PRESERVED"
        : aces.Any(a => a.Length >= 8 && a.AsSpan(4, 4).SequenceEqual(target.AsSpan(4, 4)) && a.AsSpan(8).IndexOf(U1) >= 0) ? "MODIFIED"
        : "DROPPED";
    var b = Index(before); var f = Index(after);
    var neighbors = b < 0 || f < 0 ? "NEIGHBOR CHANGED" : b < f ? "neighbors intact, order kept" : "neighbors intact, ORDER CHANGED";
    return $"{targetState}; {neighbors}; aces={aces.Count}";
}

string Rule(E.AuthorizationRule rule)
{
    var common = $"{Who(rule.IdentityReference)} inh={rule.IsInherited} IF={rule.InheritanceFlags} PF={rule.PropagationFlags}";
    return rule switch
    {
        M.ActiveDirectoryAccessRule a => $"{a.GetType().Name} {a.AccessControlType} rights=0x{(int)a.ActiveDirectoryRights:X} {common} OF={a.ObjectFlags} ot={G(a.ObjectType)} it={G(a.InheritedObjectType)} IT={Try(() => a.InheritanceType)}",
        M.ActiveDirectoryAuditRule u => $"{u.GetType().Name} {u.AuditFlags} rights=0x{(int)u.ActiveDirectoryRights:X} {common} OF={u.ObjectFlags} ot={G(u.ObjectType)} it={G(u.InheritedObjectType)} IT={Try(() => u.InheritanceType)}",
        _ => $"{rule.GetType().FullName} {common}",
    };
}

string Who(B.IdentityReference id) => id.Value switch
{
    "S-1-1-0" => "Everyone", "S-1-5-32-544" => "Admins",
    "S-1-5-21-1-2-3-1001" => "U1", "S-1-5-21-1-2-3-1002" => "U2", var v => v,
};

string G(Guid g) => g == G1 ? "G1" : g == G2 ? "G2" : g == Guid.Empty ? "-" : g.ToString();

string Try<T>(Func<T> f)
{
    try { return f()?.ToString() ?? "null"; }
    catch (Exception ex) { return "EXC " + Ex(ex); }
}

string Ex(Exception ex) => $"{ex.GetType().FullName}{(ex is ArgumentException { ParamName: { } p } ? $"(param={p})" : "")}: {ex.Message.Replace(Environment.NewLine, " ")}";

/// <summary>Reads Microsoft's protected modified flags under the required lock.</summary>
sealed class Probe : M.ActiveDirectorySecurity
{
    public string Flags()
    {
        ReadLock();
        try
        {
            return $"modified(owner/group/access/audit)={B(OwnerModified)}{B(GroupModified)}{B(AccessRulesModified)}{B(AuditRulesModified)}";
        }
        finally { ReadUnlock(); }
    }

    /// <summary>Clears all four modified flags under the write lock, isolating the next call's effect.</summary>
    public void ResetFlags()
    {
        WriteLock();
        try { OwnerModified = GroupModified = AccessRulesModified = AuditRulesModified = false; }
        finally { WriteUnlock(); }
    }

    static char B(bool value) => value ? '1' : '0';
}
