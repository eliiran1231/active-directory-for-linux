using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using Portable = AdForLinux.Security.AccessControl;

if (args.Contains("--inventory"))
{
    // Reflect real BCL public/protected dependency surface without executing constructors.
    foreach (var type in new[] {
        typeof(System.Security.Principal.IdentityReference), typeof(System.Security.Principal.SecurityIdentifier),
        typeof(System.Security.Principal.NTAccount), typeof(System.Security.AccessControl.AuthorizationRule),
        typeof(System.Security.AccessControl.AccessRule), typeof(System.Security.AccessControl.AuditRule),
        typeof(System.Security.AccessControl.ObjectAccessRule), typeof(System.Security.AccessControl.ObjectAuditRule),
        typeof(System.Security.AccessControl.ObjectSecurity), typeof(System.Security.AccessControl.DirectoryObjectSecurity),
        typeof(System.Security.AccessControl.AuthorizationRuleCollection) })
    {
        Console.WriteLine($"TYPE {type.FullName}; public={type.IsPublic}; abstract={type.IsAbstract}; sealed={type.IsSealed}; base={type.BaseType}; interfaces={string.Join(",", type.GetInterfaces().Select(t => t.FullName))}");
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        foreach (var member in type.GetMembers(flags).OrderBy(m => m.Name, StringComparer.Ordinal).ThenBy(m => m.ToString(), StringComparer.Ordinal))
        {
            if (member is MethodBase method && (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly || method.IsFamilyAndAssembly))
                Console.WriteLine($"  {method.Attributes & MethodAttributes.MemberAccessMask} {method}; static={method.IsStatic}; abstract={method.IsAbstract}; virtual={method.IsVirtual}; final={method.IsFinal}");
            else if (member is FieldInfo field && (field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly || field.IsFamilyAndAssembly))
                Console.WriteLine($"  {field.Attributes & FieldAttributes.FieldAccessMask} field {field}; static={field.IsStatic}; readonly={field.IsInitOnly}; literal={field.IsLiteral}");
        }
    }
    return;
}
Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; {RuntimeInformation.RuntimeIdentifier}");
Console.WriteLine("Research only: constructors/properties/type binding; descriptor operations deliberately unsupported.");
var sid = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
var bytes = new byte[sid.BinaryLength + 5];
sid.GetBinaryForm(bytes, 3);
var roundTrip = new SecurityIdentifier(bytes, 3);
Check(roundTrip.Value == sid.Value, "SID binary offset round-trip");
bytes[3] = 99;
Check(roundTrip.Value == sid.Value, "SID retains a defensive copy");
var classNames = new[] { "ActiveDirectorySecurity", "ActiveDirectoryAccessRule", "ActiveDirectoryAuditRule",
    "CreateChildAccessRule", "DeleteChildAccessRule", "DeleteTreeAccessRule", "ExtendedRightAccessRule",
    "ListChildrenAccessRule", "PropertyAccessRule", "PropertySetAccessRule" };
var ctorCount = 0;
foreach (var name in classNames)
{
    var type = typeof(ActiveDirectorySecurity).Assembly.GetType("AdForLinux.DirectoryServices." + name)!;
    foreach (var ctor in type.GetConstructors())
    {
        var parameters = ctor.GetParameters().Select(p => Example(p.ParameterType)).ToArray();
        var value = ctor.Invoke(parameters);
        if (value is Portable.AuthorizationRule rule)
            Check(ReferenceEquals(rule.IdentityReference, sid), name + " retains portable identity");
        ctorCount++;
    }
    Console.WriteLine($"CONSTRUCTED {name}: {type.GetConstructors().Length} public constructors; base={type.BaseType}");
}
Check(ctorCount == 46, "46 existing public constructor shapes");
var security = new ActiveDirectorySecurity();
Portable.ObjectSecurity baseView = security;
var factoryRule = baseView.AccessRuleFactory(sid, (int)ActiveDirectoryRights.ReadProperty, false,
    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
Check(factoryRule is ActiveDirectoryAccessRule, "virtual rule factory returns existing-name wrapper");
var list = new List<Portable.AccessRule> { factoryRule };
Check(list.Count == 1, "portable base generic collection compiles");
Check(!typeof(System.Security.AccessControl.ObjectSecurity).IsAssignableFrom(typeof(ActiveDirectorySecurity)), "BCL security base assignability is lost");
Check(!typeof(System.Security.Principal.IdentityReference).IsAssignableFrom(typeof(SecurityIdentifier)), "BCL identity assignability is lost");
Check(typeof(Portable.AccessRule).GetProperty("AccessControlType")!.PropertyType == typeof(AccessControlType), "real BCL enum identity retained");
Check((int)SecurityMasks.Dacl == 4 && (int)AccessControlSections.Access == 2, "LDAP masks and BCL section flags differ: never cast between them");
try
{
    security.AddAccessRule((ActiveDirectoryAccessRule)factoryRule);
    throw new Exception("Scaffold unexpectedly implemented descriptor mutation");
}
catch (NotSupportedException ex) when (ex is not PlatformNotSupportedException)
{
    Console.WriteLine("EXPECTED scaffold refusal: " + ex.Message);
}
Console.WriteLine($"PASS: {ctorCount} constructors, SID offset/copy, factory dispatch, portable generic base, enum identity, explicit BCL incompatibility.");
object Example(Type type) => type == typeof(IdentityReference) ? sid :
    type == typeof(ActiveDirectoryRights) ? ActiveDirectoryRights.ReadProperty :
    type == typeof(AccessControlType) ? AccessControlType.Allow :
    type == typeof(AuditFlags) ? AuditFlags.Success :
    type == typeof(ActiveDirectorySecurityInheritance) ? ActiveDirectorySecurityInheritance.None :
    type == typeof(PropertyAccess) ? PropertyAccess.Read :
    type == typeof(Guid) ? Guid.Parse("11111111-1111-1111-1111-111111111111") :
    throw new Exception("Unhandled parameter " + type);
void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
#if BCL_CLIENT
// Expected compile failures: a recompiled but unmigrated consumer does not retain BCL compatibility.
var bclSid = new System.Security.Principal.SecurityIdentifier("S-1-1-0");
_ = new ActiveDirectoryAccessRule(bclSid, ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
System.Security.AccessControl.ObjectSecurity oldBase = security;
var oldRules = new List<System.Security.AccessControl.AccessRule> { factoryRule };
#endif
