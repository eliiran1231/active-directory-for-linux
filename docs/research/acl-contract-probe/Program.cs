using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using AdForLinux.DirectoryServices;

Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; {RuntimeInformation.RuntimeIdentifier}");
Console.WriteLine($"OS: {RuntimeInformation.OSDescription}");
Console.WriteLine($"Library: {typeof(ActiveDirectorySecurity).Assembly.GetName()}");
foreach (var type in new[] { typeof(IdentityReference), typeof(SecurityIdentifier),
    typeof(DirectoryObjectSecurity), typeof(ObjectSecurity), typeof(AuthorizationRule), typeof(ObjectAccessRule), typeof(ObjectAuditRule) })
{
    Console.WriteLine($"TYPE {type.AssemblyQualifiedName}; sealed={type.IsSealed}; base={type.BaseType}");
    foreach (var ctor in type.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
    {
        Console.WriteLine($"  CTOR {ctor}; visibility={ctor.Attributes & MethodAttributes.MemberAccessMask}; IL={Convert.ToHexString(ctor.GetMethodBody()?.GetILAsByteArray() ?? Array.Empty<byte>())}");
    }
}
// Reflection works without constructing a Windows-only instance.
foreach (var method in typeof(ActiveDirectorySecurity).GetMethods(BindingFlags.Public | BindingFlags.Instance)
    .Where(m => new[] { "SetOwner", "SetGroup", "SetSecurityDescriptorBinaryForm", "SetSecurityDescriptorSddlForm",
        "SetAccessRuleProtection", "PurgeAccessRules", "ModifyAccessRule", "GetAccessRules" }.Contains(m.Name))
    .OrderBy(m => m.Name, StringComparer.Ordinal).ThenBy(m => m.ToString(), StringComparer.Ordinal))
    Console.WriteLine($"SURFACE {method}; declared={method.DeclaringType}; virtual={method.IsVirtual}; final={method.IsFinal}");
var failures = 0;
void Probe(string name, Action action)
{
    try { action(); Console.WriteLine($"UNEXPECTED SUCCESS: {name}"); failures++; }
    catch (PlatformNotSupportedException ex)
    {
        Console.WriteLine($"EXPECTED PNSE: {name}: {ex.Message}");
        Console.WriteLine($"  {ex.StackTrace?.Split('\n')[0].Trim()}");
    }
    catch (Exception ex) { Console.WriteLine($"UNEXPECTED {ex.GetType().FullName}: {name}: {ex.Message}"); failures++; }
}
// These use real BCL identities. No allocation bypasses, shadow assemblies or directory I/O.
Probe("BCL SID(string)", () => _ = new SecurityIdentifier("S-1-1-0"));
Probe("BCL SID(bytes)", () => _ = new SecurityIdentifier(new byte[] { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }, 0));
Probe("BCL NTAccount", () => _ = new NTAccount("Everyone"));
Probe("existing ActiveDirectorySecurity()", () => _ = new ActiveDirectorySecurity());
Probe("BCL RawAcl", () => _ = new RawAcl(2, 0));
Probe("BCL RawSecurityDescriptor", () => _ = new RawSecurityDescriptor(ControlFlags.None, null, null, null, null));
Probe("existing caller SID-to-rule expression", () => _ = new ActiveDirectoryAccessRule(new SecurityIdentifier("S-1-1-0"), ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
// Null is intentional: isolates the base-constructor failure from SID construction.
// These are not claims that null is a valid rule identity or that behavioral parity passed.
Probe("existing ActiveDirectoryAccessRule(null)", () => _ = new ActiveDirectoryAccessRule(null!, ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
Probe("existing ActiveDirectoryAuditRule(null)", () => _ = new ActiveDirectoryAuditRule(null!, ActiveDirectoryRights.ReadProperty, AuditFlags.Success));
Probe("existing CreateChildAccessRule(null)", () => _ = new CreateChildAccessRule(null!, AccessControlType.Allow));
Probe("existing DeleteChildAccessRule(null)", () => _ = new DeleteChildAccessRule(null!, AccessControlType.Allow));
Probe("existing DeleteTreeAccessRule(null)", () => _ = new DeleteTreeAccessRule(null!, AccessControlType.Allow));
Probe("existing ExtendedRightAccessRule(null)", () => _ = new ExtendedRightAccessRule(null!, AccessControlType.Allow));
Probe("existing ListChildrenAccessRule(null)", () => _ = new ListChildrenAccessRule(null!, AccessControlType.Allow));
Probe("existing PropertyAccessRule(null)", () => _ = new PropertyAccessRule(null!, AccessControlType.Allow, PropertyAccess.Read));
Probe("existing PropertySetAccessRule(null)", () => _ = new PropertySetAccessRule(null!, AccessControlType.Allow, PropertyAccess.Read, Guid.Parse("11111111-1111-1111-1111-111111111111")));
Console.WriteLine($"Unexpected outcomes: {failures}");
Environment.ExitCode = failures == 0 ? 0 : 1;

#if PROBE_DERIVED_IDENTITY
// Expected compile failure: the BCL base constructor is inaccessible.
sealed class PortableIdentity : IdentityReference
{
    public override string Value => "S-1-1-0";
    public override bool IsValidTargetType(Type t) => t == typeof(PortableIdentity);
    public override IdentityReference Translate(Type t) => this;
    public override bool Equals(object? other) => ReferenceEquals(this, other);
    public override int GetHashCode() => 0;
    public override string ToString() => Value;
}
#endif

// Compile-only consumer shape: preserving method names alone must not lose BCL assignability.
static class ExistingConsumer
{
    public static IdentityReference? ReadOwnerAndAdd(ActiveDirectorySecurity security, SecurityIdentifier sid)
    {
        ObjectSecurity baseView = security;
        AccessRule rule = new ActiveDirectoryAccessRule(sid, ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
        baseView.ModifyAccessRule(AccessControlModification.Add, rule, out _);
        return baseView.GetOwner(typeof(SecurityIdentifier));
    }
}
