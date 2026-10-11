#pragma warning disable CA1416
using System.Security.AccessControl;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
using M = System.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void InteropValues_SidSnapshotCannotHideTrailingStorage()
    {
        Assert.Throws<NotSupportedException>(() => new A.InteropIdentityValue(U1.Concat(new byte[] { 1, 2, 3, 4 }).ToArray()));
    }

    [Theory]
    [InlineData("S-1-0-0")] [InlineData("S-1-5-4294967295")] [InlineData("S-1-281474976710655-1-2-3")]
    [InlineData("EXAMPLE\\Alice")] [InlineData("alice")] [InlineData("Dömäin\\使用者")]
    public void InteropValues_IdentityCopiesExactValueWithoutLookup(string value)
    {
        P.IdentityReference identity = value.StartsWith("S-1-", StringComparison.Ordinal) ? new P.SecurityIdentifier(value) : new P.NTAccount(value);
        var snapshot = A.InteropValueCodec.CaptureIdentity(identity);
        Assert.Equal(identity.Value, snapshot.ToPortable().Value);
        if (snapshot.Sid is { } copied) Array.Fill(copied, (byte)0);
        Assert.Equal(identity.Value, snapshot.ToPortable().Value);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => A.InteropValueCodec.ToMicrosoftIdentity(identity));
            return;
        }
        var native = A.InteropValueCodec.ToMicrosoftIdentity(identity);
        Assert.Equal(identity.Value, native.Value);
        Assert.True(snapshot.Same(A.InteropValueCodec.CaptureMicrosoftIdentity(native)));
    }

    public static IEnumerable<object[]> InteropRuleMatrix()
    {
        foreach (var audit in new[] { false, true })
        foreach (var objectRule in new[] { false, true })
        foreach (var inherited in new[] { false, true })
        foreach (var name in new[] { false, true })
        foreach (var mask in new[] { 16, -1 })
            yield return new object[] { audit, objectRule, inherited, name, mask };
    }

    private static A.InteropRuleValue InteropRuleFields(bool audit = false, bool objectRule = true,
        bool inherited = true, bool name = false, int mask = 16)
        => new(name ? new A.InteropIdentityValue("EXAMPLE\\Alice") : new A.InteropIdentityValue(U1),
            mask, inherited, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly, audit, objectRule,
            audit ? AccessControlType.Allow : AccessControlType.Deny,
            audit ? AuditFlags.Success | AuditFlags.Failure : AuditFlags.None,
            objectRule ? G1 : Guid.Empty, objectRule ? G2 : Guid.Empty,
            objectRule ? ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent : ObjectAceFlags.None);

    [Theory]
    [MemberData(nameof(InteropRuleMatrix))]
    public void InteropValues_RulesPreserveEveryField(bool audit, bool objectRule, bool inherited, bool name, int mask)
    {
        var fields = InteropRuleFields(audit, objectRule, inherited, name, mask);
        A.InteropValueCodec.ValidateRuleFields(fields);
        if (OperatingSystem.IsWindows())
            Assert.True(fields.Same(InspectNativeInteropRule(ConstructNativeInteropRule(fields))));
    }


    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void InteropValues_UnrepresentableFieldsRefuse(int variant)
    {
        var fields = InteropRuleFields();
        fields = variant switch
        {
            0 => fields with { ObjectType = Guid.Empty }, // present-zero cannot be restored by rule constructors
            1 => fields with { ObjectFlags = (ObjectAceFlags)4 },
            2 => fields with { IsObject = false },
            3 => fields with { Inheritance = InheritanceFlags.None },
            4 => fields with { Mask = 0 },
            _ => fields with { Audit = AuditFlags.Success }
        };
        var error = Record.Exception(() => A.InteropValueCodec.ValidateRuleFields(fields));
        Assert.True(error is NotSupportedException or ArgumentException);
    }




    private static AuthorizationRule ConstructNativeInteropRule(A.InteropRuleValue v)
    {
        var id = A.InteropValueCodec.ToMicrosoftIdentity(v.Identity.ToPortable());
        return v.IsObject ? v.IsAudit ? new NativeInteropObjectAudit(id, v) : new NativeInteropObjectAccess(id, v)
            : v.IsAudit ? new NativeInteropAudit(id, v) : new NativeInteropAccess(id, v);
    }

    private static A.InteropRuleValue InspectNativeInteropRule(AuthorizationRule rule)
    {
        var mask = rule switch { NativeInteropAccess a => a.Mask, NativeInteropAudit a => a.Mask,
            NativeInteropObjectAccess a => a.Mask, NativeInteropObjectAudit a => a.Mask, _ => throw new NotSupportedException() };
        return new(A.InteropValueCodec.CaptureMicrosoftIdentity(rule.IdentityReference),
            mask, rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags,
            rule is AuditRule, rule is ObjectAccessRule or ObjectAuditRule,
            rule is AccessRule access ? access.AccessControlType : AccessControlType.Allow,
            rule is AuditRule audit ? audit.AuditFlags : AuditFlags.None,
            rule is ObjectAccessRule oa ? oa.ObjectType : rule is ObjectAuditRule ou ? ou.ObjectType : Guid.Empty,
            rule is ObjectAccessRule oa2 ? oa2.InheritedObjectType : rule is ObjectAuditRule ou2 ? ou2.InheritedObjectType : Guid.Empty,
            rule is ObjectAccessRule oa3 ? oa3.ObjectFlags : rule is ObjectAuditRule ou3 ? ou3.ObjectFlags : ObjectAceFlags.None);
    }
    private sealed class NativeInteropAccess(M.IdentityReference id, A.InteropRuleValue v)
        : AccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.AccessType) { internal int Mask => AccessMask; }
    private sealed class NativeInteropAudit(M.IdentityReference id, A.InteropRuleValue v)
        : AuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.Audit) { internal int Mask => AccessMask; }
    private sealed class NativeInteropObjectAccess(M.IdentityReference id, A.InteropRuleValue v)
        : ObjectAccessRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.AccessType) { internal int Mask => AccessMask; }
    private sealed class NativeInteropObjectAudit(M.IdentityReference id, A.InteropRuleValue v)
        : ObjectAuditRule(id, v.Mask, v.IsInherited, v.Inheritance, v.Propagation, v.ObjectType, v.InheritedObjectType, v.Audit) { internal int Mask => AccessMask; }
}
