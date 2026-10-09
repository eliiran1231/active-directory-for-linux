#pragma warning disable CA1416
using System.ComponentModel;
using System.Reflection;
using System.Security.AccessControl;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using D = AdForLinux.DirectoryServices;
using N = System.DirectoryServices;
using P = AdForLinux.Security.Principal;
using M = System.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static readonly Type[] CurrentAdRuleTypes = { typeof(D.ActiveDirectoryAccessRule), typeof(D.ActiveDirectoryAuditRule),
        typeof(D.ListChildrenAccessRule), typeof(D.CreateChildAccessRule), typeof(D.DeleteChildAccessRule), typeof(D.PropertyAccessRule),
        typeof(D.PropertySetAccessRule), typeof(D.ExtendedRightAccessRule), typeof(D.DeleteTreeAccessRule) };
    private static readonly Type[] NativeAdRuleTypes = { typeof(N.ActiveDirectoryAccessRule), typeof(N.ActiveDirectoryAuditRule),
        typeof(N.ListChildrenAccessRule), typeof(N.CreateChildAccessRule), typeof(N.DeleteChildAccessRule), typeof(N.PropertyAccessRule),
        typeof(N.PropertySetAccessRule), typeof(N.ExtendedRightAccessRule), typeof(N.DeleteTreeAccessRule) };
    private static string AdConstructorKey(ConstructorInfo constructor)
        => string.Join(",", constructor.GetParameters().Select(p => p.ParameterType.Name));
    private static ConstructorInfo[] AdConstructors(Type type) => type.GetConstructors().OrderBy(AdConstructorKey, StringComparer.Ordinal).ToArray();

    public static IEnumerable<object[]> AdRuleConstructorMatrix()
    {
        for (var kind = 0; kind < CurrentAdRuleTypes.Length; kind++)
            for (var constructor = 0; constructor < AdConstructors(CurrentAdRuleTypes[kind]).Length; constructor++)
                for (var variant = 0; variant < 10; variant++) yield return new object[] { kind, constructor, variant };
    }

    [Fact]
    public void InteropAdRules_MatrixCoversAllNineTypesAndFortyFiveConstructors()
    {
        Assert.Equal(45, CurrentAdRuleTypes.Sum(type => type.GetConstructors().Length));
        Assert.Equal(450, AdRuleConstructorMatrix().Count());
        for (var i = 0; i < CurrentAdRuleTypes.Length; i++)
            Assert.Equal(AdConstructors(CurrentAdRuleTypes[i]).Select(AdConstructorKey), AdConstructors(NativeAdRuleTypes[i]).Select(AdConstructorKey));
    }

    [Theory]
    [MemberData(nameof(AdRuleConstructorMatrix))]
    public void InteropAdRules_AllConstructorsRoundTripExactSubtypeAndFields(int kind, int constructor, int variant)
    {
        var ctor = AdConstructors(CurrentAdRuleTypes[kind])[constructor];
        var expected = ExpectedAdRule(kind, ctor, variant);
        A.InteropAdRuleCodec.Validate(expected);
        if (!OperatingSystem.IsWindows())
        {
            var detached = A.InteropAdRuleCodec.Export(expected, value => value with { }, value => value);
            Assert.True(expected.Same(detached));
            Assert.Throws<PlatformNotSupportedException>(() => A.InteropAdRuleCodec.CreateCurrentRule(expected));
            return;
        }
        var nativeCtor = AdConstructors(NativeAdRuleTypes[kind])[constructor];
        var current = (AuthorizationRule)ctor.Invoke(AdArguments(ctor, variant));
        var native = (AuthorizationRule)nativeCtor.Invoke(AdArguments(nativeCtor, variant));
        var fromCurrent = A.InteropAdRuleCodec.CaptureCurrentRule(current);
        var fromNative = A.InteropAdRuleCodec.Import(native, CaptureNativeAdRule);
        Assert.True(expected.Same(fromCurrent));
        Assert.True(expected.Same(fromNative));
        var exported = A.InteropAdRuleCodec.Export(fromCurrent, CreateNativeAdRule, CaptureNativeAdRule);
        Assert.Equal(native.GetType(), exported.GetType());
        Assert.NotSame(native, exported);
        var back = A.InteropAdRuleCodec.CreateCurrentRule(A.InteropAdRuleCodec.Import(exported, CaptureNativeAdRule));
        Assert.Equal(current.GetType(), back.GetType());
        Assert.True(fromCurrent.Same(A.InteropAdRuleCodec.CaptureCurrentRule(back)));
    }

    private static int AdMask(int kind, int variant) => kind switch
    {
        0 or 1 => variant == 8 ? 0x10000 : variant % 2 == 0 ? 16 : -1,
        2 => 4, 3 => 1, 4 => 2, 5 or 6 => variant % 2 == 0 ? 16 : 32, 7 => 256, 8 => 64,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
    private static A.InteropAdRuleValue ExpectedAdRule(int kind, ConstructorInfo ctor, int variant, string? invalid = null)
    {
        var parameters = ctor.GetParameters();
        var inheritance = parameters.Any(p => p.ParameterType.Name == nameof(D.ActiveDirectorySecurityInheritance))
            ? (D.ActiveDirectorySecurityInheritance)(variant % 5) : D.ActiveDirectorySecurityInheritance.None;
        if (invalid == nameof(D.ActiveDirectorySecurityInheritance)) inheritance = (D.ActiveDirectorySecurityInheritance)99;
        if (invalid == "NegativeInheritance") inheritance = (D.ActiveDirectorySecurityInheritance)(-1);
        var inf = D.ActiveDirectoryInheritance.GetInheritanceFlags(inheritance);
        var prop = D.ActiveDirectoryInheritance.GetPropagationFlags(inheritance);
        if (invalid == nameof(D.PropertyAccess)) throw new InvalidEnumArgumentException("access", 99, typeof(D.PropertyAccess));
        var mask = invalid == nameof(D.ActiveDirectoryRights) ? 0 : AdMask(kind, variant);
        var obj = parameters.Any(p => p.ParameterType == typeof(Guid) && !p.Name!.Contains("inherited", StringComparison.OrdinalIgnoreCase))
            && variant % 3 != 0 ? G1 : Guid.Empty;
        var child = parameters.Any(p => p.ParameterType == typeof(Guid) && p.Name!.Contains("inherited", StringComparison.OrdinalIgnoreCase))
            && variant % 4 != 0 ? G2 : Guid.Empty;
        var scope = A.ObjectRuleScope.Create(mask, inf, obj, child);
        var id = variant % 2 == 0 ? new A.InteropIdentityValue(U1) : new A.InteropIdentityValue("EXAMPLE\\Alice");
        var fields = new A.InteropRuleValue(invalid == nameof(M.IdentityReference) ? null! : id, mask, false, inf, prop, kind == 1, true,
            invalid == nameof(AccessControlType) ? (AccessControlType)99 : kind == 1 ? AccessControlType.Allow : (AccessControlType)(variant % 2),
            kind != 1 ? AuditFlags.None : invalid == nameof(AuditFlags) ? AuditFlags.None : invalid == "UnknownAuditFlags" ? (AuditFlags)4 : (AuditFlags)(1 + variant % 3),
            scope.Object, scope.InheritedObject, scope.Flags);
        return new((A.InteropAdRuleKind)kind, fields, inheritance);
    }

    private static object?[] AdArguments(ConstructorInfo ctor, int variant, string? invalid = null)
        => ctor.GetParameters().Select(p =>
        {
            var name = p.ParameterType.Name;
            if (name == nameof(M.IdentityReference))
                return invalid == name ? null : variant % 2 == 0 ? (object)new M.SecurityIdentifier(U1, 0) : new M.NTAccount("EXAMPLE\\Alice");
            if (p.ParameterType == typeof(Guid)) return (object)(p.Name!.Contains("inherited", StringComparison.OrdinalIgnoreCase)
                ? variant % 4 == 0 ? Guid.Empty : G2 : variant % 3 == 0 ? Guid.Empty : G1);
            var value = name switch
            {
                nameof(D.ActiveDirectoryRights) => invalid == name ? 0 : AdMask(0, variant),
                nameof(D.ActiveDirectorySecurityInheritance) => invalid == name ? 99 : invalid == "NegativeInheritance" ? -1 : variant % 5,
                nameof(D.PropertyAccess) or nameof(AccessControlType) => invalid == name ? 99 : variant % 2,
                nameof(AuditFlags) => invalid == name ? 0 : invalid == "UnknownAuditFlags" ? 4 : 1 + variant % 3,
                _ => throw new NotSupportedException(name)
            };
            return Enum.ToObject(p.ParameterType, value);
        }).ToArray();

    public static IEnumerable<object[]> AdRuleExceptionMatrix()
    {
        for (var kind = 0; kind < CurrentAdRuleTypes.Length; kind++)
            for (var constructor = 0; constructor < AdConstructors(CurrentAdRuleTypes[kind]).Length; constructor++)
                foreach (var parameter in AdConstructors(CurrentAdRuleTypes[kind])[constructor].GetParameters().Where(p => p.ParameterType != typeof(Guid)))
                {
                    yield return new object[] { kind, constructor, parameter.ParameterType.Name };
                    if (parameter.ParameterType.Name == nameof(AuditFlags)) yield return new object[] { kind, constructor, "UnknownAuditFlags" };
                    if (parameter.ParameterType.Name == nameof(D.ActiveDirectorySecurityInheritance)) yield return new object[] { kind, constructor, "NegativeInheritance" };
                }
    }

    [Theory]
    [MemberData(nameof(AdRuleExceptionMatrix))]
    public void InteropAdRules_InvalidConstructorInputsAndExceptions(int kind, int constructor, string invalid)
    {
        var ctor = AdConstructors(CurrentAdRuleTypes[kind])[constructor];
        var error = Record.Exception(() => A.InteropAdRuleCodec.Validate(ExpectedAdRule(kind, ctor, 1, invalid)));
        Assert.True(error is ArgumentException or NotSupportedException);
        if (!OperatingSystem.IsWindows()) return; // No native exception claim on Linux.
        var nativeCtor = AdConstructors(NativeAdRuleTypes[kind])[constructor];
        var current = Assert.Throws<TargetInvocationException>(() => ctor.Invoke(AdArguments(ctor, 1, invalid))).InnerException!;
        var native = Assert.Throws<TargetInvocationException>(() => nativeCtor.Invoke(AdArguments(nativeCtor, 1, invalid))).InnerException!;
        Assert.Equal(native.GetType(), current.GetType());
        Assert.Equal((native as ArgumentException)?.ParamName, (current as ArgumentException)?.ParamName);
    }

    private static A.InteropAdRuleValue CaptureNativeAdRule(AuthorizationRule source)
    {
        var index = Array.IndexOf(NativeAdRuleTypes, source.GetType());
        if (index < 0) throw new NotSupportedException("Unknown Microsoft AD rule subclass.");
        var access = source as N.ActiveDirectoryAccessRule; var audit = source as N.ActiveDirectoryAuditRule;
        var fields = new A.InteropRuleValue(A.InteropValueCodec.CaptureIdentity(A.InteropValueCodec.FromMicrosoftIdentity(source.IdentityReference)),
            (int)(access?.ActiveDirectoryRights ?? audit!.ActiveDirectoryRights), source.IsInherited, source.InheritanceFlags, source.PropagationFlags,
            audit is not null, true, access?.AccessControlType ?? AccessControlType.Allow, audit?.AuditFlags ?? AuditFlags.None,
            access?.ObjectType ?? audit!.ObjectType, access?.InheritedObjectType ?? audit!.InheritedObjectType,
            access?.ObjectFlags ?? audit!.ObjectFlags);
        return new((A.InteropAdRuleKind)index, fields, (D.ActiveDirectorySecurityInheritance)(access?.InheritanceType ?? audit!.InheritanceType));
    }

    private static AuthorizationRule CreateNativeAdRule(A.InteropAdRuleValue value)
    {
        var f = value.Fields; var id = A.InteropValueCodec.ToMicrosoftIdentity(f.Identity.ToPortable());
        var inheritance = (N.ActiveDirectorySecurityInheritance)value.InheritanceType;
        var property = f.Mask == 16 ? N.PropertyAccess.Read : N.PropertyAccess.Write;
        return value.Kind switch
        {
            A.InteropAdRuleKind.Access => new N.ActiveDirectorySecurity().AccessRuleFactory(id, f.Mask, f.IsInherited,
                f.Inheritance, f.Propagation, f.AccessType, f.ObjectType, f.InheritedObjectType),
            A.InteropAdRuleKind.Audit => new N.ActiveDirectorySecurity().AuditRuleFactory(id, f.Mask, f.IsInherited,
                f.Inheritance, f.Propagation, f.Audit, f.ObjectType, f.InheritedObjectType),
            A.InteropAdRuleKind.ListChildren => new N.ListChildrenAccessRule(id, f.AccessType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.CreateChild => new N.CreateChildAccessRule(id, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.DeleteChild => new N.DeleteChildAccessRule(id, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.Property => new N.PropertyAccessRule(id, f.AccessType, property, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.PropertySet => new N.PropertySetAccessRule(id, f.AccessType, property, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.ExtendedRight => new N.ExtendedRightAccessRule(id, f.AccessType, f.ObjectType, inheritance, f.InheritedObjectType),
            A.InteropAdRuleKind.DeleteTree => new N.DeleteTreeAccessRule(id, f.AccessType, inheritance, f.InheritedObjectType),
            _ => throw new NotSupportedException()
        };
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAdRules_InheritedOrdinaryRulesUseFactories(bool audit)
    {
        var kind = audit ? 1 : 0;
        var value = ExpectedAdRule(kind, AdConstructors(CurrentAdRuleTypes[kind]).Last(), 4);
        value = value with { Fields = value.Fields with { IsInherited = true } };
        A.InteropAdRuleCodec.Validate(value);
        if (!OperatingSystem.IsWindows()) return;
        var native = A.InteropAdRuleCodec.Export(value, CreateNativeAdRule, CaptureNativeAdRule);
        Assert.True(native.IsInherited);
        var current = A.InteropAdRuleCodec.CreateCurrentRule(CaptureNativeAdRule(native));
        Assert.True(value.Same(A.InteropAdRuleCodec.CaptureCurrentRule(current)));
    }

    [Theory]
    [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)] [InlineData(8)]
    public void InteropAdRules_SpecializedLossRefusesBeforeFactory(int kind)
    {
        var value = ExpectedAdRule(kind, AdConstructors(CurrentAdRuleTypes[kind]).Last(), 4);
        var called = false;
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Export(value with { Fields = value.Fields with { IsInherited = true } },
            v => { called = true; return v; }, v => v));
        Assert.False(called);
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Export(value, v => v with { Kind = A.InteropAdRuleKind.Access }, v => v));
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Validate(value with { Fields = value.Fields with { Mask = 12345 } }));
    }

    [Fact]
    public void InteropAdRules_UnknownSubclassAndMutationGateRefuse()
    {
        var value = ExpectedAdRule(0, AdConstructors(CurrentAdRuleTypes[0])[0], 1);
        lock (A.FacadeMutation.Gate)
            Assert.Throws<InvalidOperationException>(() => A.InteropAdRuleCodec.Export(value, v => v, v => v));
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Validate(value with { Kind = (A.InteropAdRuleKind)99 }));
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.CaptureCurrentRule(new UnknownCurrentAdRule(new M.SecurityIdentifier(U1, 0))));
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Import(new UnknownNativeAdRule(new M.SecurityIdentifier(U1, 0)), CaptureNativeAdRule));
    }
    private sealed class UnknownCurrentAdRule(M.IdentityReference id) : D.ActiveDirectoryAccessRule(id, D.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
    private sealed class UnknownNativeAdRule(M.IdentityReference id) : N.ActiveDirectoryAccessRule(id, N.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);

    public static IEnumerable<object[]> AdRuleFactoryMatrix()
    {
        foreach (var audit in new[] { false, true })
            for (var inheritance = 0; inheritance < 4; inheritance++)
                for (var propagation = 0; propagation < 4; propagation++)
                    foreach (var inherited in new[] { false, true })
                        yield return new object[] { audit, inheritance, propagation, inherited };
    }

    [Theory]
    [MemberData(nameof(AdRuleFactoryMatrix))]
    public void InteropAdRules_FactoryFlagCombinationsRoundTrip(bool audit, int inheritance, int propagation, bool inherited)
    {
        var inf = (InheritanceFlags)inheritance;
        var prop = inheritance == 0 ? PropagationFlags.None : (PropagationFlags)propagation;
        var scope = A.ObjectRuleScope.Create(16, inf, G1, G2);
        var fields = new A.InteropRuleValue(new A.InteropIdentityValue(U1), 16, inherited, inf, prop, audit, true,
            AccessControlType.Allow, audit ? AuditFlags.Success | AuditFlags.Failure : AuditFlags.None,
            scope.Object, scope.InheritedObject, scope.Flags);
        var value = new A.InteropAdRuleValue(audit ? A.InteropAdRuleKind.Audit : A.InteropAdRuleKind.Access,
            fields, D.ActiveDirectoryInheritance.FromFlags(inf, prop));
        A.InteropAdRuleCodec.Validate(value);
        if (!OperatingSystem.IsWindows()) return;
        var native = A.InteropAdRuleCodec.Export(value, CreateNativeAdRule, CaptureNativeAdRule);
        var current = A.InteropAdRuleCodec.CreateCurrentRule(CaptureNativeAdRule(native));
        Assert.True(value.Same(A.InteropAdRuleCodec.CaptureCurrentRule(current)));
    }

    [Fact]
    public void InteropAdRules_ConversionDoesNotCarryAuthorityOrChangeDescriptorFreshness()
    {
        using var fixture = new IdentityFixture();
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        fixture.Resolver.Bind(wrapper);
        var exported = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var state = wrapper.Descriptor.MutationState;
        var value = ExpectedAdRule(3, AdConstructors(CurrentAdRuleTypes[3]).Last(), 4);
        if (OperatingSystem.IsWindows())
        {
            var native = A.InteropAdRuleCodec.Export(value, CreateNativeAdRule, CaptureNativeAdRule);
            Assert.True(value.Same(A.InteropAdRuleCodec.Import(native, CaptureNativeAdRule)));
        }
        else A.InteropAdRuleCodec.Export(value, v => v, v => v);
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Export(value,
            v => v with { Fields = v.Fields with { Mask = 2 } }, v => v));
        Assert.Same(state, wrapper.Descriptor.MutationState);
        Assert.Equal(D.SecurityMasks.None, wrapper.ReconcileInterop(exported.Provenance, exported.Value));
        wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(exported.Provenance, exported.Value));
        Assert.Equal(0, fixture.Opened);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void InteropAdRules_UnsupportedFieldMetadataRefusesWithoutPublishing(int variant)
    {
        var value = ExpectedAdRule(0, AdConstructors(CurrentAdRuleTypes[0]).Last(), 4);
        value = variant switch
        {
            0 => value with { InheritanceType = (D.ActiveDirectorySecurityInheritance)99 },
            1 => value with { Fields = value.Fields with { ObjectFlags = (ObjectAceFlags)4 } },
            2 => value with { Fields = value.Fields with { ObjectFlags = ObjectAceFlags.ObjectAceTypePresent, ObjectType = Guid.Empty } },
            _ => value with { Fields = value.Fields with { IsAudit = true, Audit = AuditFlags.Success } }
        };
        var called = false;
        Assert.Throws<NotSupportedException>(() => A.InteropAdRuleCodec.Export(value, v => { called = true; return v; }, v => v));
        Assert.False(called);
    }
}
