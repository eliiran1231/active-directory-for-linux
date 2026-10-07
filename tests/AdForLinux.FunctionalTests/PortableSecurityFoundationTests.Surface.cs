using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private const BindingFlags SurfaceDeclared = BindingFlags.Public | BindingFlags.NonPublic |
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // Explicit substitution only: shared framework enums and all other BCL dependencies stay unchanged.
    private static readonly Dictionary<Type, string> SurfaceTypes = new()
    {
        [typeof(P.IdentityReference)] = "System.Security.Principal.IdentityReference",
        [typeof(P.SecurityIdentifier)] = "System.Security.Principal.SecurityIdentifier",
        [typeof(P.NTAccount)] = "System.Security.Principal.NTAccount",
        [typeof(A.AuthorizationRule)] = "System.Security.AccessControl.AuthorizationRule",
        [typeof(A.AccessRule)] = "System.Security.AccessControl.AccessRule",
        [typeof(A.AuditRule)] = "System.Security.AccessControl.AuditRule",
        [typeof(A.ObjectAccessRule)] = "System.Security.AccessControl.ObjectAccessRule",
        [typeof(A.ObjectAuditRule)] = "System.Security.AccessControl.ObjectAuditRule",
        [typeof(A.AuthorizationRuleCollection)] = "System.Security.AccessControl.AuthorizationRuleCollection",
        [typeof(A.GenericAce)] = "System.Security.AccessControl.GenericAce",
        [typeof(A.KnownAce)] = "System.Security.AccessControl.KnownAce",
        [typeof(A.QualifiedAce)] = "System.Security.AccessControl.QualifiedAce",
        [typeof(A.CommonAce)] = "System.Security.AccessControl.CommonAce",
        [typeof(A.ObjectAce)] = "System.Security.AccessControl.ObjectAce",
        [typeof(A.CompoundAce)] = "System.Security.AccessControl.CompoundAce",
        [typeof(A.CustomAce)] = "System.Security.AccessControl.CustomAce",
        [typeof(A.GenericAcl)] = "System.Security.AccessControl.GenericAcl",
        [typeof(A.RawAcl)] = "System.Security.AccessControl.RawAcl",
        [typeof(A.CommonAcl)] = "System.Security.AccessControl.CommonAcl",
        [typeof(A.DiscretionaryAcl)] = "System.Security.AccessControl.DiscretionaryAcl",
        [typeof(A.SystemAcl)] = "System.Security.AccessControl.SystemAcl",
        [typeof(A.AceEnumerator)] = "System.Security.AccessControl.AceEnumerator",
        [typeof(A.GenericSecurityDescriptor)] = "System.Security.AccessControl.GenericSecurityDescriptor",
        [typeof(A.RawSecurityDescriptor)] = "System.Security.AccessControl.RawSecurityDescriptor",
        [typeof(A.CommonSecurityDescriptor)] = "System.Security.AccessControl.CommonSecurityDescriptor"
    };

    // Explicit staging gaps, not a claim of completed SID surface. Delete each entry when implemented.
    private static readonly string[] SurfaceExpectedGaps =
    [
        "Constructor:System.Security.Principal.SecurityIdentifier:.ctor`0(System.IntPtr)"
    ];

    [Theory]
    [InlineData("net8")]
    [InlineData("net10")]
    public void Portable_foundation_surface_matches_complete_recorded_declarations_with_explicit_sid_gaps(string runtime)
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream($"AclOracle.Surface.{runtime}.json");
        Assert.NotNull(stream);
        using var document = JsonDocument.Parse(stream!);
        var root = document.RootElement;
        Assert.Equal("issue-226-required-surface-v1", root.GetProperty("Schema").GetString());
        var recorded = root.GetProperty("Types").EnumerateArray().ToDictionary(t => t.GetProperty("Type").GetString()!);
        Assert.Equal(25, SurfaceTypes.Count);
        var foundGaps = new List<string>();
        foreach (var (portable, referenceName) in SurfaceTypes)
        {
            Assert.True(recorded.TryGetValue(referenceName, out var expected), referenceName);
            Assert.Equal(expected.GetProperty("BaseType").GetString(), portable.BaseType is null ? null : SurfaceName(portable.BaseType));
            foreach (var (property, actual) in new[] { ("IsPublic", portable.IsPublic), ("IsAbstract", portable.IsAbstract), ("IsSealed", portable.IsSealed) })
                Assert.Equal(expected.GetProperty(property).GetBoolean(), actual);
            Assert.Equal(expected.GetProperty("Interfaces").EnumerateArray().Select(x => x.GetString()).Order(StringComparer.Ordinal),
                portable.GetInterfaces().Select(SurfaceName).Order(StringComparer.Ordinal));
            var actualMembers = SurfaceMembers(portable).ToDictionary(SurfaceKey);
            foreach (var member in expected.GetProperty("Members").EnumerateArray())
            {
                var key = member.GetProperty("Key").GetString()!;
                if (!actualMembers.Remove(key, out var actual)) { foundGaps.Add(key); continue; }
                Assert.Equal(SurfaceRecordedShape(member), SurfaceActualShape(actual));
            }
            Assert.True(actualMembers.Count == 0, "Unexpected portable surface: " + string.Join("; ", actualMembers.Keys));
        }
        Assert.Equal(SurfaceExpectedGaps.Order(StringComparer.Ordinal), foundGaps.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("net8")]
    [InlineData("net10")]
    public void Recorded_required_surface_retains_all_families_and_descriptor_facade_contracts(string runtime)
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream($"AclOracle.Surface.{runtime}.json");
        Assert.NotNull(stream);
        using var document = JsonDocument.Parse(stream!);
        var root = document.RootElement;
        var types = root.GetProperty("Types").EnumerateArray().ToDictionary(t => t.GetProperty("Type").GetString()!);
        var expected = new[]
        {
            ("System.DirectoryServices.", "ActiveDirectoryAccessRule ActiveDirectoryAuditRule ActiveDirectoryRights ActiveDirectorySecurity ActiveDirectorySecurityInheritance CreateChildAccessRule DeleteChildAccessRule DeleteTreeAccessRule ExtendedRightAccessRule ListChildrenAccessRule PropertyAccess PropertyAccessRule PropertySetAccessRule"),
            ("System.Security.AccessControl.", "AccessControlModification AccessControlSections AccessControlType AccessRule AceEnumerator AceFlags AceQualifier AceType AuditFlags AuditRule AuthorizationRule AuthorizationRuleCollection CommonAce CommonAcl CommonSecurityDescriptor CompoundAce CompoundAceType ControlFlags CustomAce DirectoryObjectSecurity DiscretionaryAcl GenericAce GenericAcl GenericSecurityDescriptor InheritanceFlags KnownAce ObjectAccessRule ObjectAce ObjectAceFlags ObjectAuditRule ObjectSecurity PropagationFlags QualifiedAce RawAcl RawSecurityDescriptor SystemAcl"),
            ("System.Security.Principal.", "IdentityNotMappedException IdentityReference IdentityReferenceCollection NTAccount SecurityIdentifier WellKnownSidType")
        }.SelectMany(group => group.Item2.Split(' ').Select(name => group.Item1 + name)).Order(StringComparer.Ordinal);
        Assert.Equal(expected, types.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(55, types.Count);
        var roots = root.GetProperty("Roots").EnumerateArray().Select(x => x.GetString()!).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(39, roots.Length);
        Assert.Equal(types.Where(t => t.Value.GetProperty("Kind").GetString() != "enum").Select(t => t.Key).Order(StringComparer.Ordinal), roots);
        Assert.Equal(702, types.Values.Sum(t => t.GetProperty("Members").GetArrayLength()));
        Assert.Equal(28, root.GetProperty("FrameworkBoundary").GetArrayLength());
        Assert.Equal(45, types.Where(t => t.Key.StartsWith("System.DirectoryServices.", StringComparison.Ordinal) && t.Key.EndsWith("Rule", StringComparison.Ordinal))
            .Sum(t => t.Value.GetProperty("Members").EnumerateArray().Count(m => m.GetProperty("Key").GetString()!.StartsWith("Constructor:", StringComparison.Ordinal) && m.GetProperty("Accessibility").GetString() == "public")));

        JsonElement Member(string type, string key) => Assert.Single(types["System.Security.AccessControl." + type].GetProperty("Members").EnumerateArray(), m => m.GetProperty("Key").GetString() == key);
        var descriptor = Member("ObjectSecurity", "Property:System.Security.AccessControl.ObjectSecurity:SecurityDescriptor()");
        Assert.Equal("System.Security.AccessControl.CommonSecurityDescriptor", descriptor.GetProperty("Type").GetString());
        Assert.Equal("protected", descriptor.GetProperty("Get").GetProperty("Accessibility").GetString());
        Assert.False(descriptor.GetProperty("Get").GetProperty("IsVirtual").GetBoolean());
        Assert.Equal(JsonValueKind.Null, descriptor.GetProperty("Set").ValueKind);
        foreach (var section in new[] { "Access", "Audit" })
        {
            var hook = Member("ObjectSecurity", $"Method:System.Security.AccessControl.ObjectSecurity:Modify{section}`0(System.Security.AccessControl.AccessControlModification,System.Security.AccessControl.{section}Rule,System.Boolean&)");
            Assert.Equal("protected", hook.GetProperty("Accessibility").GetString());
            Assert.True(hook.GetProperty("IsAbstract").GetBoolean());
            Assert.Equal("System.Boolean", hook.GetProperty("Return").GetProperty("Type").GetString());
            Assert.True(hook.GetProperty("Parameters")[2].GetProperty("IsOut").GetBoolean());
        }
        foreach (var acl in new[] { "GenericAcl", "RawAcl", "CommonAcl" })
        {
            var index = Member(acl, $"Property:System.Security.AccessControl.{acl}:Item(System.Int32)");
            Assert.Equal("System.Security.AccessControl.GenericAce", index.GetProperty("Type").GetString());
            Assert.Equal("public", index.GetProperty("Get").GetProperty("Accessibility").GetString());
            Assert.Equal("public", index.GetProperty("Set").GetProperty("Accessibility").GetString());
        }
        Member("RawAcl", "Constructor:System.Security.AccessControl.RawAcl:.ctor`0(System.Byte[],System.Int32)");
        Member("RawAcl", "Constructor:System.Security.AccessControl.RawAcl:.ctor`0(System.Byte,System.Int32)");
        Member("RawSecurityDescriptor", "Constructor:System.Security.AccessControl.RawSecurityDescriptor:.ctor`0(System.String)");
        Member("CommonSecurityDescriptor", "Constructor:System.Security.AccessControl.CommonSecurityDescriptor:.ctor`0(System.Boolean,System.Boolean,System.String)");
        Member("CommonSecurityDescriptor", "Constructor:System.Security.AccessControl.CommonSecurityDescriptor:.ctor`0(System.Boolean,System.Boolean,System.Security.AccessControl.RawSecurityDescriptor)");
        Member("GenericSecurityDescriptor", "Method:System.Security.AccessControl.GenericSecurityDescriptor:GetSddlForm`0(System.Security.AccessControl.AccessControlSections)");
    }

    private static bool SurfaceVisible(MethodBase m) => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly || m.IsFamilyAndAssembly;
    private static bool SurfaceVisible(FieldInfo f) => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly || f.IsFamilyAndAssembly;
    private static IEnumerable<MemberInfo> SurfaceMembers(Type t) => t.GetMembers(SurfaceDeclared).Where(m => m switch
    {
        MethodBase b => SurfaceVisible(b), FieldInfo f => SurfaceVisible(f),
        PropertyInfo p => p.GetAccessors(true).Any(SurfaceVisible),
        EventInfo e => new[] { e.AddMethod, e.RemoveMethod, e.RaiseMethod }.Any(a => a is not null && SurfaceVisible(a)),
        Type n => n.IsNestedPublic || n.IsNestedFamily || n.IsNestedFamORAssem || n.IsNestedFamANDAssem, _ => false
    });
    private static string SurfaceName(Type t) => SurfaceTypes.TryGetValue(t, out var mapped) ? mapped :
        t.IsByRef ? SurfaceName(t.GetElementType()!) + "&" : t.IsPointer ? SurfaceName(t.GetElementType()!) + "*" :
        t.IsArray ? SurfaceName(t.GetElementType()!) + "[" + new string(',', t.GetArrayRank() - 1) + "]" :
        t.IsGenericParameter ? (t.DeclaringMethod is null ? "!" : "!!") + t.GenericParameterPosition + ":" + t.Name :
        t.IsGenericType ? t.GetGenericTypeDefinition().FullName + "<" + string.Join(",", t.GetGenericArguments().Select(SurfaceName)) + ">" : t.FullName ?? t.Name;
    private static string SurfaceKey(MemberInfo m) => m.MemberType + ":" + SurfaceName(m.DeclaringType!) + ":" + m.Name +
        (m is MethodBase b ? "`" + (b.IsGenericMethod ? b.GetGenericArguments().Length : 0) + "(" + string.Join(",", b.GetParameters().Select(p => SurfaceName(p.ParameterType))) + ")" :
        m is PropertyInfo p ? "(" + string.Join(",", p.GetIndexParameters().Select(x => SurfaceName(x.ParameterType))) + ")" : "");
    private static string SurfaceAccess(MethodBase m) => m.IsPublic ? "public" : m.IsFamily ? "protected" :
        m.IsFamilyOrAssembly ? "protected internal" : m.IsFamilyAndAssembly ? "private protected" : m.IsAssembly ? "internal" : "private";
    private static string SurfaceAccess(FieldInfo f) => f.IsPublic ? "public" : f.IsFamily ? "protected" :
        f.IsFamilyOrAssembly ? "protected internal" : f.IsFamilyAndAssembly ? "private protected" : f.IsAssembly ? "internal" : "private";

    // Canonical contracts include parameter names (not just CLR overload identity), all callable
    // modifiers, exact accessor visibility and constant values. Compiler attributes/nullability
    // annotations remain in the manifest but are not asserted as binary API contracts here.
    private static string SurfaceActualParameter(ParameterInfo p) => string.Join("|", p.Name, p.Position,
        SurfaceName(p.ParameterType), p.IsIn, p.IsOut, p.IsOptional, p.HasDefaultValue,
        p.HasDefaultValue ? SurfaceConstant(p.RawDefaultValue) : "",
        string.Join(",", p.GetRequiredCustomModifiers().Select(SurfaceName)), string.Join(",", p.GetOptionalCustomModifiers().Select(SurfaceName)));
    private static string SurfaceRecordedParameter(JsonElement p) => string.Join("|", p.GetProperty("Name").GetString(), p.GetProperty("Position").GetInt32(),
        p.GetProperty("Type").GetString(), p.GetProperty("IsIn").GetBoolean(), p.GetProperty("IsOut").GetBoolean(),
        p.GetProperty("IsOptional").GetBoolean(), p.GetProperty("HasDefaultValue").GetBoolean(),
        p.GetProperty("HasDefaultValue").GetBoolean() ? SurfaceRecordedConstant(p.GetProperty("DefaultValue")) : "",
        SurfaceStrings(p.GetProperty("RequiredModifiers")), SurfaceStrings(p.GetProperty("OptionalModifiers")));
    private static string SurfaceConstant(object? value) => value is null ? "null" : value.GetType().FullName + ":" + Convert.ToString(value, CultureInfo.InvariantCulture);
    private static string SurfaceRecordedConstant(JsonElement value) => value.ValueKind == JsonValueKind.Null ? "null" : value.GetProperty("Type").GetString() + ":" + value.GetProperty("Value").GetString();
    private static string SurfaceStrings(JsonElement array) => string.Join(",", array.EnumerateArray().Select(x => x.GetString()));
    private static string SurfaceActualMethod(MethodBase m) => string.Join("|", SurfaceAccess(m), m.IsStatic, m.IsAbstract, m.IsVirtual,
        m.IsFinal, m.IsHideBySig, m.IsSpecialName, (m.Attributes & MethodAttributes.NewSlot) != 0, m.CallingConvention.ToString(),
        m is MethodInfo info ? SurfaceActualParameter(info.ReturnParameter) : "",
        m is MethodInfo method ? SurfaceKey(method.GetBaseDefinition()) : "",
        string.Join(";", m.GetParameters().Select(SurfaceActualParameter)),
        m.IsGenericMethod ? string.Join(";", m.GetGenericArguments().Select(t => string.Join("|", t.Name, t.GenericParameterPosition,
            t.GenericParameterAttributes.ToString(), string.Join(",", t.GetGenericParameterConstraints().Select(SurfaceName))))) : "");
    private static string SurfaceRecordedMethod(JsonElement m) => string.Join("|", m.GetProperty("Accessibility").GetString(),
        m.GetProperty("IsStatic").GetBoolean(), m.GetProperty("IsAbstract").GetBoolean(), m.GetProperty("IsVirtual").GetBoolean(),
        m.GetProperty("IsFinal").GetBoolean(), m.GetProperty("IsHideBySig").GetBoolean(), m.GetProperty("IsSpecialName").GetBoolean(),
        m.GetProperty("NewSlot").GetBoolean(), m.GetProperty("CallingConvention").GetString(),
        m.GetProperty("Return").ValueKind == JsonValueKind.Null ? "" : SurfaceRecordedParameter(m.GetProperty("Return")),
        m.GetProperty("BaseDefinition").GetString() ?? "", string.Join(";", m.GetProperty("Parameters").EnumerateArray().Select(SurfaceRecordedParameter)),
        string.Join(";", m.GetProperty("GenericParameters").EnumerateArray().Select(t => string.Join("|", t.GetProperty("Name").GetString(),
            t.GetProperty("GenericParameterPosition").GetInt32(), t.GetProperty("Attributes").GetString(), SurfaceStrings(t.GetProperty("Constraints"))))));
    private static string SurfaceActualAccessor(MethodInfo? m) => m is not null && SurfaceVisible(m) ? SurfaceActualMethod(m) : "";
    private static string SurfaceRecordedAccessor(JsonElement m) => m.ValueKind != JsonValueKind.Null &&
        m.GetProperty("Accessibility").GetString() is "public" or "protected" or "protected internal" or "private protected" ? SurfaceRecordedMethod(m) : "";
    private static string SurfaceActualShape(MemberInfo m) => SurfaceKey(m) + "\n" + (m switch
    {
        MethodBase b => SurfaceActualMethod(b),
        PropertyInfo p => string.Join("|", SurfaceName(p.PropertyType), string.Join(";", p.GetIndexParameters().Select(SurfaceActualParameter)), SurfaceActualAccessor(p.GetMethod), SurfaceActualAccessor(p.SetMethod)),
        FieldInfo f => string.Join("|", SurfaceName(f.FieldType), SurfaceAccess(f), f.IsStatic, f.IsInitOnly, f.IsLiteral,
            f.IsLiteral ? SurfaceConstant(f.GetRawConstantValue()) : "", string.Join(",", f.GetRequiredCustomModifiers().Select(SurfaceName)), string.Join(",", f.GetOptionalCustomModifiers().Select(SurfaceName))),
        EventInfo e => string.Join("|", SurfaceName(e.EventHandlerType!), SurfaceActualAccessor(e.AddMethod), SurfaceActualAccessor(e.RemoveMethod), SurfaceActualAccessor(e.RaiseMethod)),
        Type t => SurfaceName(t), _ => throw new InvalidOperationException()
    });
    private static string SurfaceRecordedShape(JsonElement m)
    {
        var key = m.GetProperty("Key").GetString()!;
        var shape = key.Split(':')[0] switch
        {
            "Method" or "Constructor" => SurfaceRecordedMethod(m),
            "Property" => string.Join("|", m.GetProperty("Type").GetString(), string.Join(";", m.GetProperty("IndexParameters").EnumerateArray().Select(SurfaceRecordedParameter)), SurfaceRecordedAccessor(m.GetProperty("Get")), SurfaceRecordedAccessor(m.GetProperty("Set"))),
            "Field" => string.Join("|", m.GetProperty("Type").GetString(), m.GetProperty("Accessibility").GetString(), m.GetProperty("IsStatic").GetBoolean(),
                m.GetProperty("IsInitOnly").GetBoolean(), m.GetProperty("IsLiteral").GetBoolean(), m.GetProperty("IsLiteral").GetBoolean() ? SurfaceRecordedConstant(m.GetProperty("Constant")) : "",
                SurfaceStrings(m.GetProperty("RequiredModifiers")), SurfaceStrings(m.GetProperty("OptionalModifiers"))),
            "Event" => string.Join("|", m.GetProperty("Type").GetString(), SurfaceRecordedAccessor(m.GetProperty("Add")), SurfaceRecordedAccessor(m.GetProperty("Remove")), SurfaceRecordedAccessor(m.GetProperty("Raise"))),
            "NestedType" => m.GetProperty("Type").GetString()!, _ => throw new InvalidOperationException("Unrecognized recorded member " + key)
        };
        return key + "\n" + shape;
    }
}
