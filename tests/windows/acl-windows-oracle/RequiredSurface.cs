// Metadata only: never constructs a descriptor/identity, invokes members, or accesses a directory.
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using P = System.Security.Principal;

internal static class RequiredSurface
{
    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic |
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // Derived public types cannot be discovered by following a base-typed signature.
    private static readonly Type[] Roots =
    [
        typeof(M.ActiveDirectorySecurity), typeof(M.ActiveDirectoryAccessRule), typeof(M.ActiveDirectoryAuditRule),
        typeof(M.CreateChildAccessRule), typeof(M.DeleteChildAccessRule), typeof(M.DeleteTreeAccessRule),
        typeof(M.ExtendedRightAccessRule), typeof(M.ListChildrenAccessRule), typeof(M.PropertyAccessRule),
        typeof(M.PropertySetAccessRule),
        typeof(P.IdentityReference), typeof(P.SecurityIdentifier), typeof(P.NTAccount),
        typeof(P.IdentityReferenceCollection), typeof(P.IdentityNotMappedException),
        typeof(E.AuthorizationRule), typeof(E.AccessRule), typeof(E.AuditRule), typeof(E.ObjectAccessRule),
        typeof(E.ObjectAuditRule), typeof(E.AuthorizationRuleCollection), typeof(E.ObjectSecurity),
        typeof(E.DirectoryObjectSecurity), typeof(E.GenericSecurityDescriptor), typeof(E.RawSecurityDescriptor),
        typeof(E.CommonSecurityDescriptor), typeof(E.GenericAcl), typeof(E.RawAcl), typeof(E.CommonAcl),
        typeof(E.DiscretionaryAcl), typeof(E.SystemAcl), typeof(E.AceEnumerator), typeof(E.GenericAce),
        typeof(E.KnownAce), typeof(E.QualifiedAce), typeof(E.CommonAce), typeof(E.ObjectAce),
        typeof(E.CompoundAce), typeof(E.CustomAce)
    ];

    internal static void Write(string path)
    {
        var pending = new Queue<Type>(Roots);
        var expanded = new HashSet<Type>();
        var terminal = new HashSet<Type>();
        while (pending.TryDequeue(out var type))
        {
            if (type.HasElementType) { pending.Enqueue(type.GetElementType()!); continue; }
            if (type.IsGenericParameter) { foreach (var c in type.GetGenericParameterConstraints()) pending.Enqueue(c); continue; }
            if (type.IsGenericType)
                foreach (var a in type.GetGenericArguments()) pending.Enqueue(a);
            if (!IsSecurityType(type)) { terminal.Add(type); continue; }
            if (!expanded.Add(type)) continue;
            foreach (var dependency in Dependencies(type)) pending.Enqueue(dependency);
        }

        // Fail closed if roots or a signature dependency disappeared from the manifest.
        if (Roots.Any(t => !expanded.Contains(t))) throw new InvalidOperationException("Missing required surface root.");
        foreach (var t in expanded)
            foreach (var d in Dependencies(t).SelectMany(Flatten))
                if (!d.IsGenericParameter && !expanded.Contains(d) && !terminal.Contains(d))
                    throw new InvalidOperationException($"Unresolved dependency: {Name(t)} -> {Name(d)}");

        var manifest = new
        {
            Schema = "issue-226-required-surface-v1",
            Framework = RuntimeInformation.FrameworkDescription,
            RuntimeIdentifier = RuntimeInformation.RuntimeIdentifier,
            OperatingSystem = RuntimeInformation.OSDescription,
            AssemblyProvenance = expanded.Select(t => t.Assembly).Distinct().OrderBy(a => a.FullName, StringComparer.Ordinal)
                .Select(a => new { Identity = a.FullName, ModuleVersionId = a.ManifestModule.ModuleVersionId,
                    InformationalVersion = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion }).ToArray(),
            Roots = Roots.Select(Name).Order(StringComparer.Ordinal).ToArray(),
            Types = expanded.OrderBy(Name, StringComparer.Ordinal).Select(TypeRecord).ToArray(),
            FrameworkBoundary = terminal.OrderBy(Name, StringComparer.Ordinal).Select(t => new
            { Type = Name(t), Assembly = t.Assembly.GetName().Name, Reason = "Retained framework dependency; not a portable security replacement." }).ToArray()
        };
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }) + "\n");
    }

    private static bool IsSecurityType(Type t) => Roots.Contains(t) ||
        t.Namespace is "System.Security.AccessControl" or "System.Security.Principal" ||
        (t.Namespace == "System.DirectoryServices" && t.IsEnum);

    private static string Name(Type t) => t.IsByRef ? Name(t.GetElementType()!) + "&" :
        t.IsPointer ? Name(t.GetElementType()!) + "*" :
        t.IsArray ? Name(t.GetElementType()!) + "[" + new string(',', t.GetArrayRank() - 1) + "]" :
        t.IsGenericParameter ? (t.DeclaringMethod is null ? "!" : "!!") + t.GenericParameterPosition + ":" + t.Name :
        t.IsGenericType ? t.GetGenericTypeDefinition().FullName + "<" + string.Join(",", t.GetGenericArguments().Select(Name)) + ">" :
        t.FullName ?? t.Name;

    private static bool Visible(MethodBase m) => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly || m.IsFamilyAndAssembly;
    private static bool Visible(FieldInfo f) => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly || f.IsFamilyAndAssembly;
    private static bool Visible(Type t) => t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem || t.IsNestedFamANDAssem;
    private static IEnumerable<MemberInfo> Members(Type t) => t.GetMembers(Declared).Where(m => m switch
    {
        MethodBase x => Visible(x), FieldInfo x => Visible(x),
        PropertyInfo x => x.GetAccessors(true).Any(Visible),
        EventInfo x => new[] { x.AddMethod, x.RemoveMethod, x.RaiseMethod }.Any(a => a is not null && Visible(a)),
        Type x => Visible(x), _ => false
    });

    private static IEnumerable<Type> Flatten(Type t)
    {
        if (t.HasElementType) { foreach (var d in Flatten(t.GetElementType()!)) yield return d; yield break; }
        yield return t;
        if (t.IsGenericType) foreach (var a in t.GetGenericArguments()) foreach (var d in Flatten(a)) yield return d;
        if (t.IsGenericParameter) foreach (var c in t.GetGenericParameterConstraints()) foreach (var d in Flatten(c)) yield return d;
    }

    private static IEnumerable<Type> ParameterDependencies(ParameterInfo p) =>
        new[] { p.ParameterType }.Concat(p.GetRequiredCustomModifiers()).Concat(p.GetOptionalCustomModifiers());

    private static IEnumerable<Type> Dependencies(Type t)
    {
        if (t.BaseType is not null) yield return t.BaseType;
        foreach (var i in t.GetInterfaces()) yield return i;
        foreach (var m in Members(t))
        {
            if (m is MethodBase method)
            {
                foreach (var p in method.GetParameters()) foreach (var d in ParameterDependencies(p)) yield return d;
                if (method is MethodInfo mi)
                {
                    foreach (var d in ParameterDependencies(mi.ReturnParameter)) yield return d;
                    foreach (var a in mi.GetGenericArguments()) yield return a;
                }
            }
            else if (m is PropertyInfo p)
            {
                yield return p.PropertyType;
                foreach (var index in p.GetIndexParameters()) foreach (var d in ParameterDependencies(index)) yield return d;
            }
            else if (m is FieldInfo f)
            {
                yield return f.FieldType;
                foreach (var d in f.GetRequiredCustomModifiers()) yield return d;
                foreach (var d in f.GetOptionalCustomModifiers()) yield return d;
            }
            else if (m is EventInfo e && e.EventHandlerType is not null) yield return e.EventHandlerType;
            else if (m is Type nested) yield return nested;
        }
    }

    private static string Access(MethodBase m) => m.IsPublic ? "public" : m.IsFamily ? "protected" :
        m.IsFamilyOrAssembly ? "protected internal" : m.IsFamilyAndAssembly ? "private protected" : m.IsAssembly ? "internal" : "private";
    private static string Access(FieldInfo f) => f.IsPublic ? "public" : f.IsFamily ? "protected" :
        f.IsFamilyOrAssembly ? "protected internal" : f.IsFamilyAndAssembly ? "private protected" : f.IsAssembly ? "internal" : "private";
    private static string Key(MemberInfo m) => m.MemberType + ":" + Name(m.DeclaringType!) + ":" + m.Name +
        (m is MethodBase b ? "`" + (b.IsGenericMethod ? b.GetGenericArguments().Length : 0) + "(" + string.Join(",", b.GetParameters().Select(p => Name(p.ParameterType))) + ")" :
         m is PropertyInfo p ? "(" + string.Join(",", p.GetIndexParameters().Select(x => Name(x.ParameterType))) + ")" : "");

    private static object Parameter(ParameterInfo p) => new
    {
        p.Name, p.Position, Type = Name(p.ParameterType), p.IsIn, p.IsOut, p.IsOptional, p.HasDefaultValue,
        DefaultValue = p.HasDefaultValue ? Constant(p.RawDefaultValue) : null,
        RequiredModifiers = p.GetRequiredCustomModifiers().Select(Name).ToArray(),
        OptionalModifiers = p.GetOptionalCustomModifiers().Select(Name).ToArray(),
        Attributes = Attributes(p.GetCustomAttributesData())
    };
    private static object? Constant(object? value) => value is null ? null : new
    { Type = value.GetType().FullName, Value = Convert.ToString(value, CultureInfo.InvariantCulture) };
    private static object[] Attributes(IList<CustomAttributeData> attributes) => attributes
        .OrderBy(a => a.AttributeType.FullName, StringComparer.Ordinal).Select(a => (object)new
        { Type = Name(a.AttributeType), ConstructorArguments = a.ConstructorArguments.Select(AttributeValue).ToArray(),
            NamedArguments = a.NamedArguments.Select(n => new { n.MemberName, n.IsField, Value = AttributeValue(n.TypedValue) }).ToArray() }).ToArray();
    private static object AttributeValue(CustomAttributeTypedArgument a) => new
    { Type = Name(a.ArgumentType), Value = a.Value is IReadOnlyCollection<CustomAttributeTypedArgument> values
        ? (object)values.Select(AttributeValue).ToArray() : a.Value is Type t ? Name(t) : Constant(a.Value) };

    private static object Method(MethodBase m) => new
    {
        Key = Key(m), m.Name, DeclaringType = Name(m.DeclaringType!), Accessibility = Access(m),
        m.IsStatic, m.IsAbstract, m.IsVirtual, m.IsFinal, m.IsHideBySig, m.IsSpecialName,
        NewSlot = (m.Attributes & MethodAttributes.NewSlot) != 0, CallingConvention = m.CallingConvention.ToString(),
        Return = m is MethodInfo mi ? Parameter(mi.ReturnParameter) : null,
        BaseDefinition = m is MethodInfo method ? Key(method.GetBaseDefinition()) : null,
        Parameters = m.GetParameters().Select(Parameter).ToArray(),
        GenericParameters = m.IsGenericMethod ? m.GetGenericArguments().Select(GenericParameter).ToArray() : [],
        Attributes = Attributes(m.GetCustomAttributesData())
    };
    private static object GenericParameter(Type t) => new
    { t.Name, t.GenericParameterPosition, Attributes = t.GenericParameterAttributes.ToString(), Constraints = t.GetGenericParameterConstraints().Select(Name).ToArray() };

    private static object Member(MemberInfo m) => m switch
    {
        MethodBase b => Method(b),
        PropertyInfo p => new { Key = Key(p), p.Name, Type = Name(p.PropertyType),
            IndexParameters = p.GetIndexParameters().Select(Parameter).ToArray(),
            Get = p.GetMethod is { } g ? Method(g) : null, Set = p.SetMethod is { } s ? Method(s) : null,
            Attributes = Attributes(p.GetCustomAttributesData()) },
        FieldInfo f => new { Key = Key(f), f.Name, Type = Name(f.FieldType), Accessibility = Access(f),
            f.IsStatic, f.IsInitOnly, f.IsLiteral, Constant = f.IsLiteral ? Constant(f.GetRawConstantValue()) : null,
            RequiredModifiers = f.GetRequiredCustomModifiers().Select(Name).ToArray(),
            OptionalModifiers = f.GetOptionalCustomModifiers().Select(Name).ToArray(), Attributes = Attributes(f.GetCustomAttributesData()) },
        EventInfo e => new { Key = Key(e), e.Name, Type = e.EventHandlerType is { } h ? Name(h) : null,
            Add = e.AddMethod is { } a ? Method(a) : null, Remove = e.RemoveMethod is { } r ? Method(r) : null,
            Raise = e.RaiseMethod is { } x ? Method(x) : null, Attributes = Attributes(e.GetCustomAttributesData()) },
        Type t => new { Key = Key(t), Type = Name(t) },
        _ => throw new InvalidOperationException("Unsupported reflected member.")
    };

    private static object TypeRecord(Type t)
    {
        var inherited = new List<string>();
        for (var b = t.BaseType; b is not null; b = b.BaseType)
            inherited.AddRange(Members(b).Where(m => m is not ConstructorInfo && m is not Type).Select(Key));
        return new
        {
            Type = Name(t), Assembly = t.Assembly.GetName().Name,
            Kind = t.IsEnum ? "enum" : t.IsInterface ? "interface" : t.IsValueType ? "struct" : "class",
            t.IsPublic, t.IsAbstract, t.IsSealed, BaseType = t.BaseType is { } parent ? Name(parent) : null,
            Interfaces = t.GetInterfaces().Select(Name).Order(StringComparer.Ordinal).ToArray(),
            EnumUnderlyingType = t.IsEnum ? Name(Enum.GetUnderlyingType(t)) : null,
            GenericParameters = t.IsGenericTypeDefinition ? t.GetGenericArguments().Select(GenericParameter).ToArray() : [],
            Members = Members(t).OrderBy(Key, StringComparer.Ordinal).Select(Member).ToArray(),
            // Includes shadowed base declarations; the base graph and override metadata resolve dispatch.
            InheritedDeclarations = inherited.Order(StringComparer.Ordinal).ToArray(),
            NonSurfaceConstructors = t.GetConstructors(Declared).Where(c => !Visible(c)).OrderBy(Key, StringComparer.Ordinal).Select(Method).ToArray(),
            Attributes = Attributes(t.GetCustomAttributesData())
        };
    }
}
