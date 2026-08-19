using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Exhaustively compares the public, extensible surface that AdForLinux claims
/// to mirror. Keep additions to <see cref="IntentionalDifferences"/> narrow: an
/// allowlisted descriptor is an exact contract entry, not a wildcard.
/// </summary>
public class PublicApiSurfaceComparisonTests
{
    [Fact]
    public void DirectoryServices_surface_matches_microsoft() => AssertSurface(
        typeof(System.DirectoryServices.DirectoryEntry).Assembly,
        "System.DirectoryServices",
        typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly,
        "AdForLinux.DirectoryServices");

    [Fact]
    public void AccountManagement_surface_matches_microsoft() => AssertSurface(
        typeof(System.DirectoryServices.AccountManagement.Principal).Assembly,
        "System.DirectoryServices.AccountManagement",
        typeof(AdForLinux.DirectoryServices.AccountManagement.Principal).Assembly,
        "AdForLinux.DirectoryServices.AccountManagement");

    private static void AssertSurface(
        Assembly microsoftAssembly,
        string microsoftNamespace,
        Assembly oursAssembly,
        string oursNamespace)
    {
        var microsoft = ExportedTypes(microsoftAssembly, microsoftNamespace);
        var ours = ExportedTypes(oursAssembly, oursNamespace);
        var differences = new List<string>();
        var encounteredAllowlistEntries = new HashSet<SurfaceDifference>();

        foreach (var typeName in microsoft.Keys.Union(ours.Keys).Order(StringComparer.Ordinal))
        {
            if (!microsoft.TryGetValue(typeName, out var microsoftType))
            {
                AddDifference(differences, encounteredAllowlistEntries, DifferenceSide.AdForLinux, typeName, "type", "exported type");
                continue;
            }

            if (!ours.TryGetValue(typeName, out var ourType))
            {
                AddDifference(differences, encounteredAllowlistEntries, DifferenceSide.Microsoft, typeName, "type", "exported type");
                continue;
            }

            var microsoftSurface = DescribeType(microsoftType);
            var ourSurface = DescribeType(ourType);
            foreach (var descriptor in microsoftSurface.Except(ourSurface, StringComparer.Ordinal))
            {
                AddDifference(differences, encounteredAllowlistEntries, DifferenceSide.Microsoft, typeName, "surface", descriptor);
            }

            foreach (var descriptor in ourSurface.Except(microsoftSurface, StringComparer.Ordinal))
            {
                AddDifference(differences, encounteredAllowlistEntries, DifferenceSide.AdForLinux, typeName, "surface", descriptor);
            }
        }

        var comparedTypeNames = microsoft.Keys.Union(ours.Keys).ToHashSet(StringComparer.Ordinal);
        foreach (var stale in IntentionalDifferences
                     .Where(difference => comparedTypeNames.Contains(difference.TypeName))
                     .Except(encounteredAllowlistEntries)
                     .OrderBy(difference => difference.TypeName, StringComparer.Ordinal)
                     .ThenBy(difference => difference.Descriptor, StringComparer.Ordinal))
        {
            differences.Add($"[Stale allowlist] {stale.TypeName}: {stale.Descriptor}");
        }

        Assert.True(
            differences.Count == 0,
            $"{differences.Count} unallowlisted public API difference(s) for {microsoftNamespace}:" +
            Environment.NewLine + string.Join(Environment.NewLine, differences));
    }

    private static Dictionary<string, Type> ExportedTypes(Assembly assembly, string exactNamespace) =>
        assembly.GetExportedTypes()
            .Where(type => string.Equals(type.Namespace, exactNamespace, StringComparison.Ordinal))
            .ToDictionary(RelativeTypeName, StringComparer.Ordinal);

    private static SortedSet<string> DescribeType(Type type)
    {
        var result = new SortedSet<string>(StringComparer.Ordinal)
        {
            $"type kind={TypeKind(type)} visibility={Visibility(type)} abstract={type.IsAbstract} sealed={type.IsSealed}",
            $"base {TypeName(type.BaseType)}",
        };

        AddAttributes(result, "type", type.CustomAttributes);
        AddGenericConstraints(result, "type", type.GetGenericArguments().Where(argument => argument.DeclaringType == type));

        foreach (var @interface in type.GetInterfaces().Select(TypeName).Order(StringComparer.Ordinal))
        {
            result.Add($"interface {@interface}");
        }

        const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic |
                                   BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (var constructor in type.GetConstructors(flags).Where(IsExternallyVisible))
        {
            var prefix = $"constructor {Visibility(constructor)}({Parameters(constructor.GetParameters())})";
            result.Add(prefix);
            AddAttributes(result, prefix, constructor.CustomAttributes);
            AddParameterMetadata(result, prefix, constructor.GetParameters());
        }

        var accessors = type.GetProperties(flags)
            .SelectMany(property => property.GetAccessors(nonPublic: true))
            .Concat(type.GetEvents(flags).SelectMany(@event =>
                new[] { @event.AddMethod, @event.RemoveMethod, @event.RaiseMethod }.Where(method => method is not null)!))
            .ToHashSet();

        foreach (var method in type.GetMethods(flags)
                     .Where(IsExternallyVisible)
                     .Where(method => !accessors.Contains(method)))
        {
            var prefix = $"method {MethodModifiers(method)} {TypeName(method.ReturnType)} {method.Name}" +
                         $"{GenericArity(method)}({Parameters(method.GetParameters())})";
            result.Add(prefix);
            AddAttributes(result, prefix, method.CustomAttributes);
            AddAttributes(result, prefix + " return", method.ReturnParameter.CustomAttributes);
            AddNullability(result, prefix + " return", method.ReturnParameter);
            AddGenericConstraints(result, prefix, method.GetGenericArguments());
            AddParameterMetadata(result, prefix, method.GetParameters());
        }

        foreach (var property in type.GetProperties(flags).Where(IsExternallyVisible))
        {
            var prefix = $"property {PropertyModifiers(property)} {TypeName(property.PropertyType)} {property.Name}" +
                         $"[{Parameters(property.GetIndexParameters())}]";
            result.Add(prefix);
            AddAttributes(result, prefix, property.CustomAttributes);
            AddNullability(result, prefix, property);
            AddParameterMetadata(result, prefix, property.GetIndexParameters());
        }

        foreach (var @event in type.GetEvents(flags).Where(IsExternallyVisible))
        {
            var prefix = $"event add={Visibility(@event.AddMethod)} remove={Visibility(@event.RemoveMethod)} " +
                         $"raise={Visibility(@event.RaiseMethod)} {TypeName(@event.EventHandlerType)} {@event.Name}";
            result.Add(prefix);
            AddAttributes(result, prefix, @event.CustomAttributes);
        }

        foreach (var field in type.GetFields(flags).Where(IsExternallyVisible))
        {
            var prefix = $"field {Visibility(field)} static={field.IsStatic} readonly={field.IsInitOnly} " +
                         $"literal={field.IsLiteral} {TypeName(field.FieldType)} {field.Name}";
            if (field.IsLiteral)
            {
                prefix += $"={AttributeValue(field.GetRawConstantValue())}";
            }

            result.Add(prefix);
            AddAttributes(result, prefix, field.CustomAttributes);
            AddNullability(result, prefix, field);
        }

        return result;
    }

    private static void AddParameterMetadata(SortedSet<string> result, string owner, ParameterInfo[] parameters)
    {
        for (var index = 0; index < parameters.Length; index++)
        {
            var parameter = parameters[index];
            var prefix = $"{owner} parameter[{index}]";
            AddAttributes(result, prefix, parameter.CustomAttributes);
            AddNullability(result, prefix, parameter);
        }
    }

    private static void AddGenericConstraints(
        SortedSet<string> result,
        string owner,
        IEnumerable<Type> genericParameters)
    {
        foreach (var parameter in genericParameters.Where(parameter => parameter.IsGenericParameter))
        {
            var constraints = parameter.GetGenericParameterConstraints()
                .Select(TypeName)
                .Order(StringComparer.Ordinal);
            result.Add(
                $"{owner} generic[{parameter.GenericParameterPosition}:{parameter.Name}] " +
                $"variance={parameter.GenericParameterAttributes & GenericParameterAttributes.VarianceMask} " +
                $"special={parameter.GenericParameterAttributes & GenericParameterAttributes.SpecialConstraintMask} " +
                $"constraints=[{string.Join(",", constraints)}]");
        }
    }

    private static void AddAttributes(
        SortedSet<string> result,
        string owner,
        IEnumerable<CustomAttributeData> attributes)
    {
        foreach (var attribute in attributes.Where(IsContractAttribute).Select(DescribeAttribute))
        {
            result.Add($"{owner} attribute {attribute}");
        }
    }

    private static bool IsContractAttribute(CustomAttributeData attribute)
    {
        var name = attribute.AttributeType.FullName ?? string.Empty;
        return name is not "System.Runtime.CompilerServices.NullableAttribute"
            and not "System.Runtime.CompilerServices.NullableContextAttribute"
            and not "System.Runtime.CompilerServices.CompilerGeneratedAttribute"
            and not "System.Runtime.CompilerServices.IsReadOnlyAttribute"
            and not "System.Runtime.CompilerServices.TypeForwardedFromAttribute"
            and not "System.Diagnostics.CodeAnalysis.MemberNotNullAttribute"
            and not "System.Diagnostics.DebuggerStepThroughAttribute";
    }

    private static string DescribeAttribute(CustomAttributeData attribute)
    {
        var constructorArguments = attribute.ConstructorArguments.Select(AttributeArgument);
        var namedArguments = attribute.NamedArguments
            .OrderBy(argument => argument.MemberName, StringComparer.Ordinal)
            .Select(argument => $"{argument.MemberName}={AttributeArgument(argument.TypedValue)}");
        return $"{TypeName(attribute.AttributeType)}({string.Join(",", constructorArguments.Concat(namedArguments))})";
    }

    private static string AttributeArgument(CustomAttributeTypedArgument argument)
    {
        if (argument.Value is IReadOnlyCollection<CustomAttributeTypedArgument> values)
        {
            return $"[{string.Join(",", values.Select(AttributeArgument))}]";
        }

        return $"{TypeName(argument.ArgumentType)}:{AttributeValue(argument.Value)}";
    }

    private static string AttributeValue(object? value) => value switch
    {
        null => "null",
        string text => $"\"{text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"",
        char character => $"'{character}'",
        Type type => TypeName(type),
        Enum enumeration => Convert.ToInt64(enumeration).ToString(System.Globalization.CultureInfo.InvariantCulture),
        IFormattable formattable => formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };

    private static readonly NullabilityInfoContext Nullability = new();

    private static void AddNullability(SortedSet<string> result, string owner, ParameterInfo parameter) =>
        AddNullability(result, owner, parameter.Member, () => Nullability.Create(parameter));

    private static void AddNullability(SortedSet<string> result, string owner, PropertyInfo property) =>
        AddNullability(result, owner, property, () => Nullability.Create(property));

    private static void AddNullability(SortedSet<string> result, string owner, FieldInfo field) =>
        AddNullability(result, owner, field, () => Nullability.Create(field));

    private static void AddNullability(
        SortedSet<string> result,
        string owner,
        MemberInfo member,
        Func<NullabilityInfo> factory)
    {
        // The AccountManagement reference assembly currently carries no
        // nullable annotations (reflection reports Unknown everywhere), so
        // comparing it would only punish AdForLinux for having useful local
        // annotations. DirectoryServices does carry usable metadata and is
        // compared exhaustively.
        if (member.DeclaringType?.Namespace?.EndsWith(".AccountManagement", StringComparison.Ordinal) == true)
        {
            return;
        }

        try
        {
            var info = factory();
            result.Add($"{owner} nullability {DescribeNullability(info)}");
        }
        catch (InvalidOperationException)
        {
            // Some runtime-projected members do not expose a readable nullable
            // context. Their CLR signature is still compared above.
        }
    }

    private static string DescribeNullability(NullabilityInfo info) =>
        $"{info.ReadState}/{info.WriteState}" +
        (info.ElementType is null ? string.Empty : $" element=({DescribeNullability(info.ElementType)})") +
        (info.GenericTypeArguments.Length == 0
            ? string.Empty
            : $" generic=[{string.Join(",", info.GenericTypeArguments.Select(DescribeNullability))}]");

    private static string Parameters(IEnumerable<ParameterInfo> parameters) => string.Join(",", parameters.Select(parameter =>
        $"{(parameter.IsOut ? "out " : parameter.ParameterType.IsByRef ? "ref " : string.Empty)}" +
        $"{TypeName(parameter.ParameterType)} {parameter.Name}" +
        (parameter.HasDefaultValue ? $"={AttributeValue(parameter.DefaultValue)}" : string.Empty)));

    private static string MethodModifiers(MethodInfo method) =>
        $"{Visibility(method)} static={method.IsStatic} abstract={method.IsAbstract} virtual={method.IsVirtual} " +
        $"final={method.IsFinal} newslot={(method.Attributes & MethodAttributes.NewSlot) != 0}";

    private static string PropertyModifiers(PropertyInfo property) =>
        $"get=({AccessorModifiers(property.GetMethod)}) set=({AccessorModifiers(property.SetMethod)})";

    private static string AccessorModifiers(MethodInfo? method) => method is null
        ? "none"
        : $"{Visibility(method)},static={method.IsStatic},abstract={method.IsAbstract},virtual={method.IsVirtual}," +
          $"final={method.IsFinal},newslot={(method.Attributes & MethodAttributes.NewSlot) != 0}";

    private static string GenericArity(MethodInfo method) =>
        method.IsGenericMethodDefinition ? $"`{method.GetGenericArguments().Length}" : string.Empty;

    private static bool IsExternallyVisible(MethodBase method) =>
        method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly;

    private static bool IsExternallyVisible(FieldInfo field) =>
        field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;

    private static bool IsExternallyVisible(PropertyInfo property) =>
        property.GetAccessors(nonPublic: true).Any(IsExternallyVisible);

    private static bool IsExternallyVisible(EventInfo @event) =>
        new[] { @event.AddMethod, @event.RemoveMethod, @event.RaiseMethod }
            .Where(method => method is not null)
            .Any(method => IsExternallyVisible(method!));

    private static string Visibility(Type type) => type.IsPublic ? "public" : type.IsNestedPublic ? "nested-public" : "other";

    private static string Visibility(MethodBase? method) => method switch
    {
        null => "none",
        { IsPublic: true } => "public",
        { IsFamily: true } => "protected",
        { IsFamilyOrAssembly: true } => "protected-internal",
        { IsFamilyAndAssembly: true } => "private-protected",
        { IsAssembly: true } => "internal",
        _ => "private",
    };

    private static string Visibility(FieldInfo field) => field switch
    {
        { IsPublic: true } => "public",
        { IsFamily: true } => "protected",
        { IsFamilyOrAssembly: true } => "protected-internal",
        { IsFamilyAndAssembly: true } => "private-protected",
        { IsAssembly: true } => "internal",
        _ => "private",
    };

    private static string TypeKind(Type type) => type.IsInterface ? "interface" : type.IsEnum ? "enum" :
        type.IsValueType ? "struct" : typeof(MulticastDelegate).IsAssignableFrom(type) ? "delegate" : "class";

    private static string RelativeTypeName(Type type) =>
        type.FullName![type.Namespace!.Length..].TrimStart('.').Replace('+', '.');

    private static string TypeName(Type? type)
    {
        if (type is null)
        {
            return "none";
        }

        if (type.IsByRef)
        {
            return TypeName(type.GetElementType()) + "&";
        }

        if (type.IsPointer)
        {
            return TypeName(type.GetElementType()) + "*";
        }

        if (type.IsArray)
        {
            return TypeName(type.GetElementType()) + $"[{new string(',', type.GetArrayRank() - 1)}]";
        }

        if (type.IsGenericParameter)
        {
            return "`" + type.GenericParameterPosition + ":" + type.Name;
        }

        if (type.IsGenericType)
        {
            var definition = type.GetGenericTypeDefinition();
            var name = NormalizeName(definition.FullName ?? definition.Name);
            name = name[..name.LastIndexOf('`')];
            return $"{name}<{string.Join(",", type.GetGenericArguments().Select(TypeName))}>";
        }

        return NormalizeName(type.FullName ?? type.Name);
    }

    private static string NormalizeName(string name) => name
        .Replace("System.DirectoryServices.AccountManagement.", "DirectoryServices.AccountManagement.", StringComparison.Ordinal)
        .Replace("AdForLinux.DirectoryServices.AccountManagement.", "DirectoryServices.AccountManagement.", StringComparison.Ordinal)
        .Replace("System.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal)
        .Replace("AdForLinux.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal)
        .Replace('+', '.');

    private static void AddDifference(
        List<string> differences,
        HashSet<SurfaceDifference> encounteredAllowlistEntries,
        DifferenceSide side,
        string typeName,
        string category,
        string descriptor)
    {
        var difference = new SurfaceDifference(side, typeName, category, descriptor);
        if (IntentionalDifferences.Contains(difference))
        {
            encounteredAllowlistEntries.Add(difference);
        }
        else
        {
            differences.Add($"[{side}] {typeName}: {descriptor}");
        }
    }

    // Intentional extensions and compatibility deviations are documented here
    // as exact descriptors. This ensures a signature/modifier change to an
    // allowed member still fails the oracle. ActiveDirectory is deliberately
    // absent because that namespace is outside the project's claimed scope.
    private static readonly HashSet<SurfaceDifference> IntentionalDifferences =
    [
        // Linux/LDAP conveniences that have no Microsoft counterpart.
        Ours("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) System.String DistinguishedName[]"),
        Ours("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) System.String DistinguishedName[] nullability NotNull/Unknown"),
        Ours("Principal", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) System.String SidValue[]"),
        Ours("PrincipalContext", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) System.Boolean UseSsl[]"),
        Ours("PrincipalContext", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) System.Int32 Port[]"),
        Ours("PrincipalSearcher", "method public static=False abstract=False virtual=False final=False newslot=False System.String GetLdapFilter()"),

        // Generic enumeration and collection conveniences retained for Linux
        // callers. Every exact interface/member is pinned individually so a
        // future LINQ addition must be reviewed and added explicitly.
        Ours("DirectoryEntries", "interface System.Collections.Generic.IEnumerable<DirectoryServices.DirectoryEntry>"),
        Ours("PropertyCollection", "interface System.Collections.Generic.IEnumerable<DirectoryServices.PropertyValueCollection>"),
        Ours("PropertyValueCollection", "interface System.Collections.Generic.IEnumerable<System.Object>"),
        Ours("PropertyValueCollection", "method public static=False abstract=False virtual=False final=False newslot=False System.Void AddRange(System.Collections.Generic.IEnumerable<System.Object> values)"),
        Ours("PropertyValueCollection", "method public static=False abstract=False virtual=False final=False newslot=False System.Void AddRange(System.Collections.Generic.IEnumerable<System.Object> values) parameter[0] nullability NotNull/NotNull generic=[Nullable/Nullable]"),
        Ours("PropertyValueCollection", "method public static=False abstract=False virtual=False final=False newslot=False System.Void AddRange(System.Collections.Generic.IEnumerable<System.Object> values) return nullability NotNull/NotNull"),
        Ours("PropertyValueCollection", "method public static=False abstract=False virtual=True final=True newslot=True System.Collections.Generic.IEnumerator<System.Object> GetEnumerator()"),
        Ours("PropertyValueCollection", "method public static=False abstract=False virtual=True final=True newslot=True System.Collections.Generic.IEnumerator<System.Object> GetEnumerator() return nullability NotNull/NotNull generic=[Nullable/Nullable]"),
        Ours("ResultPropertyCollection", "interface System.Collections.Generic.IEnumerable<DirectoryServices.ResultPropertyValueCollection>"),
        Ours("ResultPropertyValueCollection", "interface System.Collections.Generic.IEnumerable<System.Object>"),
        Ours("ResultPropertyValueCollection", "method public static=False abstract=False virtual=True final=True newslot=True System.Collections.Generic.IEnumerator<System.Object> GetEnumerator()"),
        Ours("ResultPropertyValueCollection", "method public static=False abstract=False virtual=True final=True newslot=True System.Collections.Generic.IEnumerator<System.Object> GetEnumerator() return nullability NotNull/NotNull generic=[Nullable/Nullable]"),
        Ours("SearchResultCollection", "interface System.Collections.Generic.IEnumerable<DirectoryServices.SearchResult>"),
        Ours("SearchResultCollection", "interface System.Collections.Generic.IReadOnlyCollection<DirectoryServices.SearchResult>"),
        Ours("SearchResultCollection", "interface System.Collections.Generic.IReadOnlyList<DirectoryServices.SearchResult>"),

        // Known metadata-only debt. Parent remains honestly nullable because
        // LDAP naming-context roots have no parent, DirectoryEntry.Options
        // never returns null in the LDAP implementation, Filter normalizes
        // null to the default, and the Windows-only designer converter cannot
        // be instantiated here.
        Microsoft("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) DirectoryServices.DirectoryEntry Parent[] nullability NotNull/Unknown"),
        Ours("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) DirectoryServices.DirectoryEntry Parent[] nullability Nullable/Unknown"),
        Microsoft("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) DirectoryServices.DirectoryEntryConfiguration Options[] nullability Nullable/Unknown"),
        Ours("DirectoryEntry", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(none) DirectoryServices.DirectoryEntryConfiguration Options[] nullability NotNull/Unknown"),
        Microsoft("DirectoryEntry", "type attribute System.ComponentModel.TypeConverterAttribute(System.Type:DirectoryServices.Design.DirectoryEntryConverter)"),
        Microsoft("DirectorySearcher", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) System.String Filter[] nullability Nullable/Nullable"),
        Ours("DirectorySearcher", "property get=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) set=(public,static=False,abstract=False,virtual=False,final=False,newslot=False) System.String Filter[] nullability NotNull/Nullable"),
    ];

    private static SurfaceDifference Microsoft(string typeName, string descriptor) =>
        new(DifferenceSide.Microsoft, typeName, "surface", descriptor);

    private static SurfaceDifference Ours(string typeName, string descriptor) =>
        new(DifferenceSide.AdForLinux, typeName, "surface", descriptor);

    private enum DifferenceSide
    {
        Microsoft,
        AdForLinux,
    }

    private sealed record SurfaceDifference(
        DifferenceSide Side,
        string TypeName,
        string Category,
        string Descriptor);
}
