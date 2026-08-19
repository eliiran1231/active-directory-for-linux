using Xunit;

namespace AdForLinux.DifferentialTests;

public class PublicTypeModifierComparisonTests
{
    [Fact]
    public void DirectoryServices_public_type_modifiers_match_microsoft() =>
        AssertPublicTypeModifiers(
            typeof(System.DirectoryServices.DirectoryEntry).Assembly,
            "System.DirectoryServices",
            typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly,
            "AdForLinux.DirectoryServices");

    [Fact]
    public void AccountManagement_public_type_modifiers_match_microsoft() =>
        AssertPublicTypeModifiers(
            typeof(System.DirectoryServices.AccountManagement.Principal).Assembly,
            "System.DirectoryServices.AccountManagement",
            typeof(AdForLinux.DirectoryServices.AccountManagement.Principal).Assembly,
            "AdForLinux.DirectoryServices.AccountManagement");

    private static void AssertPublicTypeModifiers(
        System.Reflection.Assembly microsoftAssembly,
        string microsoftNamespace,
        System.Reflection.Assembly ourAssembly,
        string ourNamespace)
    {
        var microsoftTypes = microsoftAssembly.GetExportedTypes()
            .Where(type => type.Namespace == microsoftNamespace)
            .ToDictionary(type => TypeKey(type, microsoftNamespace), StringComparer.Ordinal);
        var ourTypes = ourAssembly.GetExportedTypes()
            .Where(type => type.Namespace == ourNamespace)
            .ToDictionary(type => TypeKey(type, ourNamespace), StringComparer.Ordinal);

        var differences = microsoftTypes.Keys.Union(ourTypes.Keys, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .Select(typeName => Difference(
                typeName,
                microsoftTypes.GetValueOrDefault(typeName),
                ourTypes.GetValueOrDefault(typeName)))
            .Where(difference => difference is not null)
            .ToArray();

        Assert.True(
            differences.Length == 0,
            $"Public type modifier differences:\n{string.Join("\n", differences)}");
    }

    private static string? Difference(string typeName, Type? microsoft, Type? ours)
    {
        if (microsoft is null || ours is null)
        {
            return $"{typeName}: Microsoft={(microsoft is null ? "missing" : "present")}, " +
                   $"Ours={(ours is null ? "missing" : "present")}";
        }

        var microsoftShape = Shape(microsoft);
        var ourShape = Shape(ours);
        return microsoftShape == ourShape
            ? null
            : $"{typeName}: Microsoft={microsoftShape}, Ours={ourShape}";
    }

    private static string Shape(Type type) =>
        $"visibility={Visibility(type)}, sealed={type.IsSealed}, abstract={type.IsAbstract}, " +
        $"base={Normalize(type.BaseType)}";

    private static string Visibility(Type type) => (type.Attributes & System.Reflection.TypeAttributes.VisibilityMask) switch
    {
        System.Reflection.TypeAttributes.Public => "public",
        System.Reflection.TypeAttributes.NestedPublic => "nested-public",
        _ => "non-public",
    };

    private static string TypeKey(Type type, string @namespace) =>
        type.FullName![(@namespace.Length + 1)..];

    private static string Normalize(Type? type)
    {
        if (type is null)
        {
            return string.Empty;
        }

        if (type.IsGenericType)
        {
            var definition = type.GetGenericTypeDefinition();
            var definitionName = NormalizeName(definition.FullName!);
            return $"{definitionName}[{string.Join(",", type.GetGenericArguments().Select(Normalize))}]";
        }

        return NormalizeName(type.FullName ?? type.Name);
    }

    private static string NormalizeName(string name) => name
        .Replace("System.DirectoryServices.AccountManagement.", "DirectoryServices.AccountManagement.", StringComparison.Ordinal)
        .Replace("AdForLinux.DirectoryServices.AccountManagement.", "DirectoryServices.AccountManagement.", StringComparison.Ordinal)
        .Replace("System.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal)
        .Replace("AdForLinux.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal);
}
