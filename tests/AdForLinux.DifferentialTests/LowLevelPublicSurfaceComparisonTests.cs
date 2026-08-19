using Xunit;
using System.Reflection;

namespace AdForLinux.DifferentialTests;

public class LowLevelPublicSurfaceComparisonTests
{
    [Fact]
    public void Modern_low_level_public_type_names_and_base_types_match_microsoft()
    {
        var microsoftTypes = typeof(System.DirectoryServices.DirectoryEntry).Assembly
            .GetExportedTypes()
            .Where(type => type.Namespace == "System.DirectoryServices")
            .ToDictionary(type => type.Name, StringComparer.Ordinal);
        var ourTypes = typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly
            .GetExportedTypes()
            .Where(type => type.Namespace == "AdForLinux.DirectoryServices")
            .ToDictionary(type => type.Name, StringComparer.Ordinal);
        var microsoft = microsoftTypes.Keys
            .Order(StringComparer.Ordinal)
            .ToArray();
        var ours = ourTypes.Keys
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(microsoft, ours);
        var baseTypeDifferences = microsoft
            .Select(typeName => new
            {
                TypeName = typeName,
                Microsoft = Normalize(microsoftTypes[typeName].BaseType),
                Ours = Normalize(ourTypes[typeName].BaseType),
            })
            .Where(item => !string.Equals(item.Microsoft, item.Ours, StringComparison.Ordinal))
            .Select(item => $"{item.TypeName}: Microsoft={item.Microsoft}, Ours={item.Ours}")
            .ToArray();

        Assert.Empty(baseTypeDifferences);
    }

    [Fact]
    public void DirectorySearcher_component_inheritance_and_interfaces_match_microsoft()
    {
        var microsoft = typeof(System.DirectoryServices.DirectorySearcher);
        var ours = typeof(AdForLinux.DirectoryServices.DirectorySearcher);

        Assert.Equal(Normalize(microsoft.BaseType), Normalize(ours.BaseType));
        Assert.Equal(
            microsoft.GetInterfaces().Select(Normalize).Order(StringComparer.Ordinal),
            ours.GetInterfaces().Select(Normalize).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("ActiveDirectoryAccessRule")]
    [InlineData("ActiveDirectoryAuditRule")]
    [InlineData("ActiveDirectoryRights")]
    [InlineData("ActiveDirectorySecurity")]
    [InlineData("ActiveDirectorySecurityInheritance")]
    [InlineData("CreateChildAccessRule")]
    [InlineData("DeleteChildAccessRule")]
    [InlineData("DeleteTreeAccessRule")]
    [InlineData("DirectoryEntryConfiguration")]
    [InlineData("DirectoryServicesCOMException")]
    [InlineData("DirectorySynchronization")]
    [InlineData("DirectorySynchronizationOptions")]
    [InlineData("DirectoryVirtualListView")]
    [InlineData("DirectoryVirtualListViewContext")]
    [InlineData("ExtendedRightAccessRule")]
    [InlineData("ListChildrenAccessRule")]
    [InlineData("PropertyAccess")]
    [InlineData("PropertyAccessRule")]
    [InlineData("PropertySetAccessRule")]
    [InlineData("SchemaNameCollection")]
    [InlineData("SortDirection")]
    [InlineData("SortOption")]
    public void Newly_added_public_type_members_match_microsoft(string typeName)
    {
        var microsoft = typeof(System.DirectoryServices.DirectoryEntry).Assembly
            .GetType($"System.DirectoryServices.{typeName}", throwOnError: true)!;
        var ours = typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly
            .GetType($"AdForLinux.DirectoryServices.{typeName}", throwOnError: true)!;

        Assert.Equal(Normalize(microsoft.BaseType), Normalize(ours.BaseType));
        var microsoftSurface = PublicSurface(microsoft);
        var ourSurface = PublicSurface(ours);
        Assert.True(
            microsoftSurface.SequenceEqual(ourSurface, StringComparer.Ordinal),
            $"Microsoft:\n{string.Join("\n", microsoftSurface)}\n\nOurs:\n{string.Join("\n", ourSurface)}");
    }

    private static string[] PublicSurface(Type type)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance |
                                   BindingFlags.Static | BindingFlags.DeclaredOnly;
        var constructors = type.GetConstructors(flags)
            .Select(constructor => $"ctor({Parameters(constructor.GetParameters())})");
        var methods = type.GetMethods(flags)
            .Where(method => !method.IsSpecialName)
            .Select(method => $"method {Normalize(method.ReturnType)} {method.Name}({Parameters(method.GetParameters())})");
        var properties = type.GetProperties(flags)
            .Select(property =>
                $"property {Normalize(property.PropertyType)} {property.Name} get={property.GetMethod is not null} set={property.SetMethod is not null}");
        var fields = type.GetFields(flags)
            .Where(field => !field.IsSpecialName)
            .Select(field => $"field {Normalize(field.FieldType)} {field.Name}={field.GetRawConstantValue()}");

        return constructors.Concat(methods).Concat(properties).Concat(fields)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static string Parameters(IEnumerable<ParameterInfo> parameters) =>
        string.Join(",", parameters.Select(parameter => Normalize(parameter.ParameterType)));

    private static string Normalize(Type? type) => type?.FullName?
        .Replace("System.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal)
        .Replace("AdForLinux.DirectoryServices.", "DirectoryServices.", StringComparison.Ordinal)
        ?? string.Empty;
}
