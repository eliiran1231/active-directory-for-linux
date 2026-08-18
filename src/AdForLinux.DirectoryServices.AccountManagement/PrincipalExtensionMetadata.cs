namespace AdForLinux.DirectoryServices.AccountManagement;

internal static class PrincipalExtensionMetadata
{
    internal static string? GetDeclaredObjectClass(Type principalType) =>
        principalType
            .GetCustomAttributes(typeof(DirectoryObjectClassAttribute), inherit: false)
            .Cast<DirectoryObjectClassAttribute>()
            .Select(attribute => attribute.ObjectClass)
            .FirstOrDefault();

    internal static string GetObjectClassForCreation(
        Type principalType,
        string builtInObjectClass)
    {
        if (IsBuiltIn(principalType))
        {
            return builtInObjectClass;
        }

        return GetDeclaredObjectClass(principalType)
            ?? throw InvalidExtensionDefinition(principalType);
    }

    internal static string GetRdnPrefixForCreation(Type principalType)
    {
        var prefix = principalType
            .GetCustomAttributes(typeof(DirectoryRdnPrefixAttribute), inherit: false)
            .Cast<DirectoryRdnPrefixAttribute>()
            .Select(attribute => attribute.RdnPrefix)
            .FirstOrDefault();

        return prefix ?? throw InvalidExtensionDefinition(principalType);
    }

    private static bool IsBuiltIn(Type principalType) =>
        principalType == typeof(UserPrincipal)
        || principalType == typeof(GroupPrincipal)
        || principalType == typeof(ComputerPrincipal);

    private static InvalidOperationException InvalidExtensionDefinition(Type principalType) =>
        new($"Custom principal type {principalType.FullName} must declare both " +
            $"{nameof(DirectoryObjectClassAttribute)} and {nameof(DirectoryRdnPrefixAttribute)}.");
}
