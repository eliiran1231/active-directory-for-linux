using AdForLinux.DirectoryServices;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Helpers to create and remove test objects with the low-level API, so the
/// high-level tests have data to read.
/// </summary>
internal static class TestDirectory
{
    public static string UsersContainer => $"CN=Users,{TestSettings.BaseDn}";

    private static DirectoryEntry Open(string dn) =>
        new(TestSettings.PathFor(dn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    /// <summary>Creates an object under CN=Users and returns its DN.</summary>
    public static string Create(string cn, string schemaClass, IDictionary<string, string> attributes)
    {
        var dn = $"CN={cn},{UsersContainer}";
        using var parent = Open(UsersContainer);
        var child = parent.Children.Add($"CN={cn}", schemaClass);
        foreach (var (name, value) in attributes)
        {
            child.Properties[name].Value = value;
        }

        child.CommitChanges();
        child.Dispose();
        return dn;
    }

    /// <summary>Deletes an object, ignoring any error.</summary>
    public static void Delete(string dn)
    {
        try
        {
            using var entry = Open(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup.
        }
    }
}
