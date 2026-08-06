using System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Creates the objects the comparison tests read, using the real Microsoft
/// <see cref="DirectoryEntry"/>, and removes them afterwards.
///
/// Seeding with Microsoft's API on purpose: the data must be exactly what the
/// reference library would produce, so any difference we then see comes from
/// our reading code, not from how the object was made.
/// </summary>
public sealed class TestDataFixture : IDisposable
{
    private readonly List<string> _created = new();

    public TestDataFixture()
    {
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 8);

        UserName = $"adfl-d-u-{suffix}";
        GroupName = $"adfl-d-g-{suffix}";
        NestedGroupName = $"adfl-d-n-{suffix}";

        UserDn = $"CN={UserName},{DifferentialSettings.UsersContainer}";
        GroupDn = $"CN={GroupName},{DifferentialSettings.UsersContainer}";
        NestedGroupDn = $"CN={NestedGroupName},{DifferentialSettings.UsersContainer}";

        CreateUser();
        CreateGroups();
        AddMembership();
    }

    public string UserName { get; }

    public string GroupName { get; }

    public string NestedGroupName { get; }

    public string UserDn { get; }

    public string GroupDn { get; }

    public string NestedGroupDn { get; }

    /// <summary>The password set on the seeded user.</summary>
    public string UserPassword => "Str0ng!Passw0rd#2026";

    private static DirectoryEntry Open(string dn) =>
        new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    private void CreateUser()
    {
        using var container = Open(DifferentialSettings.UsersContainer);
        using var user = container.Children.Add($"CN={UserName}", "user");

        user.Properties["sAMAccountName"].Value = UserName;
        user.Properties["userPrincipalName"].Value = $"{UserName}@{DomainSuffix()}";
        user.Properties["givenName"].Value = "Ada";
        user.Properties["sn"].Value = "Lovelace";
        user.Properties["middleName"].Value = "Byron";
        user.Properties["displayName"].Value = "Ada Lovelace";
        user.Properties["description"].Value = "differential test user";
        user.Properties["mail"].Value = "ada@example.com";
        user.Properties["telephoneNumber"].Value = "+1-555-0100";
        user.Properties["employeeID"].Value = "E-4242";
        user.Properties["homeDirectory"].Value = @"\\server\home\ada";
        user.Properties["homeDrive"].Value = "H:";
        user.Properties["scriptPath"].Value = "logon.bat";
        user.CommitChanges();

        // Give it a password and enable it, so the account-state members have
        // something real to report.
        user.Invoke("SetPassword", UserPassword);
        user.Properties["userAccountControl"].Value = 0x200; // normal, enabled
        user.CommitChanges();

        _created.Add(UserDn);
    }

    private void CreateGroups()
    {
        using var container = Open(DifferentialSettings.UsersContainer);

        using (var group = container.Children.Add($"CN={GroupName}", "group"))
        {
            group.Properties["sAMAccountName"].Value = GroupName;
            group.CommitChanges();
            _created.Add(GroupDn);
        }

        using (var nested = container.Children.Add($"CN={NestedGroupName}", "group"))
        {
            nested.Properties["sAMAccountName"].Value = NestedGroupName;
            nested.CommitChanges();
            _created.Add(NestedGroupDn);
        }
    }

    private void AddMembership()
    {
        // group contains the user; nested group contains group.
        using (var group = Open(GroupDn))
        {
            group.Properties["member"].Add(UserDn);
            group.CommitChanges();
        }

        using (var nested = Open(NestedGroupDn))
        {
            nested.Properties["member"].Add(GroupDn);
            nested.CommitChanges();
        }
    }

    private static string DomainSuffix() =>
        string.Join(".", DifferentialSettings.BaseDn
            .Split(',')
            .Select(part => part.Trim())
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part.Substring(3)));

    public void Dispose()
    {
        // Delete children before parents; nested group first.
        _created.Reverse();
        foreach (var dn in _created)
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
}
