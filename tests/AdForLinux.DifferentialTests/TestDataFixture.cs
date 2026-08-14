using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;

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
        UnsetUserName = $"adfl-d-z-{suffix}";
        ComputerName = $"adfl-d-c-{suffix}";
        GroupName = $"adfl-d-g-{suffix}";
        NestedGroupName = $"adfl-d-n-{suffix}";

        UserDn = $"CN={UserName},{DifferentialSettings.UsersContainer}";
        UnsetUserDn = $"CN={UnsetUserName},{DifferentialSettings.UsersContainer}";
        ComputerDn = $"CN={ComputerName},{DifferentialSettings.UsersContainer}";
        GroupDn = $"CN={GroupName},{DifferentialSettings.UsersContainer}";
        NestedGroupDn = $"CN={NestedGroupName},{DifferentialSettings.UsersContainer}";

        try
        {
            CreateUser();
            CreateUnsetUser();
            CreateComputer();
            CreateGroups();
            AddMembership();
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public string UserName { get; }

    public string UnsetUserName { get; }

    public string ComputerName { get; }

    public string GroupName { get; }

    public string NestedGroupName { get; }

    public string UserDn { get; }

    public string UnsetUserDn { get; }

    public string ComputerDn { get; }

    public string GroupDn { get; }

    public string NestedGroupDn { get; }

    public DateTime UserExpirationTime { get; } =
        new(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>The password set on the seeded user.</summary>
    public string UserPassword => "Str0ng!Passw0rd#2026";

    private static DirectoryEntry Open(string dn) =>
        new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

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
        _created.Add(UserDn);

        // Give it a password and enable it, so the account-state members have
        // something real to report.
        user.Invoke("SetPassword", UserPassword);
        user.Properties["userAccountControl"].Value = 0x200; // normal, enabled
        user.CommitChanges();

        SetUserExpiration();
        RecordSuccessfulUserLogon();
    }

    private void CreateUnsetUser()
    {
        using var container = Open(DifferentialSettings.UsersContainer);
        using var user = container.Children.Add($"CN={UnsetUserName}", "user");
        user.Properties["sAMAccountName"].Value = UnsetUserName;
        user.CommitChanges();
        _created.Add(UnsetUserDn);
    }

    private void SetUserExpiration()
    {
        using var context = new System.DirectoryServices.AccountManagement.PrincipalContext(
            System.DirectoryServices.AccountManagement.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            System.DirectoryServices.AccountManagement.ContextOptions.SimpleBind |
            System.DirectoryServices.AccountManagement.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var user = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(
            context, UserName)
            ?? throw new InvalidOperationException($"Could not reload seeded user {UserName}.");
        user.AccountExpirationDate = UserExpirationTime;
        user.Save();
    }

    private void RecordSuccessfulUserLogon()
    {
        var identifier = new LdapDirectoryIdentifier(
            DifferentialSettings.Host,
            DifferentialSettings.Port,
            fullyQualifiedDnsHostName: false,
            connectionless: false);
        var upn = $"{UserName}@{DomainSuffix()}";
        using var connection = new LdapConnection(
            identifier,
            new NetworkCredential(upn, UserPassword),
            AuthType.Basic);
        connection.SessionOptions.SecureSocketLayer = DifferentialSettings.UseTls;
        connection.Bind();
    }

    private void CreateGroups()
    {
        using var container = Open(DifferentialSettings.UsersContainer);

        using (var group = container.Children.Add($"CN={GroupName}", "group"))
        {
            group.Properties["sAMAccountName"].Value = GroupName;
            // Deliberately DN-looking text in a non-DN schema attribute. ASQ
            // must reject the schema type instead of following this value.
            group.Properties["description"].Value = UserDn;
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

    private void CreateComputer()
    {
        using var container = Open(DifferentialSettings.UsersContainer);
        using var computer = container.Children.Add($"CN={ComputerName}", "computer");
        computer.Properties["sAMAccountName"].Value = $"{ComputerName}$";
        computer.CommitChanges();
        _created.Add(ComputerDn);
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
