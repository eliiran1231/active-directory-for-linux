using System.DirectoryServices.Protocols;
using System.Net;
using Xunit;

using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;
using MsAm = System.DirectoryServices.AccountManagement;
using OursAm = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class DirectoryEntryOptionsLiveTests
{
    private const string RequiredBaseDn = "OU=Issue62,OU=AoTesting,DC=adlab,DC=local";
    private const int ChildCount = 1005;

    [Fact]
    public void Connected_server_names_match_microsoft_for_the_configured_endpoint()
    {
        using var microsoftContext = new MsAm.PrincipalContext(
            MsAm.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var ourContext = new OursAm.PrincipalContext(
            OursAm.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var microsoftEntry = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourEntry = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

        Assert.Equal(
            microsoftContext.ConnectedServer,
            ourContext.ConnectedServer,
            ignoreCase: true);
        Assert.Equal(
            microsoftEntry.Options!.GetCurrentServerName(),
            ourEntry.Options.GetCurrentServerName(),
            ignoreCase: true);
    }

    [Fact]
    public void Configured_page_size_enumerates_more_than_the_ad_size_limit()
    {
        // This destructive, high-volume regression is deliberately opt-in and confined to
        // the issue's dedicated OU. Never fall back to the domain root or CN=Users.
        if (!string.Equals(
                Environment.GetEnvironmentVariable("AD_BASE_DN"),
                RequiredBaseDn,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Xunit.Sdk.SkipException.ForSkip(
                $"Set AD_BASE_DN to the isolated test OU '{RequiredBaseDn}' before running this test.");
        }

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var containerDn = $"OU=Page-{suffix},{RequiredBaseDn}";

        using var connection = CreateConnection();
        try
        {
            connection.SendRequest(new AddRequest(
                containerDn,
                new DirectoryAttribute("objectClass", "organizationalUnit"),
                new DirectoryAttribute("ou", $"Page-{suffix}")));

            for (var index = 0; index < ChildCount; index++)
            {
                var ou = $"Child-{index:D4}";
                connection.SendRequest(new AddRequest(
                    $"OU={ou},{containerDn}",
                    new DirectoryAttribute("objectClass", "organizationalUnit"),
                    new DirectoryAttribute("ou", ou)));
            }

            using var parent = new Ours.DirectoryEntry(
                DifferentialSettings.PathFor(containerDn),
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword,
                DifferentialSettings.OurAuthenticationTypes);
            parent.Options.PageSize = 128;

            var children = parent.Children.Cast<Ours.DirectoryEntry>().ToArray();
            try
            {
                Assert.Equal(ChildCount, children.Length);
            }
            finally
            {
                foreach (var child in children)
                {
                    child.Dispose();
                }
            }
        }
        finally
        {
            var delete = new DeleteRequest(containerDn);
            delete.Controls.Add(new TreeDeleteControl());
            try
            {
                connection.SendRequest(delete);
            }
            catch (DirectoryOperationException exception)
                when (exception.Response?.ResultCode == ResultCode.NoSuchObject)
            {
            }
        }
    }

    private static LdapConnection CreateConnection()
    {
        var identifier = new LdapDirectoryIdentifier(
            DifferentialSettings.Host,
            DifferentialSettings.Port,
            fullyQualifiedDnsHostName: false,
            connectionless: false);
        var connection = new LdapConnection(
            identifier,
            new NetworkCredential(
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword),
            AuthType.Basic);
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = DifferentialSettings.UseTls;
        connection.Bind();
        return connection;
    }
}
