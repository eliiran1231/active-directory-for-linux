using Xunit;

using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class ConnectionStateOfflineComparisonTests
{
    [Fact]
    public void Invalid_connected_server_endpoint_matches_microsoft_exception_type()
    {
        var microsoft = Record.Exception(() =>
        {
            using var context = new Ms.PrincipalContext(
                Ms.ContextType.Domain,
                "127.0.0.1:1",
                "DC=example,DC=test",
                Ms.ContextOptions.SimpleBind,
                "user@example.test",
                "password");
            _ = context.ConnectedServer;
        });
        var ours = Record.Exception(() =>
        {
            using var context = new Ours.PrincipalContext(
                Ours.ContextType.Domain,
                "127.0.0.1:1",
                "DC=example,DC=test",
                Ours.ContextOptions.SimpleBind,
                "user@example.test",
                "password");
            _ = context.ConnectedServer;
        });

        Assert.IsType<Ms.PrincipalServerDownException>(microsoft);
        Assert.IsType<Ours.PrincipalServerDownException>(ours);
    }
}
