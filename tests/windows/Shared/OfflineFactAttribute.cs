using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.Tests;

internal sealed class OfflineFactAttribute : FactAttribute
{
    public OfflineFactAttribute()
    {
        if (!OfflineTestGuard.Enabled) Skip = "Requires the guarded offline runner.";
    }
}
