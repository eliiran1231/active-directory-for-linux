using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DirectoryEntryUnboundCommitComparisonTests
{
    [Theory]
    [InlineData("fresh", false)]
    [InlineData("wrapper", false)]
    [InlineData("closed", false)]
    [InlineData("disposed", false)]
    [InlineData("fresh", true)]
    [InlineData("wrapper", true)]
    [InlineData("closed", true)]
    [InlineData("disposed", true)]
    public void Unbound_commit_and_cache_mode_transition_match_microsoft(string state, bool disableCache)
    {
        // Signing without Secure is rejected locally by the clone if it tries
        // to bind. Microsoft never binds for these clean, unbound operations.
        // This makes an unintended bind observable without contacting a DC.
        const string path = "LDAP://unused.example.test/DC=example,DC=test";
        using var microsoft = new Ms.DirectoryEntry(path, null, null, Ms.AuthenticationTypes.Signing);
        using var ours = new Ours.DirectoryEntry(path, null, null, Ours.AuthenticationTypes.Signing);

        if (state != "fresh")
        {
            _ = microsoft.Properties;
            _ = ours.Properties;
        }
        if (state == "closed")
        {
            microsoft.Close();
            ours.Close();
        }
        if (state == "disposed")
        {
            microsoft.Dispose();
            ours.Dispose();
        }

        var expectedError = Record.Exception(() =>
        {
            if (disableCache)
                microsoft.UsePropertyCache = false;
            else
                microsoft.CommitChanges();
        });
        var actualError = Record.Exception(() =>
        {
            if (disableCache)
                ours.UsePropertyCache = false;
            else
                ours.CommitChanges();
        });

        // Guard the oracle premise: these Microsoft operations are local no-ops
        // (apart from the requested cache flag change), not failed connections.
        Assert.Null(expectedError);
        new Comparison($"Unbound entry: state={state}, disableCache={disableCache}")
            .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
            .Check("UsePropertyCache", microsoft.UsePropertyCache, ours.UsePropertyCache)
            .Check("Path", microsoft.Path, ours.Path)
            .Assert();
    }
}
