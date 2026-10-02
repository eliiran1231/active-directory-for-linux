using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using MsDs = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Writes only inside a uniquely owned CN container. Run in the verified disposable lab.
// Reference: dotnet/runtime v9.0.0 AD/ADUtils.cs, EscapeDNComponent.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityInsertionRdnComparisonTests
{
    [Theory]
    [InlineData("plain")]
    [InlineData("leading-space")]
    [InlineData("trailing-space")]
    [InlineData("both-spaces")]
    [InlineData("leading-hash")]
    [InlineData("comma-plus")]
    [InlineData("quote-backslash")]
    [InlineData("slash")]
    public void Group_insertion_preserves_rdn_literal_like_microsoft(string shape)
    {
        var suffix = Guid.NewGuid().ToString("N");
        var microsoftToken = $"rm{suffix[..12]}";
        var ourToken = $"ro{suffix[..12]}";
        var containerName = $"adfl-rdn-{suffix}";
        var container = $"CN={containerName},{DifferentialSettings.UsersContainer}";
        var containerAttempted = false;
        Exception? primaryFailure = null;
        Exception? cleanupFailure = null;
        try
        {
            // Mark before CommitChanges: it can persist the container before a later
            // client-side step reports failure. The predictable owned DN lets
            // cleanup also remove groups whose Save failed before setting SAM.
            CompatibilityOwnedDirectoryObjects.RequireAbsent(container);
            containerAttempted = true;
            using (var parent = Open(DifferentialSettings.UsersContainer))
            using (var child = parent.Children.Add($"CN={containerName}", "container"))
                child.CommitChanges();

            using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
                DifferentialSettings.ServerName, container, DifferentialSettings.MicrosoftContextOptions,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
            using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
                DifferentialSettings.ServerName, container, DifferentialSettings.OurContextOptions,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
            using var microsoft = new Ms.GroupPrincipal(microsoftContext)
            {
                Name = Name(shape, microsoftToken), SamAccountName = microsoftToken,
                IsSecurityGroup = true, GroupScope = Ms.GroupScope.Global,
            };
            using var ours = new Ours.GroupPrincipal(ourContext)
            {
                Name = Name(shape, ourToken), SamAccountName = ourToken,
                IsSecurityGroup = true, GroupScope = Ours.GroupScope.Global,
            };

            // Oracle setup must really succeed. Equal authorization, schema or
            // connectivity failures must never count as insertion parity.
            microsoft.Save();
            var expected = Snapshot(container, microsoftToken, microsoft.Name, microsoft.DistinguishedName);
            var actualSaveError = Record.Exception(ours.Save);
            Assert.True(actualSaveError is null,
                $"Microsoft Save succeeded; AdForLinux Save failed: {Describe(actualSaveError)}");
            var actual = Snapshot(container, ourToken, ours.Name, ours.DistinguishedName);
            Assert.Equal(expected, actual);
        }
        catch (Exception error)
        {
            primaryFailure = error;
        }
        finally
        {
            if (containerAttempted)
            {
                try { CleanupOwnedContainer(container); }
                catch (Exception error) { cleanupFailure = error; }
            }
        }
        if (cleanupFailure is not null)
        {
            var failures = new List<Exception>();
            if (primaryFailure is not null) failures.Add(primaryFailure);
            failures.Add(new InvalidOperationException($"Cleanup failed for test-owned {container}.", cleanupFailure));
            throw new AggregateException("RDN insertion test and/or owned-container cleanup failed.", failures);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private static string[] Snapshot(string container, string token, string? immediateName, string? immediateDn)
    {
        Assert.NotNull(immediateName);
        Assert.NotNull(immediateDn);
        using var root = Open(container);
        using var searcher = new MsDs.DirectorySearcher(root)
        {
            // token is generated from a fixed ASCII prefix plus hexadecimal.
            Filter = $"(&(objectClass=group)(sAMAccountName={token}))",
            SearchScope = MsDs.SearchScope.OneLevel,
        };
        searcher.PropertiesToLoad.AddRange(new[] { "cn", "name", "distinguishedName", "sAMAccountName" });
        using var results = searcher.FindAll();
        var resultCount = results.Count;
        Assert.Equal(1, resultCount);
        var result = results[0];
        string Property(string name)
        {
            var values = result.Properties[name];
            Assert.Single(values.Cast<object>());
            return Assert.IsType<string>(values[0]);
        }
        Assert.Equal(token, Property("sAMAccountName"));
        // Preserve every whitespace/punctuation/case/escape difference. Only
        // the independently generated principal token is normalized; the container
        // and both APIs' server responses otherwise remain byte-for-byte text.
        return new[]
        {
            $"immediate-name:{immediateName}",
            $"immediate-dn:{immediateDn}",
            $"persisted-cn:{Property("cn")}",
            $"persisted-name:{Property("name")}",
            $"persisted-dn:{Property("distinguishedName")}",
        }.Select(value => value.Replace(token, "{principal}", StringComparison.Ordinal)).ToArray();
    }

    private static string Name(string shape, string token) => shape switch
    {
        "leading-space" => $" {token}",
        "trailing-space" => $"{token} ",
        "both-spaces" => $" {token} ",
        "leading-hash" => $"#{token}",
        "comma-plus" => $"{token},part+tail",
        "quote-backslash" => $"{token}\"part\\tail",
        "slash" => $"{token}/tail",
        _ => token,
    };

    private static string Describe(Exception? error) => error is null ? "none" :
        $"{error.GetType().Name}; HRESULT=0x{error.HResult:X8}; parameter={(error as ArgumentException)?.ParamName}; {error.Message}";

    private static void CleanupOwnedContainer(string distinguishedName)
    {
        using var entry = Open(distinguishedName);
        try { _ = entry.NativeGuid; }
        catch (COMException error) when (error.HResult == unchecked((int)0x80072030))
        {
            return; // No such object: a container creation attempt never persisted.
        }
        entry.DeleteTree();
    }

    private static MsDs.DirectoryEntry Open(string distinguishedName) =>
        new(DifferentialSettings.PathFor(distinguishedName), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
