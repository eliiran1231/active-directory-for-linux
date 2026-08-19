using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Real-AD matrix for DirectoryEntry.CopyTo. The Windows LDAP ADSI provider
/// returns E_NOTIMPL before creating a target, so the observable attribute,
/// identity, object-class, DN, and security result is that no copy exists and
/// the source remains unchanged.
/// </summary>
public sealed class DirectoryEntryCopyComparisonTests
{
    [Fact]
    public void CopyTo_matrix_matches_microsoft_and_leaves_every_source_unchanged()
    {
        var suffix = Guid.NewGuid().ToString("N")[..7];
        var rootName = $"adfl-cp-{suffix}";
        var rootDn = $"OU={rootName},{DifferentialSettings.BaseDn}";
        var sourceDn = $"OU=source,{rootDn}";
        var sameNameDestinationDn = $"OU=same,{rootDn}";
        var renamedDestinationDn = $"OU=renamed,{rootDn}";
        var dnsDomain = string.Join('.', DifferentialSettings.BaseDn.Split(',')
            .Select(part => part.Trim())
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part[3..]));

        var cases = new[]
        {
            new CopyCase("user", "CN=user", "user", $"u{suffix}", $"u{suffix}@{dnsDomain}"),
            new CopyCase("group", "CN=group", "group", $"g{suffix}", null),
            new CopyCase("computer", "CN=computer", "computer", $"c{suffix}$", null),
            new CopyCase("organizationalUnit", "OU=generic", "organizationalUnit", null, null),
        };

        try
        {
            CreateContainer(DifferentialSettings.BaseDn, $"OU={rootName}");
            CreateContainer(rootDn, "OU=source");
            CreateContainer(rootDn, "OU=same");
            CreateContainer(rootDn, "OU=renamed");
            foreach (var item in cases)
            {
                CreateSource(sourceDn, item, suffix, dnsDomain);
            }

            var comparison = new Comparison("DirectoryEntry.CopyTo real-AD matrix");
            foreach (var item in cases)
            {
                var itemDn = $"{item.Rdn},{sourceDn}";
                var renamedRdn = Rename(item.Rdn);
                var operations = new[]
                {
                    new CopyOperation("CopyTo(parent)", sameNameDestinationDn, item.Rdn, null),
                    new CopyOperation("CopyTo(parent, newName)", renamedDestinationDn, renamedRdn, renamedRdn),
                };

                using var source = MicrosoftEntry(itemDn);
                var before = Snapshot(source);
                foreach (var operation in operations)
                {
                    using var microsoftParent = MicrosoftEntry(operation.ParentDn);
                    using var ourSource = OurEntry(itemDn);
                    using var ourParent = OurEntry(operation.ParentDn);

                    var microsoftError = CaptureCopy(() => operation.NewName is null
                        ? source.CopyTo(microsoftParent)
                        : source.CopyTo(microsoftParent, operation.NewName));
                    var ourError = CaptureCopy(() => operation.NewName is null
                        ? ourSource.CopyTo(ourParent)
                        : ourSource.CopyTo(ourParent, operation.NewName));
                    var label = $"{item.Kind} {operation.Name}";

                    comparison
                        .Check($"{label} exception", microsoftError.GetType().FullName,
                            ourError.GetType().FullName)
                        .Check($"{label} HRESULT", microsoftError.HResult, ourError.HResult)
                        .Check($"{label} Microsoft E_NOTIMPL", unchecked((int)0x80004001),
                            microsoftError.HResult)
                        .Check($"{label} source attributes/security", before, Snapshot(source))
                        .Check($"{label} target absent", false,
                            Exists($"{operation.TargetRdn},{operation.ParentDn}"));
                }
            }

            comparison.Assert();
        }
        finally
        {
            SafeDeleteTree(rootDn);
        }
    }

    [Fact]
    public void CopyTo_failure_inputs_match_microsoft_exception_contract()
    {
        using var microsoft = new Ms.DirectoryEntry();
        using var ours = new Ours.DirectoryEntry();

        var microsoftNullParent = CaptureCopy(() => microsoft.CopyTo(null!));
        var ourNullParent = CaptureCopy(() => ours.CopyTo(null!));

        new Comparison("DirectoryEntry.CopyTo failure inputs")
            .Check("null parent exception", microsoftNullParent.GetType().FullName,
                ourNullParent.GetType().FullName)
            .Check("null parent HRESULT", microsoftNullParent.HResult, ourNullParent.HResult)
            .Assert();
    }

    private static void CreateSource(
        string parentDn,
        CopyCase item,
        string suffix,
        string dnsDomain)
    {
        using var parent = MicrosoftEntry(parentDn);
        using var created = parent.Children.Add(item.Rdn, item.SchemaClass);
        created.Properties["description"].Value = $"copy-matrix-{item.Kind}";
        if (item.SamAccountName is not null)
        {
            created.Properties["sAMAccountName"].Value = item.SamAccountName;
        }
        if (item.UserPrincipalName is not null)
        {
            created.Properties["userPrincipalName"].Value = item.UserPrincipalName;
        }
        if (item.Kind == "user")
        {
            created.Properties["telephoneNumber"].Value = "+1 555 0123";
            created.Properties["userAccountControl"].Value = 514;
        }
        if (item.Kind == "computer")
        {
            var hostName = $"c{suffix}.{dnsDomain}";
            created.Properties["userAccountControl"].Value = 4098;
            created.Properties["dNSHostName"].Value = hostName;
            created.Properties["servicePrincipalName"].Value = new[] { $"HOST/{hostName}" };
        }

        created.CommitChanges();
        var security = created.ObjectSecurity;
        security.AddAccessRule(new ActiveDirectoryAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            ActiveDirectoryRights.ReadProperty,
            AccessControlType.Allow));
        created.ObjectSecurity = security;
        created.CommitChanges();
    }

    private static SourceSnapshot Snapshot(Ms.DirectoryEntry entry)
    {
        entry.RefreshCache();
        return new SourceSnapshot(
            entry.Properties["distinguishedName"].Value?.ToString(),
            entry.SchemaClassName,
            Values(entry, "objectClass"),
            Values(entry, "objectGUID"),
            Values(entry, "objectSid"),
            Values(entry, "sAMAccountName"),
            Values(entry, "userPrincipalName"),
            Values(entry, "servicePrincipalName"),
            Values(entry, "dNSHostName"),
            Values(entry, "userAccountControl"),
            Values(entry, "groupType"),
            Values(entry, "description"),
            entry.ObjectSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    private static string Values(Ms.DirectoryEntry entry, string name) =>
        string.Join("\u001f", entry.Properties[name].Cast<object>().Select(Format).Order());

    private static string Format(object value) => value switch
    {
        byte[] bytes => Convert.ToHexString(bytes),
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "<null>",
    };

    private static Exception CaptureCopy<TEntry>(Func<TEntry> operation) where TEntry : IDisposable
    {
        try
        {
            using var copy = operation();
            return new Xunit.Sdk.XunitException("CopyTo unexpectedly succeeded.");
        }
        catch (Exception error)
        {
            return error;
        }
    }

    private static bool Exists(string dn)
    {
        try
        {
            using var entry = MicrosoftEntry(dn);
            entry.RefreshCache(new[] { "objectClass" });
            return true;
        }
        catch (System.Runtime.InteropServices.COMException error)
            when (error.HResult == unchecked((int)0x80072030))
        {
            return false;
        }
    }

    private static void CreateContainer(string parentDn, string rdn)
    {
        using var parent = MicrosoftEntry(parentDn);
        using var child = parent.Children.Add(rdn, "organizationalUnit");
        child.CommitChanges();
    }

    private static string Rename(string rdn)
    {
        var separator = rdn.IndexOf('=');
        return $"{rdn[..(separator + 1)]}copied-{rdn[(separator + 1)..]}";
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) => new(
        DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword,
        DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) => new(
        DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword,
        DifferentialSettings.OurAuthenticationTypes);

    private static void SafeDeleteTree(string dn)
    {
        try
        {
            using var entry = MicrosoftEntry(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best-effort cleanup when setup or a matrix row fails.
        }
    }

    private sealed record CopyCase(
        string Kind,
        string Rdn,
        string SchemaClass,
        string? SamAccountName,
        string? UserPrincipalName);

    private sealed record CopyOperation(
        string Name,
        string ParentDn,
        string TargetRdn,
        string? NewName);

    private sealed record SourceSnapshot(
        string? DistinguishedName,
        string SchemaClassName,
        string ObjectClass,
        string ObjectGuid,
        string ObjectSid,
        string SamAccountName,
        string UserPrincipalName,
        string ServicePrincipalName,
        string DnsHostName,
        string UserAccountControl,
        string GroupType,
        string Description,
        string SecurityDescriptor);
}
