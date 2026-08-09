using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using AdForLinux.DirectoryServices;
using Xunit;

#pragma warning disable CA1416 // Windows-only behavior is guarded by OperatingSystem.IsWindows().

namespace AdForLinux.FunctionalTests;

public class LowLevelFeatureFamiliesTests
{
    [Fact]
    public void Modern_directory_services_public_type_families_are_present()
    {
        var assembly = typeof(DirectoryEntry).Assembly;
        var names = assembly.GetExportedTypes()
            .Where(type => type.Namespace == "AdForLinux.DirectoryServices")
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

        var expected = new[]
        {
            nameof(ActiveDirectoryAccessRule),
            nameof(ActiveDirectoryAuditRule),
            nameof(ActiveDirectoryRights),
            nameof(ActiveDirectorySecurity),
            nameof(ActiveDirectorySecurityInheritance),
            nameof(CreateChildAccessRule),
            nameof(DeleteChildAccessRule),
            nameof(DeleteTreeAccessRule),
            nameof(DirectoryEntryConfiguration),
            nameof(DirectoryServicesCOMException),
            nameof(DirectorySynchronization),
            nameof(DirectoryVirtualListView),
            nameof(DirectoryVirtualListViewContext),
            nameof(ExtendedRightAccessRule),
            nameof(ListChildrenAccessRule),
            nameof(PropertyAccess),
            nameof(PropertyAccessRule),
            nameof(PropertySetAccessRule),
            nameof(SchemaNameCollection),
            nameof(SortOption),
        };

        Assert.All(expected, name => Assert.Contains(name, names));
    }

    [Fact]
    public void Directory_synchronization_copy_is_independent()
    {
        var original = new DirectorySynchronization(
            DirectorySynchronizationOptions.ObjectSecurity,
            new byte[] { 1, 2, 3 });

        var copy = original.Copy();
        original.ResetDirectorySynchronizationCookie(new byte[] { 4, 5 });

        Assert.NotSame(original, copy);
        Assert.Equal(DirectorySynchronizationOptions.ObjectSecurity, copy.Option);
        Assert.Equal(new byte[] { 1, 2, 3 }, copy.GetDirectorySynchronizationCookie());
    }

    [Fact]
    public void Security_rule_values_and_inheritance_match_the_directory_contract()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var identity = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var propertyType = Guid.NewGuid();
        var inheritedType = Guid.NewGuid();
        var rule = new ActiveDirectoryAccessRule(
            identity,
            ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.WriteProperty,
            AccessControlType.Allow,
            propertyType,
            ActiveDirectorySecurityInheritance.Children,
            inheritedType);

        Assert.Equal(
            ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.WriteProperty,
            rule.ActiveDirectoryRights);
        Assert.Equal(ActiveDirectorySecurityInheritance.Children, rule.InheritanceType);
        Assert.Equal(propertyType, rule.ObjectType);
        Assert.Equal(inheritedType, rule.InheritedObjectType);

        var specialized = new PropertyAccessRule(
            identity, AccessControlType.Deny, PropertyAccess.Write, propertyType);
        Assert.Equal(ActiveDirectoryRights.WriteProperty, specialized.ActiveDirectoryRights);
    }

    [Fact]
    public void Object_security_is_explicitly_windows_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var entry = new DirectoryEntry();
        Assert.Throws<PlatformNotSupportedException>(() => entry.ObjectSecurity);
    }

    [Fact]
    public void Required_sid_and_acl_primitives_are_unavailable_on_linux()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        // S-1-1-0 (Everyone) in binary form. Even the pure-binary SID
        // constructor is platform-guarded by modern .NET on Linux.
        var worldSid = new byte[] { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };

        Assert.Throws<PlatformNotSupportedException>(() => new SecurityIdentifier(worldSid, 0));
        Assert.Throws<PlatformNotSupportedException>(() => new ActiveDirectorySecurity());
    }

    [Fact]
    public void Directory_services_com_exception_preserves_standard_exception_shape()
    {
        var inner = new InvalidOperationException("inner");
        var exception = new DirectoryServicesCOMException("message", inner);

        Assert.IsAssignableFrom<COMException>(exception);
        Assert.Equal("message", exception.Message);
        Assert.Same(inner, exception.InnerException);
        Assert.Equal(0, exception.ExtendedError);
        Assert.Null(exception.ExtendedErrorMessage);
    }
}
