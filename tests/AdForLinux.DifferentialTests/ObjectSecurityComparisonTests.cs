using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Behavioral and live-AD coverage for DirectoryEntry.ObjectSecurity. These
/// tests intentionally run only on Windows because the underlying .NET ACL and
/// SID types throw PlatformNotSupportedException on Linux.
/// </summary>
[Collection("differential")]
public class ObjectSecurityComparisonTests : IClassFixture<ObjectSecurityTestFixture>
{
    private readonly ObjectSecurityTestFixture _data;

    public ObjectSecurityComparisonTests(ObjectSecurityTestFixture data)
    {
        _data = data;
    }

    [Fact]
    public void ObjectSecurity_assignment_with_cache_enabled_is_deferred_like_Microsoft()
    {
        var microsoft = ExerciseMicrosoftCaching(usePropertyCache: true);
        var ours = ExerciseOurCaching(usePropertyCache: true);

        new Comparison("ObjectSecurity with UsePropertyCache=true")
            .Check("visible before CommitChanges", microsoft.VisibleBeforeCommit, ours.VisibleBeforeCommit)
            .Check("visible after CommitChanges", microsoft.VisibleAfterCommit, ours.VisibleAfterCommit)
            .Assert();

        Assert.False(ours.VisibleBeforeCommit);
        Assert.True(ours.VisibleAfterCommit);
    }

    [Fact]
    public void ObjectSecurity_assignment_with_cache_disabled_commits_immediately_like_Microsoft()
    {
        var microsoft = ExerciseMicrosoftCaching(usePropertyCache: false);
        var ours = ExerciseOurCaching(usePropertyCache: false);

        new Comparison("ObjectSecurity with UsePropertyCache=false")
            .Check("visible immediately", microsoft.VisibleBeforeCommit, ours.VisibleBeforeCommit)
            .Assert();

        Assert.True(ours.VisibleBeforeCommit);
    }

    [Fact]
    public void Dacl_change_round_trips_without_replacing_unrequested_security_sections()
    {
        var objectType = Guid.NewGuid();
        var identity = ReadOurObjectSid();
        var before = ReadOurNonDaclSections();
        var rule = new Ours.ActiveDirectoryAccessRule(
            identity,
            Ours.ActiveDirectoryRights.ReadProperty,
            AccessControlType.Allow,
            objectType,
            Ours.ActiveDirectorySecurityInheritance.None);

        try
        {
            using (var entry = OurEntry())
            {
                entry.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
                var security = entry.ObjectSecurity;

                Assert.Throws<InvalidOperationException>(() => security.AddAuditRule(
                    new Ours.ActiveDirectoryAuditRule(
                        identity,
                        Ours.ActiveDirectoryRights.ReadProperty,
                        AuditFlags.Success)));

                security.AddAccessRule(rule);
                entry.ObjectSecurity = security;
                entry.CommitChanges();
            }

            using (var reread = OurEntry())
            {
                reread.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
                reread.RefreshCache(new[] { "nTSecurityDescriptor" });
                Assert.True(ContainsOurRule(reread.ObjectSecurity, identity, objectType));
            }

            var after = ReadOurNonDaclSections();
            Assert.Equal(before.Owner, after.Owner);
            Assert.Equal(before.Group, after.Group);
            Assert.Equal(before.Sacl, after.Sacl);
        }
        finally
        {
            RemoveOurRule(rule);
            using var restored = OurEntry();
            restored.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
            restored.RefreshCache(new[] { "nTSecurityDescriptor" });
            Assert.False(ContainsOurRule(restored.ObjectSecurity, identity, objectType));
        }
    }

    private CacheResult ExerciseMicrosoftCaching(bool usePropertyCache)
    {
        var objectType = Guid.NewGuid();
        var identity = ReadMicrosoftObjectSid();
        var rule = new Ms.ActiveDirectoryAccessRule(
            identity,
            Ms.ActiveDirectoryRights.ReadProperty,
            AccessControlType.Allow,
            objectType,
            Ms.ActiveDirectorySecurityInheritance.None);

        try
        {
            using var entry = MicrosoftEntry();
            entry.Options!.SecurityMasks = Ms.SecurityMasks.Dacl;
            entry.UsePropertyCache = usePropertyCache;
            var security = entry.ObjectSecurity;
            security.AddAccessRule(rule);
            entry.ObjectSecurity = security;

            var visibleBeforeCommit = MicrosoftContainsRule(identity, objectType);
            if (usePropertyCache)
            {
                entry.CommitChanges();
            }

            return new CacheResult(visibleBeforeCommit, MicrosoftContainsRule(identity, objectType));
        }
        finally
        {
            RemoveMicrosoftRule(rule);
        }
    }

    private CacheResult ExerciseOurCaching(bool usePropertyCache)
    {
        var objectType = Guid.NewGuid();
        var identity = ReadOurObjectSid();
        var rule = new Ours.ActiveDirectoryAccessRule(
            identity,
            Ours.ActiveDirectoryRights.ReadProperty,
            AccessControlType.Allow,
            objectType,
            Ours.ActiveDirectorySecurityInheritance.None);

        try
        {
            using var entry = OurEntry();
            entry.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
            entry.UsePropertyCache = usePropertyCache;
            var security = entry.ObjectSecurity;
            security.AddAccessRule(rule);
            entry.ObjectSecurity = security;

            var visibleBeforeCommit = OurContainsRule(identity, objectType);
            if (usePropertyCache)
            {
                entry.CommitChanges();
            }

            return new CacheResult(visibleBeforeCommit, OurContainsRule(identity, objectType));
        }
        finally
        {
            RemoveOurRule(rule);
        }
    }

    private SecurityIdentifier ReadMicrosoftObjectSid()
    {
        using var entry = MicrosoftEntry();
        return new SecurityIdentifier((byte[])entry.Properties["objectSid"].Value!, 0);
    }

    private SecurityIdentifier ReadOurObjectSid()
    {
        using var entry = OurEntry();
        return new SecurityIdentifier((byte[])entry.Properties["objectSid"].Value!, 0);
    }

    private bool MicrosoftContainsRule(SecurityIdentifier identity, Guid objectType)
    {
        using var entry = MicrosoftEntry();
        entry.Options!.SecurityMasks = Ms.SecurityMasks.Dacl;
        return entry.ObjectSecurity.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<Ms.ActiveDirectoryAccessRule>()
            .Any(rule => RuleMatches(rule.IdentityReference, rule.ActiveDirectoryRights,
                rule.AccessControlType, rule.ObjectType, identity, objectType));
    }

    private bool OurContainsRule(SecurityIdentifier identity, Guid objectType)
    {
        using var entry = OurEntry();
        entry.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
        return ContainsOurRule(entry.ObjectSecurity, identity, objectType);
    }

    private static bool ContainsOurRule(
        Ours.ActiveDirectorySecurity security,
        SecurityIdentifier identity,
        Guid objectType) =>
        security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<Ours.ActiveDirectoryAccessRule>()
            .Any(rule => RuleMatches(rule.IdentityReference, rule.ActiveDirectoryRights,
                rule.AccessControlType, rule.ObjectType, identity, objectType));

    private static bool RuleMatches(
        IdentityReference actualIdentity,
        object actualRights,
        AccessControlType actualType,
        Guid actualObjectType,
        SecurityIdentifier expectedIdentity,
        Guid expectedObjectType) =>
        actualIdentity.Equals(expectedIdentity) &&
        Convert.ToInt32(actualRights) == (int)Ours.ActiveDirectoryRights.ReadProperty &&
        actualType == AccessControlType.Allow &&
        actualObjectType == expectedObjectType;

    private void RemoveMicrosoftRule(Ms.ActiveDirectoryAccessRule rule)
    {
        using var entry = MicrosoftEntry();
        entry.Options!.SecurityMasks = Ms.SecurityMasks.Dacl;
        var security = entry.ObjectSecurity;
        security.RemoveAccessRuleSpecific(rule);
        entry.ObjectSecurity = security;
        entry.CommitChanges();
    }

    private void RemoveOurRule(Ours.ActiveDirectoryAccessRule rule)
    {
        using var entry = OurEntry();
        entry.Options.SecurityMasks = Ours.SecurityMasks.Dacl;
        var security = entry.ObjectSecurity;
        security.RemoveAccessRuleSpecific(rule);
        entry.ObjectSecurity = security;
        entry.CommitChanges();
    }

    private SecuritySections ReadOurNonDaclSections()
    {
        using var entry = OurEntry();
        entry.Options.SecurityMasks =
            Ours.SecurityMasks.Owner | Ours.SecurityMasks.Group | Ours.SecurityMasks.Sacl;
        var security = entry.ObjectSecurity;
        return new SecuritySections(
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner),
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Group),
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Audit));
    }

    private Ms.DirectoryEntry MicrosoftEntry() =>
        new(DifferentialSettings.PathFor(_data.ObjectDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.UseTls
                ? Ms.AuthenticationTypes.SecureSocketsLayer
                : Ms.AuthenticationTypes.None);

    private Ours.DirectoryEntry OurEntry() =>
        new(DifferentialSettings.PathFor(_data.ObjectDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.UseTls
                ? Ours.AuthenticationTypes.SecureSocketsLayer
                : Ours.AuthenticationTypes.None);

    private sealed record CacheResult(bool VisibleBeforeCommit, bool VisibleAfterCommit);

    private sealed record SecuritySections(string Owner, string Group, string Sacl);
}

/// <summary>Creates one passwordless, disposable AD object for ACL mutation tests.</summary>
public sealed class ObjectSecurityTestFixture : IDisposable
{
    public ObjectSecurityTestFixture()
    {
        var name = $"adfl-d-acl-{Guid.NewGuid():N}";
        ObjectDn = $"CN={name},{DifferentialSettings.UsersContainer}";

        using var container = Open(DifferentialSettings.UsersContainer);
        using var child = container.Children.Add($"CN={name}", "group");
        child.Properties["sAMAccountName"].Value = name;
        child.CommitChanges();
    }

    public string ObjectDn { get; }

    public void Dispose()
    {
        try
        {
            using var entry = Open(ObjectDn);
            entry.DeleteTree();
        }
        catch
        {
            // Best-effort cleanup if setup or a test failed midway.
        }
    }

    private static Ours.DirectoryEntry Open(string dn) =>
        new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.UseTls
                ? Ours.AuthenticationTypes.SecureSocketsLayer
                : Ours.AuthenticationTypes.None);
}
