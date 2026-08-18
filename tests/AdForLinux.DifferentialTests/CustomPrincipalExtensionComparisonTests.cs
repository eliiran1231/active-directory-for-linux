using System.DirectoryServices;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class CustomPrincipalExtensionComparisonTests
{
    [Ms.DirectoryObjectClass("inetOrgPerson")]
    [Ms.DirectoryRdnPrefix("CN")]
    private sealed class MicrosoftCustomUser : Ms.UserPrincipal
    {
        public MicrosoftCustomUser(Ms.PrincipalContext context) : base(context) { }

        [Ms.DirectoryProperty("description")]
        public string? Badge
        {
            get => ExtensionGet("description").FirstOrDefault()?.ToString();
            set => ExtensionSet("description", value!);
        }

        [Ms.DirectoryProperty("otherTelephone")]
        public string[] PhoneNumbers
        {
            get => ExtensionGet("otherTelephone").Select(value => value.ToString()!).ToArray();
            set => ExtensionSet("otherTelephone", value);
        }

        public Ms.PrincipalContext RawContext
        {
            get => ContextRaw;
            set => ContextRaw = value;
        }

        public static MicrosoftCustomUser? Find(
            Ms.PrincipalContext context,
            Ms.IdentityType identityType,
            string identity) =>
            (MicrosoftCustomUser?)FindByIdentityWithType(
                context, typeof(MicrosoftCustomUser), identityType, identity);
    }

    [Ours.DirectoryObjectClass("inetOrgPerson")]
    [Ours.DirectoryRdnPrefix("CN")]
    private sealed class OurCustomUser : Ours.UserPrincipal
    {
        public OurCustomUser(Ours.PrincipalContext context) : base(context) { }

        [Ours.DirectoryProperty("description")]
        public string? Badge
        {
            get => ExtensionGet("description").FirstOrDefault()?.ToString();
            set => ExtensionSet("description", value);
        }

        [Ours.DirectoryProperty("otherTelephone")]
        public string[] PhoneNumbers
        {
            get => ExtensionGet("otherTelephone").Select(value => value!.ToString()!).ToArray();
            set => ExtensionSet("otherTelephone", value);
        }

        public Ours.PrincipalContext RawContext
        {
            get => ContextRaw;
            set => ContextRaw = value;
        }

        public static OurCustomUser? Find(
            Ours.PrincipalContext context,
            Ours.IdentityType identityType,
            string identity) =>
            (OurCustomUser?)FindByIdentityWithType(
                context, typeof(OurCustomUser), identityType, identity);
    }

    [Fact]
    public void Extension_surface_matches_microsoft()
    {
        var microsoftContextRaw = typeof(Ms.Principal).GetProperty(
            "ContextRaw", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!;
        var ourContextRaw = typeof(Ours.Principal).GetProperty(
            "ContextRaw", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!;

        Assert.Equal(microsoftContextRaw.CanRead, ourContextRaw.CanRead);
        Assert.Equal(microsoftContextRaw.CanWrite, ourContextRaw.CanWrite);
        Assert.Equal(microsoftContextRaw.GetMethod!.IsFamilyOrAssembly,
            ourContextRaw.GetMethod!.IsFamilyOrAssembly);
        Assert.Equal(microsoftContextRaw.SetMethod!.IsFamilyOrAssembly,
            ourContextRaw.SetMethod!.IsFamilyOrAssembly);

        Assert.Equal(
            typeof(Ms.Principal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes) is not null,
            typeof(Ours.Principal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes) is not null);
        Assert.Equal(
            typeof(Ms.UserPrincipal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes)!.DeclaringType,
            typeof(Ours.UserPrincipal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes)!.DeclaringType == typeof(Ours.UserPrincipal)
                ? typeof(Ms.UserPrincipal)
                : null);

        var microsoftProperty = new Ms.DirectoryPropertyAttribute("description")
        {
            Context = Ms.ContextType.Domain,
        };
        var ourProperty = new Ours.DirectoryPropertyAttribute("description")
        {
            Context = Ours.ContextType.Domain,
        };
        Assert.Equal(microsoftProperty.Context?.ToString(), ourProperty.Context?.ToString());
    }

    [Fact]
    public void Custom_creation_round_trip_identity_QBE_and_ToString_match_microsoft()
    {
        Assert.Equal("OU=Issue44,OU=AoTesting,DC=adlab,DC=local", DifferentialSettings.BaseDn);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var microsoftName = $"i44-ms-{suffix}";
        var ourName = $"i44-our-{suffix}";

        var microsoft = ExerciseMicrosoft(microsoftName);
        var ours = ExerciseOurs(ourName);

        Assert.Equal(microsoft.RdnPrefix, ours.RdnPrefix);
        Assert.Equal(microsoft.StructuralObjectClass, ours.StructuralObjectClass);
        Assert.Equal(microsoft.HasDeclaredObjectClass, ours.HasDeclaredObjectClass);
        Assert.Equal(microsoft.Badge, ours.Badge);
        Assert.Equal(microsoft.PhoneNumbers, ours.PhoneNumbers);
        Assert.Equal(microsoft.IdentityResultType, ours.IdentityResultType);
        Assert.Equal(microsoft.QueryResultType, ours.QueryResultType);
        Assert.Equal(microsoft.StringValue, ours.StringValue);
        Assert.True(microsoft.ContextRawRoundTrip);
        Assert.True(ours.ContextRawRoundTrip);
    }

    private static Observation ExerciseMicrosoft(string name)
    {
        var customDn = $"CN={name},{DifferentialSettings.BaseDn}";
        var regularName = $"regular-{name}";
        var regularDn = $"CN={regularName},{DifferentialSettings.BaseDn}";
        var customUpn = $"{name}@adlab.local";
        try
        {
            CreateRegularUser(regularName, $"{regularName}@adlab.local", "issue44-badge");
            using var context = new Ms.PrincipalContext(
                Ms.ContextType.Domain,
                DifferentialSettings.ServerName,
                DifferentialSettings.BaseDn,
                DifferentialSettings.MicrosoftContextOptions,
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword);
            using (var user = new MicrosoftCustomUser(context)
            {
                Name = name,
                SamAccountName = name,
                UserPrincipalName = customUpn,
                Badge = "issue44-badge",
                PhoneNumbers = new[] { "+1 555 0101", "+1 555 0102" },
            })
            {
                Assert.Same(context, user.RawContext);
                user.RawContext = context;
                user.Save();
            }

            using var found = MicrosoftCustomUser.Find(context, Ms.IdentityType.Name, name)!;
            using var query = new MicrosoftCustomUser(context) { Badge = "issue44-badge" };
            using var searcher = new Ms.PrincipalSearcher(query);
            using var queryResult = searcher.FindOne();
            using var entry = (DirectoryEntry)found.GetUnderlyingObject();
            Assert.IsType<MicrosoftCustomUser>(found);
            Assert.IsType<MicrosoftCustomUser>(queryResult);
            Assert.Equal(name, found.ToString());

            return Observe(
                found.DistinguishedName!, found.StructuralObjectClass!,
                entry.Properties["objectClass"].Cast<object>().Select(v => v.ToString()!),
                found.Badge!, found.PhoneNumbers,
                "custom", "custom", "name",
                ReferenceEquals(context, found.RawContext));
        }
        finally
        {
            DeleteIfPresent(customDn);
            DeleteIfPresent(regularDn);
        }
    }

    private static Observation ExerciseOurs(string name)
    {
        var customDn = $"CN={name},{DifferentialSettings.BaseDn}";
        var regularName = $"regular-{name}";
        var regularDn = $"CN={regularName},{DifferentialSettings.BaseDn}";
        var customUpn = $"{name}@adlab.local";
        try
        {
            CreateRegularUser(regularName, $"{regularName}@adlab.local", "issue44-badge");
            using var context = new Ours.PrincipalContext(
                Ours.ContextType.Domain,
                DifferentialSettings.ServerName,
                DifferentialSettings.BaseDn,
                DifferentialSettings.OurContextOptions,
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword);
            using (var user = new OurCustomUser(context)
            {
                Name = name,
                SamAccountName = name,
                UserPrincipalName = customUpn,
                Badge = "issue44-badge",
                PhoneNumbers = new[] { "+1 555 0101", "+1 555 0102" },
            })
            {
                Assert.Same(context, user.RawContext);
                user.RawContext = context;
                user.Save();
            }

            using var found = OurCustomUser.Find(context, Ours.IdentityType.Name, name)!;
            using var query = new OurCustomUser(context) { Badge = "issue44-badge" };
            using var searcher = new Ours.PrincipalSearcher(query);
            using var queryResult = searcher.FindOne();
            using var entry = (AdForLinux.DirectoryServices.DirectoryEntry)found.GetUnderlyingObject()!;
            Assert.IsType<OurCustomUser>(found);
            Assert.IsType<OurCustomUser>(queryResult);
            Assert.Equal(name, found.ToString());

            return Observe(
                found.DistinguishedName!, found.StructuralObjectClass!,
                entry.Properties["objectClass"].Cast<object>().Select(v => v.ToString()!),
                found.Badge!, found.PhoneNumbers,
                "custom", "custom", "name",
                ReferenceEquals(context, found.RawContext));
        }
        finally
        {
            DeleteIfPresent(customDn);
            DeleteIfPresent(regularDn);
        }
    }

    private static Observation Observe(
        string distinguishedName,
        string structuralObjectClass,
        IEnumerable<string> objectClasses,
        string badge,
        string[] phoneNumbers,
        string identityType,
        string queryType,
        string stringValue,
        bool contextRawRoundTrip) =>
        new(
            distinguishedName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? "CN" : "other",
            structuralObjectClass,
            objectClasses.Contains("inetOrgPerson", StringComparer.OrdinalIgnoreCase),
            badge,
            phoneNumbers.Order(StringComparer.Ordinal).ToArray(),
            identityType,
            queryType,
            stringValue,
            contextRawRoundTrip);

    private static void CreateRegularUser(string name, string userPrincipalName, string badge)
    {
        using var container = Open(DifferentialSettings.BaseDn);
        using var user = container.Children.Add($"CN={name}", "user");
        user.Properties["sAMAccountName"].Value = name[..20];
        user.Properties["userPrincipalName"].Value = userPrincipalName;
        user.Properties["description"].Value = badge;
        user.CommitChanges();
    }

    private static void DeleteIfPresent(string dn)
    {
        try
        {
            using var entry = Open(dn);
            _ = entry.NativeGuid;
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }

    private static DirectoryEntry Open(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private sealed record Observation(
        string RdnPrefix,
        string StructuralObjectClass,
        bool HasDeclaredObjectClass,
        string Badge,
        string[] PhoneNumbers,
        string IdentityResultType,
        string QueryResultType,
        string StringValue,
        bool ContextRawRoundTrip);
}
