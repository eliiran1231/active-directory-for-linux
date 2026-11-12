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

        Assert.Equal(SuiteCapture.Expected(microsoftContextRaw.CanRead, "assert-equal-expected", 88), SuiteCapture.Expected(ourContextRaw.CanRead, "assert-equal-actual", 88));
        Assert.Equal(SuiteCapture.Expected(microsoftContextRaw.CanWrite, "assert-equal-expected", 89), SuiteCapture.Expected(ourContextRaw.CanWrite, "assert-equal-actual", 89));
        Assert.Equal(SuiteCapture.Expected(microsoftContextRaw.GetMethod!.IsFamilyOrAssembly, "assert-equal-expected", 90),
            SuiteCapture.Expected(ourContextRaw.GetMethod!.IsFamilyOrAssembly, "assert-equal-actual", 90));
        Assert.Equal(SuiteCapture.Expected(microsoftContextRaw.SetMethod!.IsFamilyOrAssembly, "assert-equal-expected", 92),
            SuiteCapture.Expected(ourContextRaw.SetMethod!.IsFamilyOrAssembly, "assert-equal-actual", 92));

        Assert.Equal(
            SuiteCapture.Expected(typeof(Ms.Principal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes) is not null, "assert-equal-expected", 95),
            SuiteCapture.Expected(typeof(Ours.Principal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes) is not null, "assert-equal-actual", 95));
        Assert.Equal(
            SuiteCapture.Expected(typeof(Ms.UserPrincipal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes)!.DeclaringType, "assert-equal-expected", 98),
            SuiteCapture.Expected(typeof(Ours.UserPrincipal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes)!.DeclaringType == typeof(Ours.UserPrincipal)
                ? typeof(Ms.UserPrincipal)
                : null, "assert-equal-actual", 98));

        var microsoftProperty = new Ms.DirectoryPropertyAttribute("description")
        {
            Context = Ms.ContextType.Domain,
        };
        var ourProperty = new Ours.DirectoryPropertyAttribute("description")
        {
            Context = Ours.ContextType.Domain,
        };
        Assert.Equal(SuiteCapture.Expected(microsoftProperty.Context?.ToString(), "assert-equal-expected", 112), SuiteCapture.Expected(ourProperty.Context?.ToString(), "assert-equal-actual", 112));
    }

    [Fact]
    public void Custom_creation_round_trip_identity_QBE_and_ToString_match_microsoft()
    {
        if (!DifferentialSettings.HasIsolatedBaseDn)
        {
            throw Xunit.Sdk.SkipException.ForSkip(
                "Set AD_BASE_DN to an isolated writable OU before running this test.");
        }

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var microsoftName = $"i44-ms-{suffix}";
        var ourName = $"i44-our-{suffix}";

        var microsoft = ExerciseMicrosoft(microsoftName);
        var ours = ExerciseOurs(ourName);

        Assert.Equal(SuiteCapture.Expected(microsoft.RdnPrefix, "assert-equal-expected", 131), SuiteCapture.Expected(ours.RdnPrefix, "assert-equal-actual", 131));
        Assert.Equal(SuiteCapture.Expected(microsoft.StructuralObjectClass, "assert-equal-expected", 132), SuiteCapture.Expected(ours.StructuralObjectClass, "assert-equal-actual", 132));
        Assert.Equal(SuiteCapture.Expected(microsoft.HasDeclaredObjectClass, "assert-equal-expected", 133), SuiteCapture.Expected(ours.HasDeclaredObjectClass, "assert-equal-actual", 133));
        Assert.Equal(SuiteCapture.Expected(microsoft.Badge, "assert-equal-expected", 134), SuiteCapture.Expected(ours.Badge, "assert-equal-actual", 134));
        Assert.Equal(SuiteCapture.Expected(microsoft.PhoneNumbers, "assert-equal-expected", 135), SuiteCapture.Expected(ours.PhoneNumbers, "assert-equal-actual", 135));
        Assert.Equal(SuiteCapture.Expected(microsoft.IdentityResultType, "assert-equal-expected", 136), SuiteCapture.Expected(ours.IdentityResultType, "assert-equal-actual", 136));
        Assert.Equal(SuiteCapture.Expected(microsoft.QueryResultType, "assert-equal-expected", 137), SuiteCapture.Expected(ours.QueryResultType, "assert-equal-actual", 137));
        Assert.Equal(SuiteCapture.Expected(microsoft.StringValue, "assert-equal-expected", 138), SuiteCapture.Expected(ours.StringValue, "assert-equal-actual", 138));
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
            Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 180), SuiteCapture.Expected(found.ToString(), "assert-equal-actual", 180));

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
            Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 233), SuiteCapture.Expected(found.ToString(), "assert-equal-actual", 233));

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
