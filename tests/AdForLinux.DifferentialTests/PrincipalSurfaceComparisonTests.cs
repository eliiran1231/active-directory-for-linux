using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class PrincipalSurfaceComparisonTests
{
    [Fact]
    public void Principal_issue_7_surface_matches_microsoft()
    {
        AssertPublicMethodPair(
            nameof(Ms.Principal.FindByIdentity),
            new[] { typeof(Ms.PrincipalContext), typeof(string) },
            new[] { typeof(Ours.PrincipalContext), typeof(string) });
        AssertPublicMethodPair(
            nameof(Ms.Principal.FindByIdentity),
            new[] { typeof(Ms.PrincipalContext), typeof(Ms.IdentityType), typeof(string) },
            new[] { typeof(Ours.PrincipalContext), typeof(Ours.IdentityType), typeof(string) });
        AssertPublicMethodPair(
            nameof(Ms.Principal.Save),
            new[] { typeof(Ms.PrincipalContext) },
            new[] { typeof(Ours.PrincipalContext) });
        AssertPublicMethodPair(
            nameof(Ms.Principal.GetGroups),
            new[] { typeof(Ms.PrincipalContext) },
            new[] { typeof(Ours.PrincipalContext) });
        AssertPublicMethodPair(
            nameof(Ms.Principal.IsMemberOf),
            new[] { typeof(Ms.GroupPrincipal) },
            new[] { typeof(Ours.GroupPrincipal) });
        AssertPublicMethodPair(
            nameof(Ms.Principal.IsMemberOf),
            new[] { typeof(Ms.PrincipalContext), typeof(Ms.IdentityType), typeof(string) },
            new[] { typeof(Ours.PrincipalContext), typeof(Ours.IdentityType), typeof(string) });

        AssertProtectedMethodPair(
            "FindByIdentityWithType",
            new[] { typeof(Ms.PrincipalContext), typeof(Type), typeof(string) },
            new[] { typeof(Ours.PrincipalContext), typeof(Type), typeof(string) });
        AssertProtectedMethodPair(
            "FindByIdentityWithType",
            new[] { typeof(Ms.PrincipalContext), typeof(Type), typeof(Ms.IdentityType), typeof(string) },
            new[] { typeof(Ours.PrincipalContext), typeof(Type), typeof(Ours.IdentityType), typeof(string) });
        AssertProtectedMethodPair(
            "ExtensionGet",
            new[] { typeof(string) },
            new[] { typeof(string) });
        AssertProtectedMethodPair(
            "ExtensionSet",
            new[] { typeof(string), typeof(object) },
            new[] { typeof(string), typeof(object) });
        AssertProtectedMethodPair(
            "CheckDisposedOrDeleted",
            Type.EmptyTypes,
            Type.EmptyTypes);

        Assert.Equal(
            typeof(Ms.Principal).GetProperty(nameof(Ms.Principal.Sid))!.PropertyType,
            typeof(Ours.Principal).GetProperty(nameof(Ours.Principal.Sid))!.PropertyType);
        Assert.Equal(
            typeof(Ms.Principal),
            typeof(Ms.Principal).GetMethod(nameof(object.Equals), new[] { typeof(object) })!.DeclaringType);
        Assert.Equal(
            typeof(Ours.Principal),
            typeof(Ours.Principal).GetMethod(nameof(object.Equals), new[] { typeof(object) })!.DeclaringType);
        Assert.Equal(
            typeof(Ms.Principal),
            typeof(Ms.Principal).GetMethod(nameof(object.GetHashCode), Type.EmptyTypes)!.DeclaringType);
        Assert.Equal(
            typeof(Ours.Principal),
            typeof(Ours.Principal).GetMethod(nameof(object.GetHashCode), Type.EmptyTypes)!.DeclaringType);
    }

    private static void AssertPublicMethodPair(
        string name,
        Type[] microsoftParameters,
        Type[] ourParameters)
    {
        var microsoft = typeof(Ms.Principal).GetMethod(name, microsoftParameters);
        var ours = typeof(Ours.Principal).GetMethod(name, ourParameters);

        Assert.NotNull(microsoft);
        Assert.NotNull(ours);
        Assert.Equal(microsoft!.IsStatic, ours!.IsStatic);
        Assert.Equal(microsoft.IsPublic, ours.IsPublic);
    }

    private static void AssertProtectedMethodPair(
        string name,
        Type[] microsoftParameters,
        Type[] ourParameters)
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.Instance | BindingFlags.NonPublic;
        var microsoft = typeof(Ms.Principal).GetMethod(name, flags, microsoftParameters);
        var ours = typeof(Ours.Principal).GetMethod(name, flags, ourParameters);

        Assert.NotNull(microsoft);
        Assert.NotNull(ours);
        Assert.Equal(microsoft!.IsStatic, ours!.IsStatic);
        Assert.Equal(microsoft.IsFamily, ours.IsFamily);
    }
}
