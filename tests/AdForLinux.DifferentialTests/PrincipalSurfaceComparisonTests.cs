using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class PrincipalSurfaceComparisonTests
{
    [Fact]
    public void PrincipalContext_and_searcher_issue_11_surface_matches_microsoft()
    {
        Assert.NotNull(typeof(Ours.PrincipalContext).GetConstructor(new[]
        {
            typeof(Ours.ContextType), typeof(string), typeof(string), typeof(string),
        }));
        Assert.NotNull(typeof(Ours.PrincipalContext).GetConstructor(new[]
        {
            typeof(Ours.ContextType), typeof(string), typeof(string), typeof(Ours.ContextOptions),
        }));
        Assert.NotNull(typeof(Ours.PrincipalContext).GetMethod(
            nameof(Ours.PrincipalContext.ValidateCredentials),
            new[] { typeof(string), typeof(string), typeof(Ours.ContextOptions) }));

        var microsoftOptions = typeof(Ms.PrincipalContext).GetProperty(nameof(Ms.PrincipalContext.Options));
        var ourOptions = typeof(Ours.PrincipalContext).GetProperty(nameof(Ours.PrincipalContext.Options));
        Assert.NotNull(microsoftOptions);
        Assert.NotNull(ourOptions);
        Assert.Equal(microsoftOptions!.CanWrite, ourOptions!.CanWrite);

        var microsoftContext = typeof(Ms.PrincipalSearcher).GetProperty(
            nameof(Ms.PrincipalSearcher.Context));
        var ourContext = typeof(Ours.PrincipalSearcher).GetProperty(
            nameof(Ours.PrincipalSearcher.Context));
        Assert.NotNull(microsoftContext);
        Assert.NotNull(ourContext);
        Assert.Equal(microsoftContext!.CanRead, ourContext!.CanRead);
        Assert.Equal(microsoftContext.CanWrite, ourContext.CanWrite);

        var microsoftUnderlying = typeof(Ms.PrincipalSearcher).GetMethod(
            nameof(Ms.PrincipalSearcher.GetUnderlyingSearcher), Type.EmptyTypes);
        var ourUnderlying = typeof(Ours.PrincipalSearcher).GetMethod(
            nameof(Ours.PrincipalSearcher.GetUnderlyingSearcher), Type.EmptyTypes);
        Assert.Equal(microsoftUnderlying!.ReturnType, ourUnderlying!.ReturnType);

        var microsoftType = typeof(Ms.PrincipalSearcher).GetMethod(
            nameof(Ms.PrincipalSearcher.GetUnderlyingSearcherType), Type.EmptyTypes);
        var ourType = typeof(Ours.PrincipalSearcher).GetMethod(
            nameof(Ours.PrincipalSearcher.GetUnderlyingSearcherType), Type.EmptyTypes);
        Assert.Equal(microsoftType!.ReturnType, ourType!.ReturnType);
    }

    [Fact]
    public void AuthenticablePrincipal_issue_8_surface_matches_microsoft()
    {
        var propertyNames = new[]
        {
            nameof(Ms.AuthenticablePrincipal.AllowReversiblePasswordEncryption),
            nameof(Ms.AuthenticablePrincipal.Certificates),
            nameof(Ms.AuthenticablePrincipal.PermittedLogonTimes),
            nameof(Ms.AuthenticablePrincipal.PermittedWorkstations),
            nameof(Ms.AuthenticablePrincipal.SmartcardLogonRequired),
            nameof(Ms.AuthenticablePrincipal.UserCannotChangePassword),
        };
        foreach (var propertyName in propertyNames)
        {
            var microsoft = typeof(Ms.AuthenticablePrincipal).GetProperty(propertyName)!;
            var ours = typeof(Ours.AuthenticablePrincipal).GetProperty(propertyName)!;
            Assert.NotNull(microsoft);
            Assert.NotNull(ours);
            Assert.Equal(microsoft.CanRead, ours.CanRead);
            Assert.Equal(microsoft.CanWrite, ours.CanWrite);
            Assert.Equal(microsoft.PropertyType.IsArray, ours.PropertyType.IsArray);
            Assert.Equal(microsoft.PropertyType.IsGenericType, ours.PropertyType.IsGenericType);
            Assert.Equal(typeof(Ms.AuthenticablePrincipal), microsoft.DeclaringType);
            Assert.Equal(typeof(Ours.AuthenticablePrincipal), ours.DeclaringType);
        }

        Assert.Equal(typeof(byte[]), typeof(Ours.AuthenticablePrincipal)
            .GetProperty(nameof(Ours.AuthenticablePrincipal.PermittedLogonTimes))!.PropertyType);
        Assert.Equal(typeof(System.Security.Cryptography.X509Certificates.X509Certificate2Collection),
            typeof(Ours.AuthenticablePrincipal)
                .GetProperty(nameof(Ours.AuthenticablePrincipal.Certificates))!.PropertyType);
        Assert.Equal(typeof(Ours.PrincipalValueCollection<string>), typeof(Ours.AuthenticablePrincipal)
            .GetProperty(nameof(Ours.AuthenticablePrincipal.PermittedWorkstations))!.PropertyType);

        Assert.NotNull(typeof(Ours.AuthenticablePrincipal).GetMethod(
            nameof(Ms.AuthenticablePrincipal.ChangePassword),
            new[] { typeof(string), typeof(string) }));
        Assert.NotNull(typeof(Ours.AuthenticablePrincipal).GetMethod(
            nameof(Ms.AuthenticablePrincipal.RefreshExpiredPassword),
            Type.EmptyTypes));
    }

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
