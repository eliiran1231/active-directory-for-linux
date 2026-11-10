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
        foreach (var optionName in Enum.GetNames<Ms.ContextOptions>())
        {
            Assert.True(Enum.TryParse<Ours.ContextOptions>(optionName, out var ourOption));
            Assert.Equal(
                SuiteCapture.Expected((int)Enum.Parse<Ms.ContextOptions>(optionName), "assert-equal-expected", 16),
                SuiteCapture.Expected((int)ourOption, "assert-equal-actual", 16));
        }

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
        Assert.Equal(SuiteCapture.Expected(microsoftOptions!.CanWrite, "assert-equal-expected", 37), SuiteCapture.Expected(ourOptions!.CanWrite, "assert-equal-actual", 37));

        var microsoftContext = typeof(Ms.PrincipalSearcher).GetProperty(
            nameof(Ms.PrincipalSearcher.Context));
        var ourContext = typeof(Ours.PrincipalSearcher).GetProperty(
            nameof(Ours.PrincipalSearcher.Context));
        Assert.NotNull(microsoftContext);
        Assert.NotNull(ourContext);
        Assert.Equal(SuiteCapture.Expected(microsoftContext!.CanRead, "assert-equal-expected", 45), SuiteCapture.Expected(ourContext!.CanRead, "assert-equal-actual", 45));
        Assert.Equal(SuiteCapture.Expected(microsoftContext.CanWrite, "assert-equal-expected", 46), SuiteCapture.Expected(ourContext.CanWrite, "assert-equal-actual", 46));

        var microsoftUnderlying = typeof(Ms.PrincipalSearcher).GetMethod(
            nameof(Ms.PrincipalSearcher.GetUnderlyingSearcher), Type.EmptyTypes);
        var ourUnderlying = typeof(Ours.PrincipalSearcher).GetMethod(
            nameof(Ours.PrincipalSearcher.GetUnderlyingSearcher), Type.EmptyTypes);
        Assert.Equal(SuiteCapture.Expected(microsoftUnderlying!.ReturnType, "assert-equal-expected", 52), SuiteCapture.Expected(ourUnderlying!.ReturnType, "assert-equal-actual", 52));

        var microsoftType = typeof(Ms.PrincipalSearcher).GetMethod(
            nameof(Ms.PrincipalSearcher.GetUnderlyingSearcherType), Type.EmptyTypes);
        var ourType = typeof(Ours.PrincipalSearcher).GetMethod(
            nameof(Ours.PrincipalSearcher.GetUnderlyingSearcherType), Type.EmptyTypes);
        Assert.Equal(SuiteCapture.Expected(microsoftType!.ReturnType, "assert-equal-expected", 58), SuiteCapture.Expected(ourType!.ReturnType, "assert-equal-actual", 58));
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
            Assert.Equal(SuiteCapture.Expected(microsoft.CanRead, "assert-equal-expected", 79), SuiteCapture.Expected(ours.CanRead, "assert-equal-actual", 79));
            Assert.Equal(SuiteCapture.Expected(microsoft.CanWrite, "assert-equal-expected", 80), SuiteCapture.Expected(ours.CanWrite, "assert-equal-actual", 80));
            Assert.Equal(SuiteCapture.Expected(microsoft.PropertyType.IsArray, "assert-equal-expected", 81), SuiteCapture.Expected(ours.PropertyType.IsArray, "assert-equal-actual", 81));
            Assert.Equal(SuiteCapture.Expected(microsoft.PropertyType.IsGenericType, "assert-equal-expected", 82), SuiteCapture.Expected(ours.PropertyType.IsGenericType, "assert-equal-actual", 82));
            Assert.Equal(SuiteCapture.Expected(typeof(Ms.AuthenticablePrincipal), "assert-equal-expected", 83), SuiteCapture.Expected(microsoft.DeclaringType, "assert-equal-actual", 83));
            Assert.Equal(SuiteCapture.Expected(typeof(Ours.AuthenticablePrincipal), "assert-equal-expected", 84), SuiteCapture.Expected(ours.DeclaringType, "assert-equal-actual", 84));
        }

        Assert.Equal(SuiteCapture.Expected(typeof(byte[]), "assert-equal-expected", 87), SuiteCapture.Expected(typeof(Ours.AuthenticablePrincipal)
            .GetProperty(nameof(Ours.AuthenticablePrincipal.PermittedLogonTimes))!.PropertyType, "assert-equal-actual", 87));
        Assert.Equal(SuiteCapture.Expected(typeof(System.Security.Cryptography.X509Certificates.X509Certificate2Collection), "assert-equal-expected", 89),
            SuiteCapture.Expected(typeof(Ours.AuthenticablePrincipal)
                .GetProperty(nameof(Ours.AuthenticablePrincipal.Certificates))!.PropertyType, "assert-equal-actual", 89));
        Assert.Equal(SuiteCapture.Expected(typeof(Ours.PrincipalValueCollection<string>), "assert-equal-expected", 92), SuiteCapture.Expected(typeof(Ours.AuthenticablePrincipal)
            .GetProperty(nameof(Ours.AuthenticablePrincipal.PermittedWorkstations))!.PropertyType, "assert-equal-actual", 92));

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
            SuiteCapture.Expected(typeof(Ms.Principal).GetProperty(nameof(Ms.Principal.Sid))!.PropertyType, "assert-equal-expected", 152),
            SuiteCapture.Expected(PortableSecurityContract.Map(typeof(Ours.Principal).GetProperty(nameof(Ours.Principal.Sid))!.PropertyType), "assert-equal-actual", 152));
        Assert.Equal(
            SuiteCapture.Expected(typeof(Ms.Principal), "assert-equal-expected", 155),
            SuiteCapture.Expected(typeof(Ms.Principal).GetMethod(nameof(object.Equals), new[] { typeof(object) })!.DeclaringType, "assert-equal-actual", 155));
        Assert.Equal(
            SuiteCapture.Expected(typeof(Ours.Principal), "assert-equal-expected", 158),
            SuiteCapture.Expected(typeof(Ours.Principal).GetMethod(nameof(object.Equals), new[] { typeof(object) })!.DeclaringType, "assert-equal-actual", 158));
        Assert.Equal(
            SuiteCapture.Expected(typeof(Ms.Principal), "assert-equal-expected", 161),
            SuiteCapture.Expected(typeof(Ms.Principal).GetMethod(nameof(object.GetHashCode), Type.EmptyTypes)!.DeclaringType, "assert-equal-actual", 161));
        Assert.Equal(
            SuiteCapture.Expected(typeof(Ours.Principal), "assert-equal-expected", 164),
            SuiteCapture.Expected(typeof(Ours.Principal).GetMethod(nameof(object.GetHashCode), Type.EmptyTypes)!.DeclaringType, "assert-equal-actual", 164));
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
        Assert.Equal(SuiteCapture.Expected(microsoft!.IsStatic, "assert-equal-expected", 179), SuiteCapture.Expected(ours!.IsStatic, "assert-equal-actual", 179));
        Assert.Equal(SuiteCapture.Expected(microsoft.IsPublic, "assert-equal-expected", 180), SuiteCapture.Expected(ours.IsPublic, "assert-equal-actual", 180));
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
        Assert.Equal(SuiteCapture.Expected(microsoft!.IsStatic, "assert-equal-expected", 194), SuiteCapture.Expected(ours!.IsStatic, "assert-equal-actual", 194));
        Assert.Equal(SuiteCapture.Expected(microsoft.IsFamily, "assert-equal-expected", 195), SuiteCapture.Expected(ours.IsFamily, "assert-equal-actual", 195));
    }
}
