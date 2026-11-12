using Xunit;

namespace AdForLinux.DifferentialTests;

public class PortableSecurityContractTests
{
    [Fact]
    public void Exported_portable_security_types_are_exactly_the_approved_substitutions()
    {
        var exported = typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly.GetExportedTypes();
        Assert.Equal(SuiteCapture.Expected(PortableSecurityContract.Types.Keys.Select(t => t.FullName).Order(), "assert-equal-expected", 11),
            SuiteCapture.Expected(exported.Where(t => t.Namespace is "AdForLinux.Security.Principal" or "AdForLinux.Security.AccessControl")
                .Select(t => t.FullName).Order(), "assert-equal-actual", 11));
        Assert.Contains(typeof(AdForLinux.DirectoryServices.DirectoryIdentityResolver), exported);
    }

    [Fact]
    public void Unapproved_names_and_framework_enums_are_not_substituted()
    {
        const string future = "AdForLinux.Security.AccessControl.FuturePublicHelper";
        Assert.Equal(SuiteCapture.Expected(future, "assert-equal-expected", 21), SuiteCapture.Expected(PortableSecurityContract.NormalizeName(future), "assert-equal-actual", 21));
        Assert.Same(typeof(System.Security.AccessControl.AceFlags), PortableSecurityContract.Map(typeof(System.Security.AccessControl.AceFlags)));
    }

    [Fact]
    public void Approved_identity_helper_exports_only_the_exact_factory_and_translation_contract()
    {
        var type = typeof(AdForLinux.DirectoryServices.DirectoryIdentityResolver);
        const System.Reflection.BindingFlags declared = System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance
            | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.DeclaredOnly;
        Assert.True(type.IsPublic); Assert.True(type.IsSealed); Assert.False(type.IsAbstract);
        Assert.Equal(SuiteCapture.Expected(typeof(object), "assert-equal-expected", 32), SuiteCapture.Expected(type.BaseType, "assert-equal-actual", 32)); Assert.Empty(type.GetInterfaces());
        Assert.Empty(type.GetConstructors()); Assert.Empty(type.GetProperties(declared));
        Assert.All(type.GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic),
            ctor => Assert.True(ctor.IsPrivate || ctor.IsAssembly));
        Assert.DoesNotContain(type.GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.DeclaredOnly),
            method => method.IsFamily || method.IsFamilyOrAssembly || method.IsFamilyAndAssembly);
        Assert.Empty(type.GetFields(declared)); Assert.Empty(type.GetEvents(declared));
        var methods = type.GetMethods(declared);
        Assert.Equal(SuiteCapture.Expected(3, "assert-equal-expected", 40), SuiteCapture.Expected(methods.Length, "assert-equal-actual", 40));
        var factory = type.GetMethod("ForEntry", [typeof(AdForLinux.DirectoryServices.DirectoryEntry)])!;
        Assert.True(factory.IsStatic); Assert.Equal(SuiteCapture.Expected(type, "assert-equal-expected", 42), SuiteCapture.Expected(factory.ReturnType, "assert-equal-actual", 42));
        Assert.Equal(SuiteCapture.Expected("entry", "assert-equal-expected", 43), SuiteCapture.Expected(Assert.Single(factory.GetParameters()).Name, "assert-equal-actual", 43));
        var single = type.GetMethod("Translate", [typeof(AdForLinux.Security.Principal.IdentityReference), typeof(Type)])!;
        Assert.Equal(SuiteCapture.Expected(typeof(AdForLinux.Security.Principal.IdentityReference), "assert-equal-expected", 45), SuiteCapture.Expected(single.ReturnType, "assert-equal-actual", 45));
        Assert.Equal(SuiteCapture.Expected(new[] { "identity", "targetType" }, "assert-equal-expected", 46), SuiteCapture.Expected(single.GetParameters().Select(p => p.Name), "assert-equal-actual", 46));
        var collection = type.GetMethod("Translate", [typeof(AdForLinux.Security.Principal.IdentityReferenceCollection), typeof(Type), typeof(bool)])!;
        Assert.Equal(SuiteCapture.Expected(typeof(AdForLinux.Security.Principal.IdentityReferenceCollection), "assert-equal-expected", 48), SuiteCapture.Expected(collection.ReturnType, "assert-equal-actual", 48));
        Assert.Equal(SuiteCapture.Expected(new[] { "identities", "targetType", "forceSuccess" }, "assert-equal-expected", 49), SuiteCapture.Expected(collection.GetParameters().Select(p => p.Name), "assert-equal-actual", 49));
        Assert.True(collection.GetParameters()[2].IsOptional); Assert.Equal(SuiteCapture.Expected(false, "assert-equal-expected", 50), SuiteCapture.Expected(collection.GetParameters()[2].DefaultValue, "assert-equal-actual", 50));
        var nullable = new System.Reflection.NullabilityInfoContext();
        foreach (var method in methods)
        {
            Assert.False(method.IsVirtual); Assert.False(method.IsGenericMethod); Assert.True(method.IsPublic);
            Assert.Equal(SuiteCapture.Expected(System.Reflection.NullabilityState.NotNull, "assert-equal-expected", 55), SuiteCapture.Expected(nullable.Create(method.ReturnParameter).ReadState, "assert-equal-actual", 55));
            Assert.All(method.GetParameters(), p => Assert.Equal(SuiteCapture.Expected(System.Reflection.NullabilityState.NotNull, "assert-equal-expected", 56), SuiteCapture.Expected(nullable.Create(p).ReadState, "assert-equal-actual", 56)));
        }
        Assert.False(single.IsStatic); Assert.False(collection.IsStatic);
        Assert.Null(type.GetMethod("Bind", declared)); Assert.Null(type.GetMethod("ForBinding", declared));
        Assert.True(type.GetMethod("Bind", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.IsAssembly);
        var contextFactory = typeof(AdForLinux.DirectoryServices.AccountManagement.PrincipalContext).GetMethod("CreateIdentityResolver", Type.EmptyTypes)!;
        Assert.True(contextFactory.IsPublic); Assert.False(contextFactory.IsStatic); Assert.False(contextFactory.IsVirtual);
        Assert.Equal(SuiteCapture.Expected(type, "assert-equal-expected", 63), SuiteCapture.Expected(contextFactory.ReturnType, "assert-equal-actual", 63));
        Assert.Equal(SuiteCapture.Expected(System.Reflection.NullabilityState.NotNull, "assert-equal-expected", 64), SuiteCapture.Expected(nullable.Create(contextFactory.ReturnParameter).ReadState, "assert-equal-actual", 64));
    }
}
