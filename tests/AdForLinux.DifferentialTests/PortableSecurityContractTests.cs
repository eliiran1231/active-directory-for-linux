using Xunit;

namespace AdForLinux.DifferentialTests;

public class PortableSecurityContractTests
{
    [Fact]
    public void Exported_portable_security_types_are_exactly_the_approved_substitutions()
    {
        var exported = typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly.GetExportedTypes();
        Assert.Equal(PortableSecurityContract.Types.Keys.Select(t => t.FullName).Order(),
            exported.Where(t => t.Namespace is "AdForLinux.Security.Principal" or "AdForLinux.Security.AccessControl")
                .Select(t => t.FullName).Order());
        Assert.Contains(typeof(AdForLinux.DirectoryServices.DirectoryIdentityResolver), exported);
    }

    [Fact]
    public void Unapproved_names_and_framework_enums_are_not_substituted()
    {
        const string future = "AdForLinux.Security.AccessControl.FuturePublicHelper";
        Assert.Equal(future, PortableSecurityContract.NormalizeName(future));
        Assert.Same(typeof(System.Security.AccessControl.AceFlags), PortableSecurityContract.Map(typeof(System.Security.AccessControl.AceFlags)));
    }

    [Fact]
    public void Approved_identity_helper_exports_only_the_exact_factory_and_translation_contract()
    {
        var type = typeof(AdForLinux.DirectoryServices.DirectoryIdentityResolver);
        const System.Reflection.BindingFlags declared = System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance
            | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.DeclaredOnly;
        Assert.True(type.IsPublic); Assert.True(type.IsSealed); Assert.False(type.IsAbstract);
        Assert.Equal(typeof(object), type.BaseType); Assert.Empty(type.GetInterfaces());
        Assert.Empty(type.GetConstructors()); Assert.Empty(type.GetProperties(declared));
        Assert.All(type.GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic),
            ctor => Assert.True(ctor.IsPrivate || ctor.IsAssembly));
        Assert.DoesNotContain(type.GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.DeclaredOnly),
            method => method.IsFamily || method.IsFamilyOrAssembly || method.IsFamilyAndAssembly);
        Assert.Empty(type.GetFields(declared)); Assert.Empty(type.GetEvents(declared));
        var methods = type.GetMethods(declared);
        Assert.Equal(3, methods.Length);
        var factory = type.GetMethod("ForEntry", [typeof(AdForLinux.DirectoryServices.DirectoryEntry)])!;
        Assert.True(factory.IsStatic); Assert.Equal(type, factory.ReturnType);
        Assert.Equal("entry", Assert.Single(factory.GetParameters()).Name);
        var single = type.GetMethod("Translate", [typeof(AdForLinux.Security.Principal.IdentityReference), typeof(Type)])!;
        Assert.Equal(typeof(AdForLinux.Security.Principal.IdentityReference), single.ReturnType);
        Assert.Equal(new[] { "identity", "targetType" }, single.GetParameters().Select(p => p.Name));
        var collection = type.GetMethod("Translate", [typeof(AdForLinux.Security.Principal.IdentityReferenceCollection), typeof(Type), typeof(bool)])!;
        Assert.Equal(typeof(AdForLinux.Security.Principal.IdentityReferenceCollection), collection.ReturnType);
        Assert.Equal(new[] { "identities", "targetType", "forceSuccess" }, collection.GetParameters().Select(p => p.Name));
        Assert.True(collection.GetParameters()[2].IsOptional); Assert.Equal(false, collection.GetParameters()[2].DefaultValue);
        var nullable = new System.Reflection.NullabilityInfoContext();
        foreach (var method in methods)
        {
            Assert.False(method.IsVirtual); Assert.False(method.IsGenericMethod); Assert.True(method.IsPublic);
            Assert.Equal(System.Reflection.NullabilityState.NotNull, nullable.Create(method.ReturnParameter).ReadState);
            Assert.All(method.GetParameters(), p => Assert.Equal(System.Reflection.NullabilityState.NotNull, nullable.Create(p).ReadState));
        }
        Assert.False(single.IsStatic); Assert.False(collection.IsStatic);
        Assert.Null(type.GetMethod("Bind", declared)); Assert.Null(type.GetMethod("ForBinding", declared));
        Assert.True(type.GetMethod("Bind", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.IsAssembly);
        var contextFactory = typeof(AdForLinux.DirectoryServices.AccountManagement.PrincipalContext).GetMethod("CreateIdentityResolver", Type.EmptyTypes)!;
        Assert.True(contextFactory.IsPublic); Assert.False(contextFactory.IsStatic); Assert.False(contextFactory.IsVirtual);
        Assert.Equal(type, contextFactory.ReturnType);
        Assert.Equal(System.Reflection.NullabilityState.NotNull, nullable.Create(contextFactory.ReturnParameter).ReadState);
    }
}
