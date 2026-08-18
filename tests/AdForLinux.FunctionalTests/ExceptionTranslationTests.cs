using System.DirectoryServices.Protocols;
using System.Security.Authentication;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class ExceptionTranslationTests
{
    [Theory]
    [InlineData(81, unchecked((int)0x8007203A))]
    [InlineData(85, unchecked((int)0x80072022))]
    [InlineData(87, unchecked((int)0x8007203E))]
    [InlineData(49, unchecked((int)0x8007052E))]
    public void ProtocolErrorsBecomeDirectoryServicesComExceptions(
        int ldapError,
        int expectedHResult)
    {
        var protocol = new LdapException(ldapError, "protocol message");

        var translated = LdapExceptionTranslator.Translate(protocol);

        Assert.Equal(expectedHResult, translated.ErrorCode);
        Assert.IsType<COMException>(translated);
        Assert.Contains("protocol message", translated.Message);
    }

    [Theory]
    [InlineData(unchecked((int)0x80070005), typeof(UnauthorizedAccessException))]
    [InlineData(unchecked((int)0x8007052E), typeof(AuthenticationException))]
    [InlineData(unchecked((int)0x80071392), typeof(PrincipalExistsException))]
    [InlineData(unchecked((int)0x8007202F), typeof(InvalidOperationException))]
    [InlineData(unchecked((int)0x80072035), typeof(InvalidOperationException))]
    [InlineData(unchecked((int)0x8007203A), typeof(PrincipalServerDownException))]
    [InlineData(unchecked((int)0x80072030), typeof(PrincipalOperationException))]
    public void AccountManagementUsesMicrosoftExceptionCategories(
        int hresult,
        Type expectedType)
    {
        var protocol = new LdapException(80, "inner");
        var directoryException = new DirectoryServicesCOMException(
            "directory message", protocol, hresult, 80, "server diagnostic");

        var translated = AccountManagementExceptionTranslator.Translate(directoryException);

        Assert.IsType(expectedType, translated);
        Assert.Same(directoryException, translated.InnerException);
        if (translated is PrincipalOperationException operation)
        {
            Assert.Equal(hresult, operation.ErrorCode);
        }
    }

    [Fact]
    public void MissingObjectDoesNotLeakDirectoryOperationException()
    {
        var dn = $"CN=issue41-missing-{Guid.NewGuid():N},{TestSettings.BaseDn}";
        using var entry = new DirectoryEntry(
            TestSettings.PathFor(dn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            TestSettings.UseTls
                ? AuthenticationTypes.SecureSocketsLayer
                : AuthenticationTypes.None);

        var exception = Assert.Throws<DirectoryServicesCOMException>(entry.RefreshCache);

        Assert.Equal(unchecked((int)0x80072030), exception.ErrorCode);
        Assert.IsType<DirectoryOperationException>(exception.InnerException);
    }

    [Fact]
    public void InvalidFilterDoesNotLeakProtocolException()
    {
        using var root = new DirectoryEntry(
            TestSettings.PathFor(TestSettings.BaseDn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            TestSettings.UseTls
                ? AuthenticationTypes.SecureSocketsLayer
                : AuthenticationTypes.None);
        using var searcher = new DirectorySearcher(root, "(|invalid)");

        var exception = Assert.Throws<ArgumentException>(searcher.FindOne);

        Assert.IsType<LdapException>(exception.InnerException);
    }

    [Fact]
    public void ServerUnavailableMapsAtBothApiLayers()
    {
        using var entry = new DirectoryEntry("LDAP://127.0.0.1:1/DC=unavailable");
        var lowLevel = Assert.Throws<COMException>(entry.RefreshCache);
        Assert.Equal(unchecked((int)0x8007203A), lowLevel.ErrorCode);
        Assert.IsNotType<DirectoryServicesCOMException>(lowLevel);

        using var context = new PrincipalContext(
            ContextType.Domain,
            "127.0.0.1:1",
            "DC=unavailable",
            ContextOptions.SimpleBind,
            "user",
            "password");
        var highLevel = Assert.Throws<PrincipalServerDownException>(
            () => UserPrincipal.FindByIdentity(context, "missing"));
        Assert.IsType<COMException>(highLevel.InnerException);
    }

    [Fact]
    public void InvalidCredentialsReturnFalseInsteadOfLeakingProtocolExceptions()
    {
        using var context = TestSettings.CreatePrincipalContext(TestSettings.BaseDn);

        Assert.False(context.ValidateCredentials(
            $"issue41-missing-{Guid.NewGuid():N}@invalid.example",
            "not-the-password",
            TestSettings.PrincipalContextOptions));
    }

    [Fact]
    public void DuplicateCreateMapsAtBothApiLayers()
    {
        var name = $"i41-{Guid.NewGuid():N}"[..18];
        var dn = $"CN={name},{TestSettings.BaseDn}";
        using var parent = new DirectoryEntry(
            TestSettings.PathFor(TestSettings.BaseDn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            TestSettings.UseTls
                ? AuthenticationTypes.SecureSocketsLayer
                : AuthenticationTypes.None);
        using var first = parent.Children.Add($"CN={name}", "user");
        first.Properties["sAMAccountName"].Value = name;
        first.CommitChanges();

        try
        {
            using var duplicate = parent.Children.Add($"CN={name}", "user");
            duplicate.Properties["sAMAccountName"].Value = name;
            var lowLevel = Assert.Throws<DirectoryServicesCOMException>(duplicate.CommitChanges);
            Assert.Equal(unchecked((int)0x80071392), lowLevel.ErrorCode);

            using var context = TestSettings.CreatePrincipalContext(TestSettings.BaseDn);
            using var principal = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
            };
            Assert.Throws<PrincipalExistsException>(principal.Save);
        }
        finally
        {
            using var cleanup = new DirectoryEntry(
                TestSettings.PathFor(dn),
                TestSettings.BindDn,
                TestSettings.BindPassword,
                TestSettings.UseTls
                    ? AuthenticationTypes.SecureSocketsLayer
                    : AuthenticationTypes.None);
            cleanup.DeleteTree();
        }
    }
}
