using System.Collections;
using System.Reflection;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using AccountMatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public class AccountManagementPublicTypesTests
{
    private static PrincipalContext OfflineContext() =>
        new(ContextType.Domain, "dc.example.test", "DC=example,DC=test");

    [Fact]
    public void Computer_principal_exposes_a_mutable_service_principal_name_collection()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context);
        var values = computer.ServicePrincipalNames;

        values.Add("HOST/server.example.test");
        values.Insert(0, "RestrictedKrbHost/server.example.test");
        IList list = values;
        var returnedCount = list.Add("TERMSRV/server.example.test");

        Assert.Equal(3, returnedCount);
        Assert.Equal(3, values.Count);
        Assert.Equal("RestrictedKrbHost/server.example.test", values[0]);
        Assert.False(values.IsFixedSize);
        Assert.False(values.IsReadOnly);
        Assert.False(values.IsSynchronized);
        Assert.Same(values, values.SyncRoot);
    }

    [Fact]
    public void Advanced_filters_are_included_in_query_by_example_ldap()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context) { SamAccountName = "server$" };
        var when = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        computer.AdvancedSearchFilter.LastLogonTime(when, AccountMatchType.GreaterThan);

        using var searcher = new PrincipalSearcher(computer);
        var ticks = when.ToFileTimeUtc();

        Assert.Equal(
            $"(&(objectCategory=computer)(sAMAccountName=server$)(&(lastLogonTimestamp>={ticks})(!(lastLogonTimestamp={ticks}))))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void Every_match_type_has_the_microsoft_numeric_value()
    {
        Assert.Equal(new[] { 0, 1, 2, 3, 4, 5 },
            Enum.GetValues<AccountMatchType>().Select(value => (int)value));
    }

    [Fact]
    public void Directory_mapping_attributes_expose_the_compatible_contract()
    {
        var property = new DirectoryPropertyAttribute("extensionAttribute1")
        {
            Context = ContextType.Domain,
        };
        var objectClass = new DirectoryObjectClassAttribute("customPerson");
        var rdn = new DirectoryRdnPrefixAttribute("CN");

        Assert.Equal("extensionAttribute1", property.SchemaAttributeName);
        Assert.Equal(ContextType.Domain, property.Context);
        Assert.Equal("customPerson", objectClass.ObjectClass);
        Assert.Null(objectClass.Context);
        Assert.Equal("CN", rdn.RdnPrefix);
        Assert.Null(rdn.Context);
        Assert.True(typeof(DirectoryPropertyAttribute).GetCustomAttribute<AttributeUsageAttribute>()!.AllowMultiple);
    }

    [Fact]
    public void Principal_exception_hierarchy_preserves_messages_causes_and_error_codes()
    {
        var cause = new InvalidOperationException("cause");
        PrincipalException operation = new PrincipalOperationException("failed", cause, 49);

        Assert.IsAssignableFrom<SystemException>(operation);
        Assert.Equal("failed", operation.Message);
        Assert.Same(cause, operation.InnerException);
        Assert.Equal(49, Assert.IsType<PrincipalOperationException>(operation).ErrorCode);
        Assert.IsAssignableFrom<PrincipalException>(new MultipleMatchesException());
        Assert.IsAssignableFrom<PrincipalException>(new NoMatchingPrincipalException());
        Assert.IsAssignableFrom<PrincipalException>(new PasswordException());
        Assert.IsAssignableFrom<PrincipalException>(new PrincipalExistsException());
        Assert.IsAssignableFrom<PrincipalException>(new PrincipalServerDownException());
    }
}
