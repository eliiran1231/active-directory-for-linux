using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Compares the low-level API: DirectoryEntry and DirectorySearcher.
/// </summary>
[Collection("differential")]
public class DirectoryEntryComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public DirectoryEntryComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) =>
        new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            Ms.AuthenticationTypes.SecureSocketsLayer);

    private static Ours.DirectoryEntry OurEntry(string dn) =>
        new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            Ours.AuthenticationTypes.SecureSocketsLayer);

    [Fact]
    public void Entry_identity_members_match()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        new Comparison($"DirectoryEntry {_data.UserDn}")
            .Check(nameof(ms.Name), ms.Name, ours.Name)
            .Check(nameof(ms.SchemaClassName), ms.SchemaClassName, ours.SchemaClassName)
            .Check(nameof(ms.Guid), ms.Guid, ours.Guid)
            .Assert();
    }

    [Theory]
    [InlineData("sAMAccountName")]
    [InlineData("givenName")]
    [InlineData("sn")]
    [InlineData("displayName")]
    [InlineData("mail")]
    [InlineData("telephoneNumber")]
    [InlineData("description")]
    [InlineData("userPrincipalName")]
    [InlineData("employeeID")]
    [InlineData("homeDirectory")]
    [InlineData("homeDrive")]
    [InlineData("scriptPath")]
    [InlineData("distinguishedName")]
    [InlineData("userAccountControl")]
    public void String_properties_match(string attributeName)
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        new Comparison($"Properties[\"{attributeName}\"]")
            .Check("Value",
                ms.Properties[attributeName].Value?.ToString(),
                ours.Properties[attributeName].Value?.ToString())
            .Assert();
    }

    [Fact]
    public void Missing_property_behaves_the_same()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        new Comparison("missing property")
            .Check("Value", ms.Properties["noSuchAttributeHere"].Value,
                            ours.Properties["noSuchAttributeHere"].Value)
            .Check("Count", ms.Properties["noSuchAttributeHere"].Count,
                            ours.Properties["noSuchAttributeHere"].Count)
            .Assert();
    }

    [Fact]
    public void Multi_valued_object_class_matches()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        new Comparison("objectClass")
            .CheckSet("values",
                ms.Properties["objectClass"].Cast<object>().Select(v => v.ToString()),
                ours.Properties["objectClass"].Cast<object>().Select(v => v.ToString()))
            .Assert();
    }

    [Fact]
    public void Group_member_list_matches()
    {
        using var ms = MicrosoftEntry(_data.GroupDn);
        using var ours = OurEntry(_data.GroupDn);

        new Comparison("member")
            .CheckSet("values",
                ms.Properties["member"].Cast<object>().Select(v => v.ToString()),
                ours.Properties["member"].Cast<object>().Select(v => v.ToString()))
            .Assert();
    }

    [Fact]
    public void Searcher_findone_matches()
    {
        using var msRoot = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourRoot = OurEntry(DifferentialSettings.UsersContainer);

        var filter = $"(&(objectClass=user)(sAMAccountName={_data.UserName}))";

        using var msSearcher = new Ms.DirectorySearcher(msRoot, filter);
        msSearcher.PropertiesToLoad.Add("sAMAccountName");
        msSearcher.PropertiesToLoad.Add("distinguishedName");

        using var ourSearcher = new Ours.DirectorySearcher(ourRoot, filter);
        ourSearcher.PropertiesToLoad.Add("sAMAccountName");
        ourSearcher.PropertiesToLoad.Add("distinguishedName");

        var msResult = msSearcher.FindOne();
        var ourResult = ourSearcher.FindOne();

        Assert.NotNull(msResult);
        Assert.NotNull(ourResult);

        new Comparison("DirectorySearcher.FindOne")
            .Check("sAMAccountName",
                msResult!.Properties["sAMAccountName"][0].ToString(),
                ourResult!.Properties["sAMAccountName"][0].ToString())
            .Check("distinguishedName",
                msResult.Properties["distinguishedName"][0].ToString(),
                ourResult.Properties["distinguishedName"][0].ToString())
            .Assert();
    }

    [Fact]
    public void Searcher_findone_agrees_when_nothing_matches()
    {
        using var msRoot = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourRoot = OurEntry(DifferentialSettings.UsersContainer);

        const string filter = "(sAMAccountName=no-such-user-xyz-123)";

        using var msSearcher = new Ms.DirectorySearcher(msRoot, filter);
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot, filter);

        new Comparison("FindOne with no match")
            .Check("found", msSearcher.FindOne() is not null, ourSearcher.FindOne() is not null)
            .Assert();
    }

    [Fact]
    public void Searcher_findall_counts_match()
    {
        using var msRoot = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourRoot = OurEntry(DifferentialSettings.UsersContainer);

        const string filter = "(objectClass=group)";

        using var msSearcher = new Ms.DirectorySearcher(msRoot, filter) { PageSize = 100 };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot, filter) { PageSize = 100 };

        using var msResults = msSearcher.FindAll();
        var ourResults = ourSearcher.FindAll();

        new Comparison("FindAll over groups")
            .Check("Count", msResults.Count, ourResults.Count)
            .CheckSet("paths",
                msResults.Cast<Ms.SearchResult>().Select(r => r.Properties["distinguishedname"][0].ToString()),
                ourResults.Select(r => r.Properties["distinguishedname"][0].ToString()))
            .Assert();
    }

    [Fact]
    public void Searcher_attribute_scope_query_matches()
    {
        using var msRoot = MicrosoftEntry(_data.GroupDn);
        using var ourRoot = OurEntry(_data.GroupDn);
        using var msSearcher = new Ms.DirectorySearcher(msRoot)
        {
            AttributeScopeQuery = "member",
            Filter = "(objectClass=user)",
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            AttributeScopeQuery = "member",
            Filter = "(objectClass=user)",
        };
        msSearcher.PropertiesToLoad.Add("sAMAccountName");
        msSearcher.PropertiesToLoad.Add("distinguishedName");
        ourSearcher.PropertiesToLoad.Add("sAMAccountName");
        ourSearcher.PropertiesToLoad.Add("distinguishedName");

        using var msResults = msSearcher.FindAll();
        var ourResults = ourSearcher.FindAll();

        new Comparison("DirectorySearcher.AttributeScopeQuery")
            .Check("SearchScope", msSearcher.SearchScope.ToString(), ourSearcher.SearchScope.ToString())
            .Check("Count", msResults.Count, ourResults.Count)
            .CheckSet("paths",
                msResults.Cast<Ms.SearchResult>().Select(result => result.Path),
                ourResults.Select(result => result.Path))
            .CheckSet("sAMAccountName",
                msResults.Cast<Ms.SearchResult>().Select(result => result.Properties["sAMAccountName"][0].ToString()),
                ourResults.Select(result => result.Properties["sAMAccountName"][0].ToString()))
            .Assert();
    }

    [Fact]
    public void Searcher_attribute_scope_query_rejects_unset_non_dn_attribute()
    {
        CompareInvalidAttributeScopeQuery(_data.NestedGroupDn, "unset non-DN attribute");
    }

    [Fact]
    public void Searcher_attribute_scope_query_rejects_dn_text_in_non_dn_attribute()
    {
        CompareInvalidAttributeScopeQuery(_data.GroupDn, "DN text in non-DN attribute");
    }

    private static void CompareInvalidAttributeScopeQuery(string rootDn, string scenario)
    {
        using var msRoot = MicrosoftEntry(rootDn);
        using var ourRoot = OurEntry(rootDn);
        using var msSearcher = new Ms.DirectorySearcher(msRoot)
        {
            AttributeScopeQuery = "description",
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            AttributeScopeQuery = "description",
        };

        var msError = Record.Exception(() =>
        {
            using var results = msSearcher.FindAll();
            _ = results.Count;
        });
        var ourError = Record.Exception(() => _ = ourSearcher.FindAll());

        new Comparison($"DirectorySearcher.AttributeScopeQuery {scenario}")
            .Check("throws", msError is not null, ourError is not null)
            .Assert();
        Assert.NotNull(msError);
        Assert.IsType<System.DirectoryServices.Protocols.DirectoryOperationException>(ourError);
        Assert.Contains("InvalidAttributeSyntax (21)", ourError!.Message, StringComparison.OrdinalIgnoreCase);
    }
}
