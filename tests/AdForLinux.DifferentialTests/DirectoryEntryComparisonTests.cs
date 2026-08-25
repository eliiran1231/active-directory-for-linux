using System.Collections;
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

    [Fact]
    public void Credential_constructor_authentication_default_matches()
    {
        using var ms = new Ms.DirectoryEntry(
            "LDAP://dc.example.test/DC=example,DC=test", "user@example.test", "password");
        using var ours = new Ours.DirectoryEntry(
            "LDAP://dc.example.test/DC=example,DC=test", "user@example.test", "password");

        new Comparison("DirectoryEntry credential constructor authentication default")
            .Check("AuthenticationType", ms.AuthenticationType.ToString(), ours.AuthenticationType.ToString())
            .Assert();
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Disposed_entry_lifecycle_matches_for_cached_and_uncached_entries(bool usePropertyCache)
    {
        var ms = MicrosoftEntry(_data.UserDn);
        var ours = OurEntry(_data.UserDn);
        ms.UsePropertyCache = usePropertyCache;
        ours.UsePropertyCache = usePropertyCache;

        _ = ms.Properties["displayName"].Value;
        _ = ours.Properties["displayName"].Value;
        var msPath = ms.Path;
        var ourPath = ours.Path;

        ms.Dispose();
        ours.Dispose();

        var msRefreshError = Assert.IsType<ObjectDisposedException>(Record.Exception(ms.RefreshCache));
        var ourRefreshError = Assert.IsType<ObjectDisposedException>(Record.Exception(ours.RefreshCache));
        var msPropertyError = Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => _ = ms.Properties["displayName"].Value));
        var ourPropertyError = Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => _ = ours.Properties["displayName"].Value));
        var msCommitError = Record.Exception(ms.CommitChanges);
        var ourCommitError = Record.Exception(ours.CommitChanges);
        var msNameError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => _ = ms.Name));
        var ourNameError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => _ = ours.Name));
        var msParentError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => _ = ms.Parent));
        var ourParentError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => _ = ours.Parent));

        using var msSearcher = new Ms.DirectorySearcher(ms);
        using var ourSearcher = new Ours.DirectorySearcher(ours);
        var msSearchError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => msSearcher.FindOne()));
        var ourSearchError = Assert.IsType<ObjectDisposedException>(Record.Exception(() => ourSearcher.FindOne()));

        new Comparison($"DirectoryEntry disposed lifecycle (UsePropertyCache={usePropertyCache})")
            .Check("RefreshCache exception", msRefreshError.GetType().Name, ourRefreshError.GetType().Name)
            .Check("RefreshCache object name", msRefreshError.ObjectName, ourRefreshError.ObjectName)
            .Check("Properties exception", msPropertyError.GetType().Name, ourPropertyError.GetType().Name)
            .Check("Properties object name", msPropertyError.ObjectName, ourPropertyError.ObjectName)
            .Check("CommitChanges exception", msCommitError?.GetType().Name, ourCommitError?.GetType().Name)
            .Check(
                "CommitChanges object name",
                (msCommitError as ObjectDisposedException)?.ObjectName,
                (ourCommitError as ObjectDisposedException)?.ObjectName)
            .Check("Name exception", msNameError.GetType().Name, ourNameError.GetType().Name)
            .Check("Name object name", msNameError.ObjectName, ourNameError.ObjectName)
            .Check("Parent exception", msParentError.GetType().Name, ourParentError.GetType().Name)
            .Check("Parent object name", msParentError.ObjectName, ourParentError.ObjectName)
            .Check("Search exception", msSearchError.GetType().Name, ourSearchError.GetType().Name)
            .Check("Search object name", msSearchError.ObjectName, ourSearchError.ObjectName)
            .Check("Path remains readable", msPath, ourPath)
            .Assert();

        ms.Dispose();
        ours.Dispose();
    }

    [Fact]
    public void Closed_entry_rebinds_and_refreshes_like_microsoft()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        var msBefore = ms.Properties["displayName"].Value?.ToString();
        var oursBefore = ours.Properties["displayName"].Value?.ToString();

        ms.Close();
        ours.Close();
        ms.RefreshCache();
        ours.RefreshCache();

        new Comparison("DirectoryEntry Close followed by rebind")
            .Check("Value before Close", msBefore, oursBefore)
            .Check("Value after RefreshCache", ms.Properties["displayName"].Value?.ToString(),
                ours.Properties["displayName"].Value?.ToString())
            .Assert();

        ms.Close();
        ours.Close();
        ms.Close();
        ours.Close();
    }

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

    [Fact]
    public void Parent_identity_and_inherited_state_match()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);
        ms.UsePropertyCache = false;
        ours.UsePropertyCache = false;

        using var msParent = ms.Parent;
        using var ourParent = ours.Parent;

        new Comparison("DirectoryEntry.Parent inherited state")
            .Check("Name", msParent.Name, ourParent!.Name)
            .Check("Path", msParent.Path, ourParent.Path)
            .Check("UsePropertyCache", msParent.UsePropertyCache, ourParent.UsePropertyCache)
            .Check("Username", msParent.Username, ourParent.Username)
            .Check("AuthenticationType", msParent.AuthenticationType.ToString(), ourParent.AuthenticationType.ToString())
            .Assert();
    }

    [Fact]
    public void Missing_entry_name_and_parent_errors_match()
    {
        var missingDn = $"CN=issue107-missing-{Guid.NewGuid():N},{DifferentialSettings.BaseDn}";
        using var msName = MicrosoftEntry(missingDn);
        using var ourName = OurEntry(missingDn);
        using var msParent = MicrosoftEntry(missingDn);
        using var ourParent = OurEntry(missingDn);

        var msNameError = Assert.IsType<Ms.DirectoryServicesCOMException>(
            Record.Exception(() => _ = msName.Name));
        var ourNameError = Assert.IsType<Ours.DirectoryServicesCOMException>(
            Record.Exception(() => _ = ourName.Name));
        var msParentError = Assert.IsType<Ms.DirectoryServicesCOMException>(
            Record.Exception(() => _ = msParent.Parent));
        var ourParentError = Assert.IsType<Ours.DirectoryServicesCOMException>(
            Record.Exception(() => _ = ourParent.Parent));

        new Comparison("DirectoryEntry missing bind semantics")
            .Check("Name exception", msNameError.GetType().Name, ourNameError.GetType().Name)
            .Check("Name HResult", msNameError.ErrorCode, ourNameError.ErrorCode)
            .Check("Parent exception", msParentError.GetType().Name, ourParentError.GetType().Name)
            .Check("Parent HResult", msParentError.ErrorCode, ourParentError.ErrorCode)
            .Assert();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void CommitChanges_after_create_reloads_server_generated_properties(bool usePropertyCache)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msName = $"ms104-{suffix}";
        var ourName = $"our104-{suffix}";
        var msDn = $"CN={msName},{DifferentialSettings.UsersContainer}";
        var ourDn = $"CN={ourName},{DifferentialSettings.UsersContainer}";

        try
        {
            using var msParent = MicrosoftEntry(DifferentialSettings.UsersContainer);
            using var ourParent = OurEntry(DifferentialSettings.UsersContainer);
            using var ms = msParent.Children.Add($"CN={msName}", "group");
            using var ours = ourParent.Children.Add($"CN={ourName}", "group");
            ms.Properties["sAMAccountName"].Value = msName;
            ours.Properties["sAMAccountName"].Value = ourName;
            var msAddProperties = ms.Properties;
            var ourAddProperties = ours.Properties;
            ms.UsePropertyCache = usePropertyCache;
            ours.UsePropertyCache = usePropertyCache;

            ms.CommitChanges();
            ours.CommitChanges();

            new Comparison($"DirectoryEntry create CommitChanges cache (UsePropertyCache={usePropertyCache})")
                .Check("PropertyCollection invalidated",
                    !ReferenceEquals(msAddProperties, ms.Properties),
                    !ReferenceEquals(ourAddProperties, ours.Properties))
                .Check("GUID available", ms.Guid != Guid.Empty, ours.Guid != Guid.Empty)
                .Check("SID available",
                    ms.Properties["objectSid"].Value is byte[] { Length: > 0 },
                    ours.Properties["objectSid"].Value is byte[] { Length: > 0 })
                .Check("default sAMAccountType available",
                    ms.Properties["sAMAccountType"].Value is not null,
                    ours.Properties["sAMAccountType"].Value is not null)
                .Assert();
        }
        finally
        {
            SafeDeleteMicrosoft(msDn);
            SafeDeleteOur(ourDn);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void CommitChanges_after_update_matches_cached_and_uncached_behavior(bool usePropertyCache)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msName = $"ms104u-{suffix}";
        var ourName = $"our104u-{suffix}";
        var msDn = $"CN={msName},{DifferentialSettings.UsersContainer}";
        var ourDn = $"CN={ourName},{DifferentialSettings.UsersContainer}";

        try
        {
            CreateMicrosoftGroup(msName);
            CreateOurGroup(ourName);
            using var ms = MicrosoftEntry(msDn);
            using var ours = OurEntry(ourDn);
            ms.UsePropertyCache = usePropertyCache;
            ours.UsePropertyCache = usePropertyCache;
            var msProperties = ms.Properties;
            var ourProperties = ours.Properties;
            ms.Properties["description"].Value = "issue 104 update";
            ours.Properties["description"].Value = "issue 104 update";

            ms.CommitChanges();
            ours.CommitChanges();

            new Comparison($"DirectoryEntry update CommitChanges cache (UsePropertyCache={usePropertyCache})")
                .Check("PropertyCollection invalidated",
                    !ReferenceEquals(msProperties, ms.Properties),
                    !ReferenceEquals(ourProperties, ours.Properties))
                .Check("committed value", ms.Properties["description"].Value, ours.Properties["description"].Value)
                .Assert();
        }
        finally
        {
            SafeDeleteMicrosoft(msDn);
            SafeDeleteOur(ourDn);
        }
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
    public void Partial_refresh_cache_and_pending_change_semantics_match()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);
        var msProperties = ms.Properties;
        var ourProperties = ours.Properties;
        var msRequestedBefore = msProperties["displayName"];
        var ourRequestedBefore = ourProperties["displayName"];
        var msUnrelatedBefore = msProperties["mail"];
        var ourUnrelatedBefore = ourProperties["mail"];

        msRequestedBefore.Value = "staged display name";
        ourRequestedBefore.Value = "staged display name";
        msUnrelatedBefore.Value = "staged mail";
        ourUnrelatedBefore.Value = "staged mail";

        ms.RefreshCache(new[] { "displayName" });
        ours.RefreshCache(new[] { "displayName" });

        new Comparison("DirectoryEntry.RefreshCache(string[]) partial cache")
            .Check("PropertyCollection retained",
                ReferenceEquals(msProperties, ms.Properties),
                ReferenceEquals(ourProperties, ours.Properties))
            .Check("requested collection invalidated",
                ReferenceEquals(msRequestedBefore, ms.Properties["displayName"]),
                ReferenceEquals(ourRequestedBefore, ours.Properties["displayName"]))
            .Check("requested value refreshed",
                ms.Properties["displayName"].Value,
                ours.Properties["displayName"].Value)
            .Check("held requested snapshot",
                msRequestedBefore.Value,
                ourRequestedBefore.Value)
            .Check("unrelated collection retained",
                ReferenceEquals(msUnrelatedBefore, ms.Properties["mail"]),
                ReferenceEquals(ourUnrelatedBefore, ours.Properties["mail"]))
            .Check("unrelated pending value retained",
                ms.Properties["mail"].Value,
                ours.Properties["mail"].Value)
            .Assert();
    }

    [Fact]
    public void Partial_refresh_edge_cases_match()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);
        var msProperties = ms.Properties;
        var ourProperties = ours.Properties;
        var msUnrelated = msProperties["mail"];
        var ourUnrelated = ourProperties["mail"];
        var msMissingBefore = msProperties["noSuchAttributeHere"];
        var ourMissingBefore = ourProperties["noSuchAttributeHere"];

        ms.RefreshCache(new[] { "DISPLAYNAME", "displayName", "noSuchAttributeHere" });
        ours.RefreshCache(new[] { "DISPLAYNAME", "displayName", "noSuchAttributeHere" });

        new Comparison("DirectoryEntry.RefreshCache(string[]) edge cases")
            .Check("case-varied duplicate value",
                ms.Properties["displayName"].Value,
                ours.Properties["displayName"].Value)
            .Check("missing collection invalidated",
                ReferenceEquals(msMissingBefore, ms.Properties["noSuchAttributeHere"]),
                ReferenceEquals(ourMissingBefore, ours.Properties["noSuchAttributeHere"]))
            .Check("missing value",
                ms.Properties["noSuchAttributeHere"].Value,
                ours.Properties["noSuchAttributeHere"].Value)
            .Check("unrelated collection retained",
                ReferenceEquals(msUnrelated, ms.Properties["mail"]),
                ReferenceEquals(ourUnrelated, ours.Properties["mail"]))
            .Assert();

        var msEmptyError = Record.Exception(() => ms.RefreshCache(Array.Empty<string>()));
        var ourEmptyError = Record.Exception(() => ours.RefreshCache(Array.Empty<string>()));

        new Comparison("DirectoryEntry.RefreshCache(empty)")
            .Check("throws", msEmptyError is not null, ourEmptyError is not null)
            .Check("PropertyCollection retained",
                ReferenceEquals(msProperties, ms.Properties),
                ReferenceEquals(ourProperties, ours.Properties))
            .Check("unrelated collection retained",
                ReferenceEquals(msUnrelated, ms.Properties["mail"]),
                ReferenceEquals(ourUnrelated, ours.Properties["mail"]))
            .Check("unrelated value",
                ms.Properties["mail"].Value,
                ours.Properties["mail"].Value)
            .Assert();

        new Comparison("DirectoryEntry.RefreshCache argument validation")
            .Check("null array exception",
                Record.Exception(() => ms.RefreshCache(null!))?.GetType().Name,
                Record.Exception(() => ours.RefreshCache(null!))?.GetType().Name)
            .Check("null element exception",
                Record.Exception(() => ms.RefreshCache(new string[] { null! }))?.GetType().Name,
                Record.Exception(() => ours.RefreshCache(new string[] { null! }))?.GetType().Name)
            .Assert();
    }

    [Fact]
    public void Partial_refresh_with_a_ranged_property_name_matches()
    {
        using var ms = MicrosoftEntry(_data.GroupDn);
        using var ours = OurEntry(_data.GroupDn);
        var msProperties = ms.Properties;
        var ourProperties = ours.Properties;
        var msUnrelated = msProperties["objectClass"];
        var ourUnrelated = ourProperties["objectClass"];
        const string rangedName = "member;range=0-0";

        var msError = Record.Exception(() => ms.RefreshCache(new[] { rangedName }));
        var ourError = Record.Exception(() => ours.RefreshCache(new[] { rangedName }));
        new Comparison("DirectoryEntry.RefreshCache(ranged property)")
            .Check("exception", msError?.GetType().Name, ourError?.GetType().Name)
            .Check("PropertyCollection retained",
                ReferenceEquals(msProperties, ms.Properties),
                ReferenceEquals(ourProperties, ours.Properties))
            .Check("unrelated collection retained",
                ReferenceEquals(msUnrelated, ms.Properties["objectClass"]),
                ReferenceEquals(ourUnrelated, ours.Properties["objectClass"]))
            .Check("requested range count",
                ms.Properties[rangedName].Count,
                ours.Properties[rangedName].Count)
            .Assert();
    }

    [Fact]
    public void Property_collection_non_generic_copy_copies_property_values()
    {
        using var ms = MicrosoftEntry(_data.UserDn);
        using var ours = OurEntry(_data.UserDn);

        var msValues = new Ms.PropertyValueCollection[ms.Properties.Count];
        var ourValues = new Ours.PropertyValueCollection[ours.Properties.Count];

        ((ICollection)ms.Properties).CopyTo(msValues, 0);
        ((ICollection)ours.Properties).CopyTo(ourValues, 0);

        new Comparison("PropertyCollection.ICollection.CopyTo")
            .CheckSet("property names",
                msValues.Select(value => value.PropertyName),
                ourValues.Select(value => value.PropertyName))
            .Assert();
    }

    [Fact]
    public void Directory_entries_find_requires_the_actual_schema_class()
    {
        using var msContainer = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourContainer = OurEntry(DifferentialSettings.UsersContainer);
        var relativeName = $"CN={_data.UserName}";

        var msError = Record.Exception(() => msContainer.Children.Find(relativeName, "person"));
        var ourError = Record.Exception(() => ourContainer.Children.Find(relativeName, "person"));

        new Comparison("DirectoryEntries.Find schema class")
            .Check("derived class rejected", msError is not null, ourError is not null)
            .Assert();
        Assert.NotNull(msError);
        Assert.IsType<InvalidOperationException>(ourError);
    }

    [Fact]
    public void Directory_entries_remove_is_non_recursive_and_delete_tree_remains_recursive()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var msEmptyDn = $"OU=adfl-ms-empty-{suffix},{DifferentialSettings.BaseDn}";
        var msParentDn = $"OU=adfl-ms-remove-{suffix},{DifferentialSettings.BaseDn}";
        var msChildDn = $"OU=child,{msParentDn}";
        var ourEmptyDn = $"OU=adfl-our-empty-{suffix},{DifferentialSettings.BaseDn}";
        var ourParentDn = $"OU=adfl-our-remove-{suffix},{DifferentialSettings.BaseDn}";
        var ourChildDn = $"OU=child,{ourParentDn}";

        try
        {
            CreateMicrosoftOrganizationalUnit(msEmptyDn);
            CreateMicrosoftOrganizationalUnit(msParentDn);
            CreateMicrosoftOrganizationalUnit(msChildDn);
            CreateOurOrganizationalUnit(ourEmptyDn);
            CreateOurOrganizationalUnit(ourParentDn);
            CreateOurOrganizationalUnit(ourChildDn);

            using var msDomain = MicrosoftEntry(DifferentialSettings.BaseDn);
            using var msEmpty = MicrosoftEntry(msEmptyDn);
            using var msParent = MicrosoftEntry(msParentDn);
            using var ourDomain = OurEntry(DifferentialSettings.BaseDn);
            using var ourEmpty = OurEntry(ourEmptyDn);
            using var ourParent = OurEntry(ourParentDn);

            msDomain.Children.Remove(msEmpty);
            ourDomain.Children.Remove(ourEmpty);

            Assert.False(MicrosoftEntryExists(msEmptyDn));
            Assert.False(OurEntryExists(ourEmptyDn));

            var msError = Record.Exception(() => msDomain.Children.Remove(msParent));
            var ourError = Record.Exception(() => ourDomain.Children.Remove(ourParent));

            var msComError = Assert.IsType<Ms.DirectoryServicesCOMException>(msError);
            Assert.Equal(unchecked((int)0x80072015), msComError.HResult);
            var ourComError = Assert.IsType<Ours.DirectoryServicesCOMException>(ourError);
            Assert.Equal(msComError.HResult, ourComError.HResult);
            Assert.True(MicrosoftEntryExists(msParentDn));
            Assert.True(MicrosoftEntryExists(msChildDn));
            Assert.True(OurEntryExists(ourParentDn));
            Assert.True(OurEntryExists(ourChildDn));

            msParent.DeleteTree();
            ourParent.DeleteTree();

            Assert.False(MicrosoftEntryExists(msParentDn));
            Assert.False(MicrosoftEntryExists(msChildDn));
            Assert.False(OurEntryExists(ourParentDn));
            Assert.False(OurEntryExists(ourChildDn));
        }
        finally
        {
            SafeDeleteMicrosoft(msEmptyDn);
            SafeDeleteMicrosoft(msParentDn);
            SafeDeleteOur(ourEmptyDn);
            SafeDeleteOur(ourParentDn);
        }
    }

    [Fact]
    public void Directory_entries_remove_uses_the_collections_parent()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var msFirstDn = $"OU=adfl-ms-first-{suffix},{DifferentialSettings.BaseDn}";
        var msSecondDn = $"OU=adfl-ms-second-{suffix},{DifferentialSettings.BaseDn}";
        var msChildDn = $"OU=child,{msSecondDn}";
        var ourFirstDn = $"OU=adfl-our-first-{suffix},{DifferentialSettings.BaseDn}";
        var ourSecondDn = $"OU=adfl-our-second-{suffix},{DifferentialSettings.BaseDn}";
        var ourChildDn = $"OU=child,{ourSecondDn}";

        try
        {
            CreateMicrosoftOrganizationalUnit(msFirstDn);
            CreateMicrosoftOrganizationalUnit(msSecondDn);
            CreateMicrosoftOrganizationalUnit(msChildDn);
            CreateOurOrganizationalUnit(ourFirstDn);
            CreateOurOrganizationalUnit(ourSecondDn);
            CreateOurOrganizationalUnit(ourChildDn);

            using var msFirst = MicrosoftEntry(msFirstDn);
            using var msChild = MicrosoftEntry(msChildDn);
            using var ourFirst = OurEntry(ourFirstDn);
            using var ourChild = OurEntry(ourChildDn);

            var msError = Record.Exception(() => msFirst.Children.Remove(msChild));
            var ourError = Record.Exception(() => ourFirst.Children.Remove(ourChild));

            var msComError = Assert.IsType<Ms.DirectoryServicesCOMException>(msError);
            Assert.Equal(unchecked((int)0x80072030), msComError.HResult);
            var ourComError = Assert.IsType<Ours.DirectoryServicesCOMException>(ourError);
            Assert.Equal(msComError.HResult, ourComError.HResult);
            Assert.True(MicrosoftEntryExists(msChildDn));
            Assert.True(OurEntryExists(ourChildDn));
        }
        finally
        {
            SafeDeleteMicrosoft(msFirstDn);
            SafeDeleteMicrosoft(msSecondDn);
            SafeDeleteOur(ourFirstDn);
            SafeDeleteOur(ourSecondDn);
        }
    }

    [Fact]
    public void Directory_entries_remove_handles_an_rdn_ending_in_a_literal_backslash()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var msRelativeName = $@"OU=adfl-ms-slash-{suffix}\\";
        var ourRelativeName = $@"OU=adfl-our-slash-{suffix}\\";
        var msDn = $"{msRelativeName},{DifferentialSettings.BaseDn}";
        var ourDn = $"{ourRelativeName},{DifferentialSettings.BaseDn}";

        try
        {
            CreateMicrosoftOrganizationalUnit(msDn);
            CreateOurOrganizationalUnit(ourDn);

            using var msDomain = MicrosoftEntry(DifferentialSettings.BaseDn);
            using var msChild = MicrosoftEntry(msDn);
            using var ourDomain = OurEntry(DifferentialSettings.BaseDn);
            using var ourChild = OurEntry(ourDn);

            new Comparison("DirectoryEntries.Remove literal trailing backslash RDN")
                .Check("Microsoft Name", msRelativeName, msChild.Name)
                .Check("AdForLinux Name", ourRelativeName, ourChild.Name)
                .Assert();

            msDomain.Children.Remove(msChild);
            ourDomain.Children.Remove(ourChild);

            Assert.False(MicrosoftEntryExists(msDn));
            Assert.False(OurEntryExists(ourDn));
        }
        finally
        {
            SafeDeleteMicrosoft(msDn);
            SafeDeleteOur(ourDn);
        }
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
    public void Searcher_result_handle_documents_adsi_limitation_and_matches_disposed_contract()
    {
        using var msRoot = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourRoot = OurEntry(DifferentialSettings.UsersContainer);
        using var msSearcher = new Ms.DirectorySearcher(msRoot, "(objectClass=*)");
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot, "(objectClass=*)");

        var msResults = msSearcher.FindAll();
        var ourResults = ourSearcher.FindAll();

        Assert.NotEqual(IntPtr.Zero, msResults.Handle);
        Assert.Throws<PlatformNotSupportedException>(() => ourResults.Handle);

        msResults.Dispose();
        ourResults.Dispose();

        var msDisposed = Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => _ = msResults.Handle));
        var ourDisposed = Assert.IsType<ObjectDisposedException>(
            Record.Exception(() => _ = ourResults.Handle));
        new Comparison("SearchResultCollection.Handle disposed contract")
            .Check("Exception", msDisposed.GetType().Name, ourDisposed.GetType().Name)
            .Check("ObjectName", msDisposed.ObjectName, ourDisposed.ObjectName)
            .Assert();
    }

    [Theory]
    [InlineData(Ms.ExtendedDN.Standard, Ours.ExtendedDN.Standard)]
    [InlineData(Ms.ExtendedDN.HexString, Ours.ExtendedDN.HexString)]
    public void Searcher_extended_dn_representation_matches(
        Ms.ExtendedDN microsoftFormat,
        Ours.ExtendedDN ourFormat)
    {
        using var msRoot = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var ourRoot = OurEntry(DifferentialSettings.UsersContainer);
        var filter = $"(sAMAccountName={_data.UserName})";
        using var msSearcher = new Ms.DirectorySearcher(msRoot, filter) { ExtendedDN = microsoftFormat };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot, filter) { ExtendedDN = ourFormat };
        msSearcher.PropertiesToLoad.Add("distinguishedName");
        ourSearcher.PropertiesToLoad.Add("distinguishedName");

        var msValue = msSearcher.FindOne()!.Properties["distinguishedName"][0].ToString();
        var ourValue = ourSearcher.FindOne()!.Properties["distinguishedName"][0].ToString();

        Assert.Contains("<GUID=", msValue, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(msValue, ourValue, ignoreCase: true);
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
        Assert.IsType<Ours.DirectoryServicesCOMException>(ourError);
        Assert.Contains("InvalidAttributeSyntax (21)", ourError!.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static void CreateMicrosoftOrganizationalUnit(string distinguishedName)
    {
        var separator = distinguishedName.IndexOf(',');
        using var parent = MicrosoftEntry(distinguishedName[(separator + 1)..]);
        using var child = parent.Children.Add(distinguishedName[..separator], "organizationalUnit");
        child.CommitChanges();
    }

    private static void CreateOurOrganizationalUnit(string distinguishedName)
    {
        var separator = distinguishedName.IndexOf(',');
        using var parent = OurEntry(distinguishedName[(separator + 1)..]);
        using var child = parent.Children.Add(distinguishedName[..separator], "organizationalUnit");
        child.CommitChanges();
    }

    private static void CreateMicrosoftGroup(string name)
    {
        using var parent = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var child = parent.Children.Add($"CN={name}", "group");
        child.Properties["sAMAccountName"].Value = name;
        child.CommitChanges();
    }

    private static void CreateOurGroup(string name)
    {
        using var parent = OurEntry(DifferentialSettings.UsersContainer);
        using var child = parent.Children.Add($"CN={name}", "group");
        child.Properties["sAMAccountName"].Value = name;
        child.CommitChanges();
    }

    private static bool MicrosoftEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = MicrosoftEntry(distinguishedName);
            entry.RefreshCache();
            return true;
        }
        catch (Ms.DirectoryServicesCOMException)
        {
            return false;
        }
    }

    private static bool OurEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = OurEntry(distinguishedName);
            entry.RefreshCache();
            return true;
        }
        catch (Ours.DirectoryServicesCOMException error)
            when (error.ErrorCode == unchecked((int)0x80072030))
        {
            return false;
        }
    }

    private static void SafeDeleteMicrosoft(string distinguishedName)
    {
        try
        {
            using var entry = MicrosoftEntry(distinguishedName);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup for a failed differential assertion.
        }
    }

    private static void SafeDeleteOur(string distinguishedName)
    {
        try
        {
            using var entry = OurEntry(distinguishedName);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup for a failed differential assertion.
        }
    }
}
