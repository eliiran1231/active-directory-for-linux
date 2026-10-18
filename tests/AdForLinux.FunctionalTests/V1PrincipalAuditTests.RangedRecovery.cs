using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Runtime.CompilerServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class RangedReadConnection : LdapConnection
    {
        private RangedReadConnection() : base("offline.invalid") { }
        private Func<SearchResponse> _response = null!;
        internal static RangedReadConnection Create(Func<SearchResponse> response)
        {
            // No native LDAP handle or socket is needed: every request is handled
            // below. Skip the native constructor so this is offline on Linux too.
            var connection = (RangedReadConnection)RuntimeHelpers.GetUninitializedObject(typeof(RangedReadConnection));
            connection._response = response;
            return connection;
        }
        protected override void Dispose(bool disposing) { }
        internal int ObjectReads;
        public override DirectoryResponse SendRequest(DirectoryRequest request)
        {
            var search = Assert.IsType<SearchRequest>(request);
            // Real SearchEntryReader schema resolution gets a schema-less rootDSE;
            // servicePrincipalName then takes its ordinary string fallback.
            if (string.IsNullOrEmpty(search.DistinguishedName)) return RawResponse();
            Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, search.Scope);
            ObjectReads++;
            return _response();
        }
    }

    private static SearchResponse RawResponse(params (string Name, string[] Values)[] attributes)
        => RawResponseWithStatus(ResultCode.Success, [], attributes);

    private static SearchResponse RawResponseWithStatus(ResultCode resultCode, Uri[] referrals,
        params (string Name, string[] Values)[] attributes)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var response = (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
            new object?[] { null, Array.Empty<DirectoryControl>(), resultCode, null, referrals }, null)!;
        var entry = (SearchResultEntry)Activator.CreateInstance(typeof(SearchResultEntry), flags, null,
            new object[] { "CN=item,DC=example,DC=test" }, null)!;
        foreach (var (name, values) in attributes)
        {
            var attribute = new DirectoryAttribute(name, values.Cast<object>().ToArray());
            typeof(SearchResultAttributeCollection).GetMethod("Add", flags)!.Invoke(entry.Attributes, [name, attribute]);
        }
        typeof(SearchResultEntryCollection).GetMethod("Add", flags)!.Invoke(response.Entries, [entry]);
        return response;
    }

    private static RangedReadConnection InstallRawRead(Fixture fixture, Func<SearchResponse> response)
    {
        fixture.Entry.PropertyReadOverride = null;
        var connection = RangedReadConnection.Create(response);
        foreach (var field in new[] { "_connection", "_schemaConnection" })
            typeof(DirectoryEntry).GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(fixture.Entry, connection);
        return connection;
    }

    private static SearchResponse SpnResponse(string shape) => shape switch
    {
        "absent" => RawResponse(),
        "empty-bare" => RawResponse(("servicePrincipalName", [])),
        "empty-terminal" => RawResponse(("servicePrincipalName;range=0-*", [])),
        "bare" => RawResponse(("servicePrincipalName", ["HOST/keep"])),
        "terminal" => RawResponse(("servicePrincipalName;range=0-*", ["HOST/keep"])),
        "terminal-empty-bare" => RawResponse(("servicePrincipalName", []), ("servicePrincipalName;range=0-*", ["HOST/keep"])),
        "nonterminal" => RawResponse(("servicePrincipalName;range=0-0", ["HOST/keep"])),
        "nonterminal-empty-bare" => RawResponse(("servicePrincipalName", []), ("servicePrincipalName;range=0-0", ["HOST/keep"])),
        "missing-prefix" => RawResponse(("servicePrincipalName;range=1-*", ["HOST/keep"])),
        "bad-low" => RawResponse(("servicePrincipalName;range=x-*", ["HOST/keep"])),
        "bad-high" => RawResponse(("servicePrincipalName;range=0-x", ["HOST/keep"])),
        "duplicate-option" => RawResponse(("servicePrincipalName;range=0-*;range=0-*", ["HOST/keep"])),
        "conflicting-bare" => RawResponse(("servicePrincipalName", ["HOST/other"]), ("servicePrincipalName;range=0-*", ["HOST/keep"])),
        "conflicting-ranges" => RawResponse(("servicePrincipalName;range=0-*", ["HOST/keep"]), ("servicePrincipalName;range=1-*", ["HOST/other"])),
        "unknown-option" => RawResponse(("servicePrincipalName;range=0-*;other", ["HOST/keep"])),
        _ => throw new ArgumentOutOfRangeException(nameof(shape)),
    };

    [Theory]
    [InlineData("nonterminal", false)] [InlineData("nonterminal", true)]
    [InlineData("nonterminal-empty-bare", false)] [InlineData("nonterminal-empty-bare", true)]
    [InlineData("missing-prefix", false)] [InlineData("missing-prefix", true)]
    [InlineData("bad-low", false)] [InlineData("bad-low", true)]
    [InlineData("bad-high", false)] [InlineData("bad-high", true)]
    [InlineData("duplicate-option", false)] [InlineData("duplicate-option", true)]
    [InlineData("conflicting-bare", false)] [InlineData("conflicting-bare", true)]
    [InlineData("conflicting-ranges", false)] [InlineData("conflicting-ranges", true)]
    [InlineData("unknown-option", false)] [InlineData("unknown-option", true)]
    public void Raw_ranged_spn_readback_cannot_acknowledge_absence_or_change_cached_intent(string shape, bool full)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Remove("HOST/old");
        f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save()); f.BeforeWrite = null;
        var cache = f.Entry.Properties; var property = cache["servicePrincipalName"];
        var uncertaintyField = typeof(DirectoryEntry).GetField("_uncertainWrite", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var uncertainty = uncertaintyField.GetValue(f.Entry);
        var version = property.ChangeVersion;
        using var connection = InstallRawRead(f, () => SpnResponse(shape));
        Assert.Throws<InvalidOperationException>(() => { if (full) f.Entry.RefreshCache(); else f.Entry.RefreshCache(new[] { "servicePrincipalName" }); });
        Assert.Equal(1, connection.ObjectReads);
        Assert.Same(cache, f.Entry.Properties); Assert.Same(property, cache["servicePrincipalName"]);
        Assert.Equal(new object[] { "HOST/old" }, property.Cast<object>());
        Assert.Equal(version, property.ChangeVersion);
        Assert.Same(uncertainty, uncertaintyField.GetValue(f.Entry));
        Assert.Empty(computer.ServicePrincipalNames);
        Assert.Throws<InvalidOperationException>(() => computer.Save()); Assert.Equal(1, f.Attempts);
    }

    [Theory]
    [InlineData("bare", false)] [InlineData("bare", true)]
    [InlineData("terminal", false)] [InlineData("terminal", true)]
    [InlineData("terminal-empty-bare", false)] [InlineData("terminal-empty-bare", true)]
    [InlineData("absent", false)] [InlineData("absent", true)]
    [InlineData("empty-bare", false)] [InlineData("empty-bare", true)]
    [InlineData("empty-terminal", false)] [InlineData("empty-terminal", true)]
    public void Raw_complete_spn_readback_can_reconcile_and_normalize_without_replay(string shape, bool full)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Remove("HOST/old");
        f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save()); f.BeforeWrite = null;
        using var connection = InstallRawRead(f, () => SpnResponse(shape));
        if (full) f.Entry.RefreshCache(); else f.Entry.RefreshCache(new[] { "servicePrincipalName" });
        Assert.Equal(shape == "absent" || shape.StartsWith("empty-") ? Array.Empty<object>() : new object[] { "HOST/keep" },
            f.Entry.Properties["servicePrincipalName"].Cast<object>());
        Assert.DoesNotContain(f.Entry.Properties.PropertyNames.Cast<string>(), name => name.Contains(";range="));
        computer.Save(); Assert.Equal(1, f.Attempts); Assert.Empty(computer.ServicePrincipalNames);
    }

    [Theory]
    [InlineData("status")] [InlineData("referral")] [InlineData("reference")]
    [InlineData("empty")] [InlineData("multiple")]
    public void Raw_unsuccessful_or_referred_spn_readback_cannot_release_uncertainty(string shape)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        computer.ServicePrincipalNames.Remove("HOST/old"); f.BeforeWrite = () => throw new TimeoutException();
        Assert.ThrowsAny<Exception>(() => computer.Save()); f.BeforeWrite = null;
        var cache = f.Entry.Properties;
        using var connection = InstallRawRead(f, () =>
        {
            const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var response = RawResponseWithStatus(shape == "status" ? ResultCode.SizeLimitExceeded : ResultCode.Success,
                shape == "referral" ? [new Uri("ldap://other.invalid/")] : [], ("servicePrincipalName", ["HOST/keep"]));
            if (shape == "empty") typeof(SearchResponse).GetField("_entryCollection", flags)!.SetValue(response,
                Activator.CreateInstance(typeof(SearchResultEntryCollection), nonPublic: true));
            if (shape == "multiple") typeof(SearchResultEntryCollection).GetMethod("Add", flags)!.Invoke(response.Entries, [response.Entries[0]]);
            if (shape == "reference")
            {
                var reference = Activator.CreateInstance(typeof(SearchResultReference), flags, null,
                    new object[] { new[] { new Uri("ldap://other.invalid/") } }, null);
                typeof(SearchResultReferenceCollection).GetMethod("Add", flags)!.Invoke(response.References, [reference]);
            }
            return response;
        });
        Assert.Throws<InvalidOperationException>(() => f.Entry.RefreshCache(new[] { "servicePrincipalName" }));
        Assert.Same(cache, f.Entry.Properties);
        Assert.Equal(new object[] { "HOST/old" }, cache["servicePrincipalName"].Cast<object>());
        Assert.Throws<InvalidOperationException>(() => computer.Save()); Assert.Equal(1, f.Attempts);
    }

    [Fact]
    public void Ordinary_raw_ranged_read_exercises_loader_normalization()
    {
        using var f = new Fixture();
        using var connection = InstallRawRead(f, () => SpnResponse("nonterminal-empty-bare"));
        f.Entry.RefreshCache(new[] { "servicePrincipalName" });
        Assert.Equal(new object[] { "HOST/keep" }, f.Entry.Properties["servicePrincipalName"].Cast<object>());
        Assert.Equal(1, connection.ObjectReads);
    }
}
