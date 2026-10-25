using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Referral = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

public sealed class WindowsContinuationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Continuation_is_reference_then_local_entry_then_terminal_result(bool partial)
    {
        const string uri = "ldaps://127.0.0.1:1636/CN=target??base?(objectClass=*)";
        var reader = new AsnReader(WindowsReferralEndpoint.ContinuationResponse(17, "synthetic", uri, partial), AsnEncodingRules.BER);
        var reference = reader.ReadSequence(); Assert.Equal(17, (int)reference.ReadInteger());
        var urls = reference.ReadSequence(new Asn1Tag(TagClass.Application, 19, true));
        Assert.Equal(uri, Encoding.UTF8.GetString(urls.ReadOctetString()));
        urls.ThrowIfNotEmpty(); reference.ThrowIfNotEmpty();
        var message = reader.ReadSequence(); Assert.Equal(17, (int)message.ReadInteger());
        var entry = message.ReadSequence(new Asn1Tag(TagClass.Application, 4, true));
        Assert.Equal("CN=local,CN=target", Encoding.UTF8.GetString(entry.ReadOctetString()));
        var attributes = entry.ReadSequence(); var attribute = attributes.ReadSequence();
        Assert.Equal("description", Encoding.UTF8.GetString(attribute.ReadOctetString()));
        var values = attribute.ReadSetOf(); Assert.Equal("synthetic", Encoding.UTF8.GetString(values.ReadOctetString()));
        values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty(); entry.ThrowIfNotEmpty(); message.ThrowIfNotEmpty();
        var done = reader.ReadSequence(); Assert.Equal(17, (int)done.ReadInteger());
        var result = done.ReadSequence(new Asn1Tag(TagClass.Application, 5, true));
        Assert.Equal(partial ? ResultCode.SizeLimitExceeded : ResultCode.Success, result.ReadEnumeratedValue<ResultCode>());
        Assert.Empty(result.ReadOctetString()); Assert.Empty(result.ReadOctetString());
        result.ThrowIfNotEmpty(); done.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
    }

    [Theory]
    [InlineData(SearchScope.OneLevel)]
    [InlineData(SearchScope.Subtree)]
    public void Continuation_capability_still_requires_explicit_scope_and_loopback_host(SearchScope scope)
    {
        LdapConnectionOptions Options(string host = "127.0.0.1", bool skip = false, bool startTls = false) =>
            new() { Host = host, Port = 1636, UseSsl = true, BindDn = "synthetic", BindPassword = "synthetic",
                SkipCertificateCheck = skip, UseStartTls = startTls };
        var options = Options();
        var request = new SearchRequest("CN=target", "(objectClass=*)", scope) { SizeLimit = 1 };
        bool Allowed(SearchScope? permitted) => LdapConnectionProvider.IsContextScopedDiagnosticConfiguration(options, Referral.External, request, permitted);
        Assert.True(Allowed(scope)); Assert.False(Allowed(null));
        Assert.False(Allowed(scope == SearchScope.OneLevel ? SearchScope.Subtree : SearchScope.OneLevel));
        Assert.True(LdapConnectionProvider.IsContextScopedReadConfiguration(options, Referral.External, request));
        request.SizeLimit = 0; Assert.False(Allowed(scope)); request.SizeLimit = 1;
        request.Controls.Add(new PageResultRequestControl(1)); Assert.False(Allowed(scope)); request.Controls.Clear();
        options = Options(skip: true); Assert.False(Allowed(scope));
        options = Options(startTls: true); Assert.False(Allowed(scope));
        options = Options(host: "directory.example"); Assert.False(Allowed(scope));
    }

    [Theory]
    [InlineData(false, false, 3)]
    [InlineData(false, true, 3)]
    [InlineData(true, false, 4)]
    [InlineData(true, true, 5)]
    public void Final_counts_reject_late_duplicate_and_missing_referral(bool scoped, bool partial, int binds)
    {
        int[] counts = [binds, 7, 1, 4, 2, 2, 1, 2];
        Assert.True(WindowsContinuationDiagnostic.CountsMatch(counts, scoped, partial));
        for (int i = 0; i < counts.Length; i++)
        {
            var changed = (int[])counts.Clone(); changed[i] = 0;
            Assert.False(WindowsContinuationDiagnostic.CountsMatch(changed, scoped, partial));
        }
        counts[7]++; Assert.False(WindowsContinuationDiagnostic.CountsMatch(counts, scoped, partial));
    }

    [Theory]
    [InlineData("original-direct", 0)]
    [InlineData("original-referral", 0)]
    [InlineData("a-direct", 4)]
    [InlineData("anonymous-direct", 4)]
    public void Scheduling_preserves_original_dependencies_without_hiding_other_failures(string failed, int expected)
    {
        var native = WindowsAuthenticatedDiagnostic.Schedule((_, _) => new("passed", 0, 0, 0, 0, 0, 0));
        native[failed] = native[failed] with { Status = "failed" };
        int invoked = 0;
        var cases = WindowsContinuationDiagnostic.Schedule(native, _ => { invoked++; return new("failed", true, Empty(), Empty()); });
        Assert.Equal(expected, invoked); Assert.Equal(4, cases.Count);
        Assert.Equal("failed", WindowsContinuationDiagnostic.CreateReport(native, cases).Supported);
    }

    private static WindowsContinuationDiagnostic.Observation Empty() => new("passed", "complete", "none", 0, true, 0, 2, 2,
        [0, 0], ["local", "local"], 3, 7, 1, 4, 2, 2, 1, 2, true, 0);

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public void Every_cleanup_is_attempted_despite_any_combination_of_failures(int mask)
    {
        var attempted = new List<int>();
        var actions = Enumerable.Range(0, 3).Select(index => (Action)(() =>
        { attempted.Add(index); if ((mask & (1 << index)) != 0) throw new IOException("synthetic"); })).ToArray();
        Assert.Equal(mask == 0, WindowsContinuationDiagnostic.CleanupAll(actions));
        Assert.Equal(new[] { 0, 1, 2 }, attempted);
    }

    [Theory]
    [InlineData(SearchScope.OneLevel)]
    [InlineData(SearchScope.Subtree)]
    public void External_fixture_validates_actual_request_scope_and_limit(SearchScope scope)
    {
        bool Match(SearchScope requested, int limit, string dn = "CN=target")
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            writer.WriteEnumeratedValue(requested); writer.WriteEnumeratedValue(DereferenceAlias.Never); writer.WriteInteger(limit);
            return WindowsReferralEndpoint.MatchesScopedSearch(Encoding.UTF8.GetBytes(dn), new AsnReader(writer.Encode(), AsnEncodingRules.BER), scope);
        }
        Assert.True(Match(scope, 1)); Assert.False(Match(SearchScope.Base, 1));
        Assert.False(Match(scope, 0)); Assert.False(Match(scope, 2)); Assert.False(Match(scope, 1, "CN=other"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void External_contract_requires_target_searches_without_relabeling_continuation_failures(bool scoped)
    {
        int[] counts = [scoped ? 4 : 3, 7, 1, 4, 0, 0, 1, 2];
        Assert.True(WindowsContinuationDiagnostic.ExternalCountsMatch(counts, scoped));
        Assert.False(WindowsContinuationDiagnostic.CountsMatch(counts, scoped, false));
        counts[6] = 0; counts[7] = 0;
        Assert.False(WindowsContinuationDiagnostic.ExternalCountsMatch(counts, scoped));
        counts[4] = 2; counts[5] = 2; // Historical unchased continuation observations remain failed.
        Assert.False(WindowsContinuationDiagnostic.CountsMatch(counts, scoped, false));
        counts[4] = 0; counts[5] = 0; counts[6] = 1; counts[7] = 3;
        Assert.False(WindowsContinuationDiagnostic.ExternalCountsMatch(counts, scoped));
    }

    [Fact]
    public void External_inventory_is_separate_and_original_dependency_gated()
    {
        var native = WindowsAuthenticatedDiagnostic.Schedule((_, _) => new("passed", 0, 0, 0, 0, 0, 0));
        int calls = 0;
        WindowsContinuationDiagnostic.Comparison Execute(string name)
        { calls++; return new("failed", true, Empty(), Empty()); }
        var cases = WindowsContinuationDiagnostic.ScheduleExternal(native, Execute);
        Assert.Equal(new[] { "onelevel/external", "subtree/external" }, cases.Keys);
        Assert.Equal(2, calls); Assert.Equal(4, WindowsContinuationDiagnostic.Names.Length);
        native["original-referral"] = native["original-referral"] with { Status = "failed" };
        calls = 0; cases = WindowsContinuationDiagnostic.ScheduleExternal(native, Execute);
        Assert.Equal(0, calls); Assert.All(cases.Values, c => Assert.Equal("skipped", c.Status));
    }

    [Fact]
    public void Comparison_preserves_order_partial_result_and_cleanup_failures()
    {
        var value = Empty();
        Assert.Equal("passed", WindowsContinuationDiagnostic.Compare(value, value).Status);
        Assert.Equal("failed", WindowsContinuationDiagnostic.Compare(value, value with { Returned = ["target", "local"] }).Status);
        Assert.Equal("failed", WindowsContinuationDiagnostic.Compare(value, value with { Results = [4, 4] }).Status);
        Assert.Equal("failed", WindowsContinuationDiagnostic.Compare(value, value with { Cleanup = false }).Status);
        Assert.Equal("failed", WindowsContinuationDiagnostic.Compare(value, value with { Status = "failed", FailureCode = 81 }).Status);
    }
}
