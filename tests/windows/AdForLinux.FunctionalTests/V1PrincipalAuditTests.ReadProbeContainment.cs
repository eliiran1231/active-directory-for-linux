using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Text.RegularExpressions;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Scope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private const string ProbeFixtureDn = "CN=item,DC=example,DC=test";
    private const string ProbeSchemaDn = "CN=Schema,CN=Configuration,DC=example,DC=test";
    private static LdapReadOnlyProbePolicy ProbePolicy(TimeProvider? clock = null)
        => new("offline.invalid", ProbeFixtureDn, ProbeSchemaDn, clock);
    private static LdapConnectionOptions ProbeOptions(LdapReadOnlyProbePolicy policy,
        string host = "offline.invalid", int port = 636, bool ssl = true, bool startTls = false,
        bool skip = false, AuthType auth = AuthType.Basic) => new()
    {
        Host = host, Port = port, UseSsl = ssl, UseStartTls = startTls, SkipCertificateCheck = skip,
        AuthenticationType = auth, BindDn = "synthetic-reader", BindPassword = "synthetic-test-value",
        Timeout = TimeSpan.FromSeconds(10), ReadOnlyProbe = policy,
    };

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("tls")]
    [InlineData("starttls")]
    [InlineData("bypass")]
    [InlineData("auth")]
    [InlineData("referrals")]
    public void Read_probe_rejects_changed_recipe_and_latches_before_admission(string change)
    {
        var policy = ProbePolicy();
        var options = ProbeOptions(policy, host: change == "host" ? "other.invalid" : "offline.invalid",
            port: change == "port" ? 3269 : 636, ssl: change != "tls", startTls: change == "starttls",
            skip: change == "bypass", auth: change == "auth" ? AuthType.Negotiate : AuthType.Basic);
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => policy.ValidateAdmission(options,
            change == "referrals" ? ReferralChasingOption.External : ReferralChasingOption.None));
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(policy.Check);
    }

    [Theory]
    [InlineData("path")]
    [InlineData("user")]
    [InlineData("password")]
    [InlineData("auth")]
    [InlineData("referral")]
    [InlineData("gc")]
    [InlineData("foreign")]
    [InlineData("validate")]
    [InlineData("save")]
    [InlineData("drop-recipe")]
    public void Read_probe_selected_handles_cannot_drop_scope_or_start_writes(string change)
    {
        var policy = ProbePolicy();
        using var context = new PrincipalContext(policy, "synthetic-reader", "synthetic-test-value");
        using var entry = context.CreateDirectoryEntry(ProbeFixtureDn);
        Assert.Equal(ReferralChasingOption.None, entry.Options.Referral);
        Assert.Same(policy, entry.BuildOptions().Clone().ReadOnlyProbe);
        var sends = 0;
        entry.WriteRequestOverride = _ => { sends++; return ResultCode.Success; };
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() =>
        {
            switch (change)
            {
                case "path": entry.Path = "LDAP://other.invalid:636/" + ProbeFixtureDn; break;
                case "user": entry.Username = "other"; break;
                case "password": entry.Password = "other"; break;
                case "auth": entry.AuthenticationType = AuthenticationTypes.None; break;
                case "referral": entry.Options.Referral = ReferralChasingOption.All; break;
                case "gc": context.CreateGlobalCatalogEntry(ProbeFixtureDn); break;
                case "foreign": context.GetForeignDomainContext("foreign.invalid"); break;
                case "validate": context.ValidateCredentials("other", "other"); break;
                case "save": entry.CommitChanges(); break;
                case "drop-recipe":
                    typeof(DirectoryEntry).GetField("_connectionOptionsOverride", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .SetValue(entry, new LdapConnectionOptions { Host = "offline.invalid", Port = 636, UseSsl = true,
                            BindDn = "synthetic-reader", BindPassword = "synthetic-test-value", Timeout = TimeSpan.FromSeconds(10) });
                    entry.BuildOptions(); break;
            }
        });
        Assert.Equal(0, sends);
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(policy.Check);
    }

    [Theory]
    [InlineData("reference")]
    [InlineData("referral")]
    [InlineData("status")]
    [InlineData("wrong-dn")]
    [InlineData("absent")]
    [InlineData("multiple")]
    public void Read_probe_rejects_bad_envelopes_on_actual_Protocols_send_and_stops_later_reads(string fault)
    {
        var policy = ProbePolicy();
        var sends = 0;
        using var connection = SaveReadConnection.Create(_ =>
        {
            sends++;
            return SaveResponse(fault == "wrong-dn" ? "CN=other,DC=example,DC=test" : ProbeFixtureDn, [],
                fault == "absent" ? 0 : fault == "multiple" ? 2 : 1,
                fault == "status" ? ResultCode.SizeLimitExceeded : ResultCode.Success,
                fault == "referral", fault == "reference");
        }, () => { });
        policy.Register(connection);
        var request = new SearchRequest(ProbeFixtureDn, "(objectClass=*)", Scope.Base, "objectGUID");
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => connection.SendRequestTracked(request));
        Assert.Equal(1, sends);
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => connection.SendRequestTracked(request));
        Assert.Equal(1, sends);
        Assert.True(connection.Timeout > TimeSpan.Zero && connection.Timeout <= TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData("write")]
    [InlineData("subtree")]
    [InlineData("outside")]
    [InlineData("control")]
    [InlineData("alias")]
    public void Read_probe_refuses_out_of_scope_requests_before_dispatch(string shape)
    {
        var policy = ProbePolicy();
        var sends = 0;
        DirectoryRequest request = shape == "write" ? new DeleteRequest(ProbeFixtureDn)
            : new SearchRequest(shape == "outside" ? "DC=example,DC=test" : ProbeFixtureDn,
                "(objectClass=*)", shape == "subtree" ? Scope.Subtree : Scope.Base, "cn");
        if (shape == "control") request.Controls.Add(new PageResultRequestControl(5));
        if (shape == "alias") ((SearchRequest)request).Aliases = System.DirectoryServices.Protocols.DereferenceAlias.FindingBaseObject;
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => policy.Execute(request, _ =>
        { sends++; return SaveResponse(ProbeFixtureDn, [], 1, ResultCode.Success, false, false); }));
        Assert.Equal(0, sends);
    }

    private sealed class ProbeClock : TimeProvider
    {
        internal long Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
    }

    [Theory]
    [InlineData("async")]
    [InlineData("stream")]
    [InlineData("paging")]
    [InlineData("subtree")]
    [InlineData("asq")]
    [InlineData("root")]
    public void Read_probe_unsupported_search_modes_refuse_before_any_connection_acquisition(string mode)
    {
        var policy = ProbePolicy();
        using var root = new DirectoryEntry("LDAP://offline.invalid:636/" + ProbeFixtureDn, ProbeOptions(policy));
        var acquisitions = 0;
        root.OperationSessionFactory = (_, _, _, _, _) => { acquisitions++; throw new InvalidOperationException(); };
        using var searcher = new DirectorySearcher(root) { SearchScope = AdForLinux.DirectoryServices.SearchScope.Base, ReferralChasing = ReferralChasingOption.None };
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() =>
        {
            switch (mode)
            {
                case "async": searcher.Asynchronous = true; break;
                case "stream": searcher.CacheResults = false; break;
                case "paging": searcher.PageSize = 10; break;
                case "subtree": searcher.SearchScope = AdForLinux.DirectoryServices.SearchScope.Subtree; break;
                case "asq": searcher.AttributeScopeQuery = "member"; break;
                case "root": searcher.SearchRoot = new DirectoryEntry("LDAP://other.invalid:636/" + ProbeFixtureDn); break;
            }
            using var results = searcher.FindAll();
        });
        Assert.Equal(0, acquisitions);
    }

    [Fact]
    public void Read_probe_keys_are_isolated_and_retained_raw_handles_are_refused()
    {
        var policy = ProbePolicy(); var options = ProbeOptions(policy);
        Assert.Equal(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None),
            LdapConnectionProvider.ConnectionKey.Create(options.Clone(), ReferralChasingOption.None));
        Assert.NotEqual(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None),
            LdapConnectionProvider.ConnectionKey.Create(ProbeOptions(ProbePolicy()), ReferralChasingOption.None));
        using var root = new DirectoryEntry("LDAP://offline.invalid:636/" + ProbeFixtureDn, options);
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => root.GetConnection());
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("duplicate-opt-in")]
    [InlineData("ip")]
    [InlineData("port")]
    [InlineData("guid")]
    [InlineData("nul")]
    [InlineData("dn")]
    public void Read_probe_pure_configuration_refuses_invalid_inputs_without_secret_or_connection_access(string shape)
    {
        var arguments = new List<string> { "--allow-live-read", "--host", "offline.invalid", "--port", "636",
            "--fixture-dn", ProbeFixtureDn, "--schema-dn", ProbeSchemaDn, "--sam", "known", "--guid", "c26aba77-e788-46b0-90dc-f434cd707608" };
        switch (shape)
        {
            case "unknown": arguments.AddRange(["--password", "synthetic"]); break;
            case "missing": arguments.RemoveAt(arguments.Count - 1); break;
            case "duplicate": arguments.AddRange(["--host", "offline.invalid"]); break;
            case "duplicate-opt-in": arguments.Add("--allow-live-read"); break;
            case "ip": arguments[2] = "127.0.0.1"; break;
            case "port": arguments[4] = "389"; break;
            case "guid": arguments[^1] = Guid.Empty.ToString(); break;
            case "nul": arguments[10] = "known\0"; break;
            case "dn": arguments[6] = "<GUID=unknown>"; break;
        }
        Assert.Throws<ArgumentException>(() => AdForLinux.ReadProbe.ProbeConfiguration.Parse(arguments.ToArray()));
    }

    [Fact]
    public void Read_probe_late_success_and_shared_deadline_never_publish_success()
    {
        var clock = new ProbeClock(); var policy = ProbePolicy(clock);
        var request = new SearchRequest(ProbeFixtureDn, "(objectClass=*)", Scope.Base);
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => policy.Execute(request, timeout =>
        {
            Assert.Equal(TimeSpan.FromSeconds(10), timeout);
            clock.Ticks = TimeSpan.FromSeconds(61).Ticks;
            return SaveResponse(ProbeFixtureDn, [], 1, ResultCode.Success, false, false);
        }));
        Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(policy.Check);
    }

    [Theory]
    [InlineData("healthy")]
    [InlineData("reference")]
    [InlineData("missing-syntax")]
    [InlineData("duplicate")]
    [InlineData("unexpected")]
    [InlineData("schema-base-row")]
    [InlineData("empty")]
    public void Read_probe_policy_survives_real_deferred_AccountManagement_attachment(string schemaShape)
    {
        var policy = ProbePolicy();
        using var context = new PrincipalContext(policy, "synthetic-reader", "synthetic-test-value");
        var reads = new List<SearchRequest>(); var closes = 0; var opens = 0; var corruptSid = false;
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        SaveReadConnection Open(LdapConnectionOptions options)
        {
                policy.ValidateAdmission(options, ReferralChasingOption.None);
                opens++;
                var connection = SaveReadConnection.Create(raw =>
                {
                    var request = Assert.IsType<SearchRequest>(raw); reads.Add(request);
                    if (request.DistinguishedName.Length == 0)
                        return SaveResponse("", new() { ["schemaNamingContext"] = [ProbeSchemaDn] }, 1, ResultCode.Success, false, false);
                    if (request.DistinguishedName == ProbeSchemaDn)
                    {
                        if (schemaShape == "reference") return SaveResponse("", [], 0, ResultCode.Success, false, true);
                        var response = SaveResponse("", [], 0, ResultCode.Success, false, false);
                        if (schemaShape == "empty") return response;
                        foreach (Match match in Regex.Matches((string)request.Filter, @"\(lDAPDisplayName=([^()]+)\)"))
                        {
                            var name = match.Groups[1].Value;
                            var binary = new[] { "objectGUID", "objectSid", "nTSecurityDescriptor" }.Contains(name, StringComparer.OrdinalIgnoreCase);
                            var values = new Dictionary<string, object[]>()
                            {
                                ["lDAPDisplayName"] = [schemaShape == "unexpected" ? "unsolicited" : name],
                                ["attributeSyntax"] = [binary ? "2.5.5.10" : "2.5.5.12"], ["oMSyntax"] = [binary ? "4" : "64"],
                            };
                            if (schemaShape == "missing-syntax") values.Remove("attributeSyntax");
                            var row = SaveResponse(schemaShape == "schema-base-row" ? ProbeSchemaDn : "CN=" + name + "," + ProbeSchemaDn,
                                values, 1, ResultCode.Success, false, false).Entries[0];
                            typeof(SearchResultEntryCollection).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(response.Entries, [row]);
                            if (schemaShape == "duplicate")
                                typeof(SearchResultEntryCollection).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(response.Entries, [row]);
                        }
                        return response;
                    }
                    return SaveResponse(ProbeFixtureDn, request.Attributes.Contains("1.1") ? [] : new()
                    {
                        ["objectGUID"] = [new Guid("c26aba77-e788-46b0-90dc-f434cd707608").ToByteArray()],
                        ["objectSid"] = [corruptSid ? SecurityDescriptorFixtures.U1.Concat(new byte[] { 0 }).ToArray() : SecurityDescriptorFixtures.U1], ["objectClass"] = ["top", "user"],
                        ["sAMAccountName"] = ["known"], ["description"] = ["description"],
                    }, 1, ResultCode.Success, false, false);
                }, () => closes++);
                policy.Register(connection);
                return connection;
        }
        LdapConnectionProvider.Session[] Acquire(LdapConnectionOptions options, int count, ReferralChasingOption referrals, bool fresh, long minimum)
        {
            policy.ValidateAdmission(options, referrals);
            Assert.Same(policy, options.ReadOnlyProbe);
            return pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count,
                () => new BoundLdapSession(Open(options), options, new(options), referrals), reusable: false)
                .Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        context.SearchRoot.OperationSessionFactory = Acquire;
        using var query = new UserPrincipal(context) { SamAccountName = "known" };
        using var searcher = new PrincipalSearcher(query);
        var rawSearcher = Assert.IsType<DirectorySearcher>(searcher.GetUnderlyingSearcher());
        rawSearcher.SearchScope = AdForLinux.DirectoryServices.SearchScope.Base;
        rawSearcher.PageSize = 0; rawSearcher.CacheResults = true; rawSearcher.Asynchronous = false;
        rawSearcher.ConfigureConnectionOverride = _ => { };
        if (schemaShape != "healthy")
        {
            Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(() => searcher.FindAll());
            Assert.Throws<LdapReadOnlyProbePolicy.ProbePolicyException>(policy.Check);
        }
        else
        {
            using var results = searcher.FindAll();
            using var cursor = results.GetEnumerator(); Assert.True(cursor.MoveNext());
            using var user = Assert.IsType<UserPrincipal>(cursor.Current);
            Assert.Equal("known", user.SamAccountName); Assert.Equal("description", user.Description);
            Assert.Equal(new Guid("c26aba77-e788-46b0-90dc-f434cd707608"), user.Guid);
            var entry = Assert.IsType<DirectoryEntry>(user.GetUnderlyingObject());
            Assert.Same(policy, entry.ReadOnlyProbe); Assert.Equal(ReferralChasingOption.None, entry.Options.Referral);
            Assert.False(cursor.MoveNext()); policy.Check();
            Assert.Contains(reads, request => request.Attributes.Contains("*"));
            AdForLinux.ReadProbe.ProbeReads.Run(new("offline.invalid", ProbeFixtureDn, ProbeSchemaDn,
                "known", new Guid("c26aba77-e788-46b0-90dc-f434cd707608")), policy,
                "synthetic-reader", "synthetic-test-value", controlledBaseline: Open,
                controlledEntry: entry => entry.OperationSessionFactory = Acquire,
                controlledContext: selected => selected.SearchRoot.OperationSessionFactory = Acquire,
                controlledSearcher: selected => selected.ConfigureConnectionOverride = _ => { });
            policy.Check();
            Assert.Throws<InvalidOperationException>(() => AdForLinux.ReadProbe.ProbeReads.Run(
                new("offline.invalid", ProbeFixtureDn, ProbeSchemaDn, "known", new Guid("d7387998-5d0c-4fad-9c13-e116b841c1b6")),
                policy, "synthetic-reader", "synthetic-test-value", controlledBaseline: Open,
                controlledEntry: _ => throw new Exception("Baseline mismatch must stop before Entry construction.")));
            corruptSid = true;
            Assert.Throws<InvalidOperationException>(() => AdForLinux.ReadProbe.ProbeReads.Run(
                new("offline.invalid", ProbeFixtureDn, ProbeSchemaDn, "known", new Guid("c26aba77-e788-46b0-90dc-f434cd707608")),
                policy, "synthetic-reader", "synthetic-test-value", controlledBaseline: Open,
                controlledEntry: _ => throw new Exception("Malformed SID must stop before Entry construction.")));
        }
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(opens, closes);
        Assert.All(reads, request => Assert.Contains(request.DistinguishedName, new[] { "", ProbeFixtureDn, ProbeSchemaDn }));
        Assert.False(new LdapAuthenticationSource(ProbeOptions(ProbePolicy())).Freshness(ReferralChasingOption.None)
            == LdapSessionFreshness.CompatibleEstablishedSession);
    }
}
