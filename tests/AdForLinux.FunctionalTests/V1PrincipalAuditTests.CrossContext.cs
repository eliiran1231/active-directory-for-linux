using System.Reflection;
using System.Runtime.CompilerServices;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class SaveReadConnection : LdapConnection
    {
        private SaveReadConnection() : base("offline.invalid") { }
        private Func<DirectoryRequest, DirectoryResponse> read = null!;
        private Action close = null!;
        internal static SaveReadConnection Create(Func<DirectoryRequest, DirectoryResponse> read, Action close)
        {
            var connection = (SaveReadConnection)RuntimeHelpers.GetUninitializedObject(typeof(SaveReadConnection));
            connection.read = read; connection.close = close; connection.Timeout = TimeSpan.FromSeconds(30); return connection;
        }
        public override DirectoryResponse SendRequest(DirectoryRequest request)
        {
            Assert.True(Timeout > TimeSpan.Zero);
            return read(request);
        }
        protected override void Dispose(bool disposing) { if (disposing) close(); }
    }
    private static SearchResponse SaveResponse(string dn, Dictionary<string, object[]> values, int count,
        ResultCode status, bool referrals, bool references)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var response = (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
            new object?[] { null, Array.Empty<DirectoryControl>(), status, null,
                referrals ? new[] { new Uri("ldap://never-follow.invalid/") } : Array.Empty<Uri>() }, null)!;
        for (var i = 0; i < count; i++)
        {
            var entry = (SearchResultEntry)Activator.CreateInstance(typeof(SearchResultEntry), flags, null, new object[] { dn }, null)!;
            foreach (var (name, data) in values)
                typeof(SearchResultAttributeCollection).GetMethod("Add", flags)!.Invoke(entry.Attributes, [name, new DirectoryAttribute(name, data)]);
            typeof(SearchResultEntryCollection).GetMethod("Add", flags)!.Invoke(response.Entries, [entry]);
        }
        if (references)
        {
            var reference = (SearchResultReference)Activator.CreateInstance(typeof(SearchResultReference), flags, null,
                new object[] { new[] { new Uri("ldap://never-follow.invalid/") } }, null)!;
            typeof(SearchResultReferenceCollection).GetMethod("Add", flags)!.Invoke(response.References, [reference]);
        }
        return response;
    }
    private sealed class SaveUser(PrincipalContext context) : UserPrincipal(context)
    {
        internal void SetExtension(string value) => ExtensionSet("department", value);
        internal object?[] GetExtension() => ExtensionGet("department");
    }
    private sealed class CrossContextFixture : IDisposable
    {
        internal const string DomainDn = "DC=example,DC=test";
        internal const string ItemDn = "CN=item,OU=source," + DomainDn;
        internal readonly PrincipalContext Source = new(ContextType.Domain, "source.invalid", DomainDn,
            ContextOptions.Negotiate, "source-reader", "source-test-value");
        internal readonly PrincipalContext Destination = new(ContextType.Domain, "destination.invalid", DomainDn,
            ContextOptions.Negotiate, "destination-reader", "destination-test-value");
        internal readonly Guid DomainGuid = Guid.NewGuid(), ObjectGuid = Guid.NewGuid(), ContainerGuid = Guid.NewGuid();
        internal readonly string ObjectSid = new SecurityIdentifier(SecurityDescriptorFixtures.U1, 0).Value;
        internal string DomainSid => new SecurityIdentifier(ObjectSid).AccountDomainSid!.Value;
        internal readonly Guid ReplacementGuid = Guid.NewGuid();
        internal readonly DirectoryEntry Entry;
        internal readonly SaveUser User;
        internal readonly List<(bool Destination, string Path, string User)> Reads = [];
        internal string Fault = "";
        internal int Writes, Opens, Closes;
        internal readonly List<TimeSpan> OpenTimeouts = [];
        internal Action<int>? AfterRead;
        internal Action<int>? AfterOpen;
        internal int CorruptRead;
        internal ResultCode Status = ResultCode.Success;
        internal bool References, Referrals, ThrowResponse;
        internal string Omit = "";
        internal int? CountOverride;
        internal Action<Dictionary<string, object[]>>? ChangeValues;
        internal CrossContextFixture()
        {
            foreach (var context in new[] { Source, Destination })
                typeof(PrincipalContext).GetField("_defaultNamingContext", BindingFlags.NonPublic | BindingFlags.Instance)!
                    .SetValue(context, DomainDn);
            Entry = Source.CreateDirectoryEntry(ItemDn);
            Entry.PropertyReadOverride = (_, _) =>
            {
                var values = new PropertyCollection();
                values.ReplaceLoaded("objectGUID", [(Fault == "refreshed-replacement" ? ReplacementGuid : ObjectGuid).ToByteArray()]);
                values.ReplaceLoaded("objectSid", [SidBytes(ObjectSid)]);
                return values;
            };
            Entry.WriteRequestOverride = _ => { Writes++; return System.DirectoryServices.Protocols.ResultCode.Success; };
            // MoveTo bypasses the Modify write hook. Intercept its actual retained
            // connection too, so an attempted compensation cannot hide in a catch.
            typeof(DirectoryEntry).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(Entry, SaveReadConnection.Create(_ =>
                {
                    Writes++;
                    throw new InvalidOperationException("unexpected retained-entry transport request");
                }, () => { }));
            User = new SaveUser(Source);
            typeof(Principal).GetMethod("AttachExisting", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(User, [Source, Entry]);
            Source.SaveContextSessionFactory = options => Open(false, options);
            Destination.SaveContextSessionFactory = options => Open(true, options);
        }

        private CrossContextSaveSession Open(bool destination, LdapConnectionOptions options)
        {
            Assert.Equal(destination ? "destination.invalid" : "source.invalid", options.Host);
            Assert.Equal(destination ? "destination-reader" : "source-reader", options.BindDn);
            Assert.Equal(destination ? "destination-test-value" : "source-test-value", options.BindPassword);
            OpenTimeouts.Add(options.Timeout);
            Opens++;
            AfterOpen?.Invoke(Opens);
            return new CrossContextSaveSession(SaveReadConnection.Create(request => Read(destination, Assert.IsType<SearchRequest>(request)), () => Closes++));
        }
        internal SearchResponse Read(bool destination, SearchRequest request)
        {
            Assert.Equal(2, request.SizeLimit);
            Assert.Equal(System.DirectoryServices.Protocols.DereferenceAlias.Never, request.Aliases);
            var subtree = request.Scope == ProtocolScope.Subtree;
            if (subtree)
            {
                var control = Assert.Single(request.Controls.Cast<DirectoryControl>());
                Assert.Equal(AdIdentityLookup.DomainScopeControl, control.Type);
                Assert.True(control.IsCritical); Assert.True(control.ServerSide);
                Assert.Equal(DomainDn, request.DistinguishedName);
            }
            else Assert.Empty(request.Controls);
            Reads.Add((destination, request.DistinguishedName, destination ? "destination-reader" : "source-reader"));
            var domain = (string)request.Filter == "(objectClass=domainDNS)";
            var replica = ((string)request.Filter).StartsWith("(objectGUID=");
            var container = destination && subtree && !replica;
            var guid = domain ? DomainGuid : container ? ContainerGuid : ObjectGuid;
            if (destination && ((domain && Fault == "domain-guid") || (replica && Fault == "object-guid"))) guid = Guid.NewGuid();
            if (!domain && !container && Fault == "refreshed-replacement") guid = ReplacementGuid;
            if (container && Fault == "empty-container-guid") guid = Guid.Empty;
            var sid = domain ? DomainSid : ObjectSid;
            if (destination && ((domain && Fault == "domain-sid") || (replica && Fault == "object-sid")))
                sid = "S-1-5-21-900-901-902-903";
            if (!destination && subtree && Fault == "source-replaced") guid = Guid.NewGuid();
            var dn = domain || container ? DomainDn : ItemDn;
            if (container && Fault == "same-container") dn = "OU=source," + DomainDn;
            if (container && Fault == "nested-container") dn = "OU=valid," + DomainDn;
            var values = new Dictionary<string, object[]>
            {
                ["objectGUID"] = [guid.ToByteArray()], ["objectSid"] = [SidBytes(sid)], ["distinguishedName"] = [dn]
            };
            if (request.DistinguishedName.Length == 0)
            {
                dn = "";
                values = new()
                {
                    ["defaultNamingContext"] = [DomainDn], ["configurationNamingContext"] = ["CN=Configuration," + DomainDn],
                    ["namingContexts"] = [DomainDn, "CN=Configuration," + DomainDn, "DC=app," + DomainDn],
                    ["supportedControl"] = [AdIdentityLookup.DomainScopeControl]
                };
            }
            if (Reads.Count == CorruptRead) { values.Remove(Omit); ChangeValues?.Invoke(values); }
            var count = replica && Fault == "duplicate" ? 2 : 1;
            if ((!destination && subtree && Fault == "source-subordinate-nc") || (replica && Fault == "missing") || (container && Fault is "outside-container" or "escaped-container" or "subordinate-nc")) count = 0;
            if (Reads.Count == CorruptRead && CountOverride is { } overrideCount) count = overrideCount;
            var response = SaveResponse(dn, values, count, Reads.Count == CorruptRead ? Status : ResultCode.Success,
                Reads.Count == CorruptRead && Referrals, Reads.Count == CorruptRead && References);
            AfterRead?.Invoke(Reads.Count);
            if (Reads.Count == CorruptRead && ThrowResponse) throw new DirectoryOperationException(response);
            return response;
        }
        internal static byte[] SidBytes(string text)
        {
            var sid = new SecurityIdentifier(text); var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes;
        }
        public void Dispose() { User.Dispose(); Entry.Dispose(); Source.Dispose(); Destination.Dispose(); }
    }

    [Fact]
    public void Cross_context_preflight_is_data_only_and_does_not_apply_pending_rename()
    {
        using var f = new CrossContextFixture();
        f.User.Name = "pending, name"; f.User.Description = "pending description";
        f.Entry.Properties["displayName"].Value = "direct pending";
        var plan = CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry, f.ObjectGuid, CrossContextFixture.DomainDn, f.User.Name);
        Assert.Equal(f.ObjectGuid, plan.ObjectGuid); Assert.Equal(f.DomainGuid, plan.DomainGuid);
        Assert.Equal(f.ContainerGuid, plan.ContainerGuid); Assert.Equal("CN=item", plan.CurrentRdn);
        Assert.Equal("pending, name", plan.PendingName); Assert.Equal(7, f.Reads.Count);
        Assert.All(typeof(CrossContextSavePlan).GetProperties(), property =>
            Assert.True(property.PropertyType == typeof(string) || property.PropertyType == typeof(Guid)));
        Assert.Equal(0, f.Writes); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
        Assert.Equal("direct pending", f.Entry.Properties["displayName"].Value);
    }

    [Fact]
    public void Cross_context_save_refuses_after_preflight_without_changing_wrapper_authority_or_intent()
    {
        using var f = new CrossContextFixture();
        f.User.Name = "pending name"; f.User.Description = "pending description";
        var error = Assert.Throws<PlatformNotSupportedException>(() => f.User.Save(f.Destination));
        Assert.Equal(CrossContextSavePlan.ExecutionBoundary, error.Message);
        Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
        Assert.Contains("source.invalid", f.Entry.Path); Assert.Equal("source-reader", f.Entry.Username);
        Assert.Equal("pending name", f.User.Name); Assert.Equal("pending description", f.User.Description);
        Assert.Equal(0, f.Writes); Assert.Equal(7, f.Reads.Count);
    }

    [Theory]
    [InlineData("domain-guid")] [InlineData("domain-sid")]
    [InlineData("object-guid")] [InlineData("object-sid")]
    [InlineData("missing")] [InlineData("duplicate")]
    [InlineData("empty-container-guid")] [InlineData("outside-container")]
    [InlineData("source-replaced")] [InlineData("escaped-container")] [InlineData("subordinate-nc")]
    public void Cross_context_identity_preflight_refuses_incomplete_or_conflicting_proof(string fault)
    {
        using var f = new CrossContextFixture { Fault = fault };
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
    }

    [Fact]
    public void Cross_context_preflight_rejects_refreshed_replacement_of_attached_identity()
    {
        using var f = new CrossContextFixture { Fault = "refreshed-replacement" };
        f.Entry.RefreshCache();
        Assert.Equal(f.ReplacementGuid, f.Entry.Guid);
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Same(f.Source, f.User.Context);
    }

    [Fact]
    public void Cross_context_preflight_accepts_nested_container_boundaries()
    {
        using var f = new CrossContextFixture { Fault = "nested-container" };
        var plan = CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry, f.ObjectGuid, "OU=valid," + CrossContextFixture.DomainDn, null);
        Assert.Equal("OU=valid," + CrossContextFixture.DomainDn, plan.ContainerDn);
        Assert.Equal(0, f.Writes);
    }

    [Fact]
    public void Cross_context_preflight_refuses_changed_source_authority_before_reads()
    {
        using var f = new CrossContextFixture(); f.Entry.Username = "changed-reader";
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Empty(f.Reads); Assert.Equal(0, f.Writes);
    }
    public static IEnumerable<object[]> CrossContextResponseFailures()
    {
        for (var read = 1; read <= 7; read++)
            foreach (var fault in new[] { "references", "referrals", "size-limit", "time-limit", "admin-limit", "denied", "unavailable", "empty", "multiple", "throw-partial" })
                yield return [read, fault];
    }

    [Theory]
    [MemberData(nameof(CrossContextResponseFailures))]
    public void Cross_context_raw_response_failure_preserves_binding_and_pending_edits(int read, string fault)
    {
        using var f = new CrossContextFixture { CorruptRead = read };
        f.References = fault == "references"; f.Referrals = fault == "referrals";
        f.Status = fault switch
        {
            "size-limit" or "throw-partial" => ResultCode.SizeLimitExceeded,
            "time-limit" => ResultCode.TimeLimitExceeded, "admin-limit" => ResultCode.AdminLimitExceeded,
            "denied" => ResultCode.InsufficientAccessRights, "unavailable" => ResultCode.Unavailable,
            _ => ResultCode.Success
        };
        f.ThrowResponse = fault == "throw-partial";
        f.CountOverride = fault == "empty" ? 0 : fault == "multiple" ? 2 : null;
        f.User.Name = "pending rename"; f.User.Description = "pending scalar";
        f.User.SetExtension("pending extension");
        f.Entry.Properties["displayName"].Value = "pending entry";
        var generation = f.Entry.IdentityLifetime.Capture(f.Entry.ThrowIfDisposed);
        if (fault == "throw-partial")
            Assert.Throws<DirectoryOperationException>(() => f.User.Save(f.Destination));
        else
            Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
        Assert.Equal(CrossContextFixture.ItemDn, f.Entry.IdentityTarget);
        Assert.Equal("pending rename", f.User.Name); Assert.Equal("pending scalar", f.User.Description);
        Assert.Equal("pending extension", Assert.Single(f.User.GetExtension()));
        Assert.Equal("pending entry", f.Entry.Properties["displayName"].Value);
        Assert.Equal(generation, f.Entry.IdentityLifetime.Capture(f.Entry.ThrowIfDisposed));
        Assert.Equal(read, f.Reads.Count); Assert.Equal(2, f.Opens); Assert.Equal(2, f.Closes);
        // The target differs from the source parent: even then no rollback may be sent.
        Assert.Equal(0, f.Writes);
    }

    [Theory]
    [InlineData(1, "defaultNamingContext")] [InlineData(2, "defaultNamingContext")]
    [InlineData(1, "configurationNamingContext")] [InlineData(2, "configurationNamingContext")]
    [InlineData(1, "namingContexts")] [InlineData(2, "namingContexts")]
    [InlineData(1, "supportedControl")] [InlineData(2, "supportedControl")]
    [InlineData(3, "objectGUID")] [InlineData(4, "objectGUID")]
    [InlineData(3, "objectSid")] [InlineData(4, "objectSid")]
    [InlineData(5, "objectGUID")] [InlineData(6, "objectGUID")] [InlineData(7, "objectGUID")]
    [InlineData(5, "objectSid")] [InlineData(6, "objectSid")]
    [InlineData(5, "distinguishedName")] [InlineData(6, "distinguishedName")] [InlineData(7, "distinguishedName")]
    public void Cross_context_missing_metadata_never_produces_a_plan(int read, string attribute)
    {
        using var f = new CrossContextFixture { CorruptRead = read, Omit = attribute };
        if (read <= 2)
            Assert.Throws<NotSupportedException>(() => f.User.Save(f.Destination));
        else
            Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Equal(2, f.Closes);
        Assert.Same(f.Source, f.User.Context); Assert.Same(f.Entry, f.User.GetUnderlyingObject());
    }

    public static IEnumerable<object[]> CrossContextLifetimeFailures()
    {
        for (var read = 1; read <= 7; read++)
            foreach (var owner in new[] { "source", "destination", "entry", "rebind", "source-generation", "destination-generation", "entry-generation" })
                yield return [read, owner];
    }
    [Theory]
    [MemberData(nameof(CrossContextLifetimeFailures))]
    public void Cross_context_owner_revocation_rejects_inflight_and_final_results(int read, string owner)
    {
        using var f = new CrossContextFixture();
        f.AfterRead = index =>
        {
            if (index != read) return;
            switch (owner)
            {
                case "source": f.Source.Dispose(); break;
                case "destination": f.Destination.Dispose(); break;
                case "entry": f.Entry.Dispose(); break;
                case "rebind": f.Entry.Username = "rebound"; break;
                case "source-generation": f.Source.IdentityLifetime.Invalidate(); break;
                case "destination-generation": f.Destination.IdentityLifetime.Invalidate(); break;
                case "entry-generation": f.Entry.IdentityLifetime.Invalidate(); break;
            }
        };
        Assert.ThrowsAny<Exception>(() => CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry,
            f.ObjectGuid, CrossContextFixture.DomainDn, null));
        Assert.Equal(read, f.Reads.Count); Assert.Equal(0, f.Writes); Assert.Equal(2, f.Closes);
    }

    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void Cross_context_revocation_during_session_open_prevents_requests(int open)
    {
        using var f = new CrossContextFixture();
        f.AfterOpen = index => { if (index == open) f.Source.IdentityLifetime.Invalidate(); };
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Empty(f.Reads); Assert.Equal(open, f.Opens); Assert.Equal(open, f.Closes); Assert.Equal(0, f.Writes);
    }

    [Fact]
    public void Cross_context_final_publication_rechecks_cached_identity()
    {
        using var f = new CrossContextFixture();
        f.AfterRead = index => { if (index == 7) f.Entry.Properties["objectGUID"].Value = Guid.NewGuid().ToByteArray(); };
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Equal(2, f.Closes); Assert.Same(f.Source, f.User.Context);
    }

    [Fact]
    public void Cross_context_cached_naming_context_is_not_used_as_domain_evidence()
    {
        using var f = new CrossContextFixture();
        foreach (var context in new[] { f.Source, f.Destination })
            typeof(PrincipalContext).GetField("_defaultNamingContext", BindingFlags.NonPublic | BindingFlags.Instance)!
                .SetValue(context, "DC=stale-" + context.Name);
        Assert.Equal(CrossContextSavePlan.ExecutionBoundary,
            Assert.Throws<PlatformNotSupportedException>(() => f.User.Save(f.Destination)).Message);
        Assert.Equal(7, f.Reads.Count); Assert.Equal(0, f.Writes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Cross_context_subordinate_nc_with_same_suffix_requires_server_membership(bool source)
    {
        using var f = new CrossContextFixture { Fault = source ? "source-subordinate-nc" : "subordinate-nc" };
        var container = "OU=target,DC=app," + CrossContextFixture.DomainDn;
        if (source) f.Entry.Path = "LDAP://source.invalid:389/CN=item,DC=app," + CrossContextFixture.DomainDn;
        // Path rebind clears cached identity; load the fixture identity before preflight.
        if (source) _ = f.Entry.Guid;
        Assert.Throws<InvalidOperationException>(() => CrossContextSavePlan.Prepare(f.Source, f.Destination,
            f.Entry, f.ObjectGuid, container, null));
        Assert.Equal(source ? 5 : 7, f.Reads.Count); Assert.Equal(0, f.Writes);
    }

    [Fact]
    public void Cross_context_missing_retained_cache_refuses_without_loading_or_mutating_it()
    {
        using var f = new CrossContextFixture();
        f.Entry.Close();
        var loads = 0;
        f.Entry.PropertyReadOverride = (_, _) => { loads++; throw new Exception("must not load"); };
        Assert.Throws<InvalidOperationException>(() => CrossContextSavePlan.Prepare(f.Source, f.Destination,
            f.Entry, f.ObjectGuid, CrossContextFixture.DomainDn, null));
        Assert.Equal(0, loads); Assert.Empty(f.Reads); Assert.Equal(0, f.Opens); Assert.Equal(0, f.Writes);
    }

    [Fact]
    public void Cross_context_destination_open_failure_disposes_source_session()
    {
        using var f = new CrossContextFixture();
        f.Destination.SaveContextSessionFactory = _ => throw new InvalidOperationException("failed bind");
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(1, f.Opens); Assert.Equal(1, f.Closes); Assert.Empty(f.Reads); Assert.Equal(0, f.Writes);
    }

    [Theory]
    [InlineData("guid-length")] [InlineData("guid-cardinality")] [InlineData("sid-cardinality")]
    [InlineData("sid-trailing")] [InlineData("dn-cardinality")] [InlineData("dn-mismatch")]
    public void Cross_context_malformed_attribute_evidence_is_not_a_plan(string fault)
    {
        using var f = new CrossContextFixture { CorruptRead = 5 };
        f.ChangeValues = values =>
        {
            switch (fault)
            {
                case "guid-length": values["objectGUID"] = [new byte[15]]; break;
                case "guid-cardinality": values["objectGUID"] = [f.ObjectGuid.ToByteArray(), f.ObjectGuid.ToByteArray()]; break;
                case "sid-cardinality": values["objectSid"] = [values["objectSid"][0], values["objectSid"][0]]; break;
                case "sid-trailing": values["objectSid"] = [((byte[])values["objectSid"][0]).Concat(new byte[1]).ToArray()]; break;
                case "dn-cardinality": values["distinguishedName"] = [CrossContextFixture.ItemDn, CrossContextFixture.ItemDn]; break;
                case "dn-mismatch": values["distinguishedName"] = ["CN=other," + CrossContextFixture.DomainDn]; break;
            }
        };
        Assert.Throws<InvalidOperationException>(() => f.User.Save(f.Destination));
        Assert.Equal(0, f.Writes); Assert.Same(f.Source, f.User.Context); Assert.Equal(2, f.Closes);
    }

    [Fact]
    public void Cross_context_fixture_observes_direct_move_transport_for_rollback_assertions()
    {
        using var f = new CrossContextFixture();
        using var parent = f.Source.CreateDirectoryEntry(CrossContextFixture.DomainDn);
        Assert.Throws<InvalidOperationException>(() => f.Entry.MoveTo(parent));
        Assert.Equal(1, f.Writes);
    }

    private sealed class SaveClock : TimeProvider
    {
        internal TimeSpan Elapsed;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Elapsed.Ticks;
    }
    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void Cross_context_expired_open_budget_prevents_further_work_and_disposes_sessions(int open)
    {
        using var f = new CrossContextFixture(); var clock = new SaveClock();
        f.AfterOpen = index => { if (index == open) clock.Elapsed = TimeSpan.FromSeconds(30); };
        Assert.Throws<TimeoutException>(() => CrossContextSavePlan.Prepare(f.Source, f.Destination,
            f.Entry, f.ObjectGuid, CrossContextFixture.DomainDn, null, clock));
        Assert.Equal(open, f.Opens); Assert.Equal(open, f.Closes); Assert.Empty(f.Reads); Assert.Equal(0, f.Writes);
    }
    [Fact]
    public void Cross_context_second_open_receives_only_remaining_budget()
    {
        using var f = new CrossContextFixture(); var clock = new SaveClock();
        f.AfterOpen = index => { if (index == 1) clock.Elapsed = TimeSpan.FromSeconds(12); };
        _ = CrossContextSavePlan.Prepare(f.Source, f.Destination, f.Entry, f.ObjectGuid, CrossContextFixture.DomainDn, null, clock);
        Assert.Equal(new[] { TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(18) }, f.OpenTimeouts);
        Assert.Equal(2, f.Closes); Assert.Equal(0, f.Writes);
    }

}
