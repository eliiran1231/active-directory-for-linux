using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

public sealed class WindowsContextScopedReadTests
{
    private static readonly WindowsLdapContext A = new(1, 10, 100, 2, 2, true);
    private static readonly WindowsLdapContext B = new(2, 10, 200, 2, 2, true);
    private static readonly LdapConnectionOptions Options = new()
    { Host = "127.0.0.1", Port = 1636, BindDn = "synthetic", BindPassword = "synthetic" };

    private sealed class Resource(int id, bool disposeThrows = false) : IDisposable
    {
        internal int Id = id, Disposed, Users;
        public void Dispose() { Interlocked.Increment(ref Disposed); if (disposeThrows) throw new IOException("synthetic disposal"); }
    }
    private sealed class Harness : IDisposable
    {
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, Resource> Pool =
            new(perKeyLimit: 2, totalLimit: 8, startTimer: false);
        internal readonly List<Resource> Resources = [];
        internal readonly List<bool> Reusable = [];
        internal Func<WindowsLdapContext?> Capture = () => A;
        internal Action? Preparing;
        internal ContextRequestBoundary? Boundary;
        internal Func<Resource, int>? Sending;
        internal bool DisposeThrows, CreateThrows;
        internal int Sends;
        private readonly object gate = new();
        internal int Run(CancellationToken cancellation = default) =>
            ContextScopedRequest.Execute(() => Capture(), (context, reusable) => Acquire(context, reusable, cancellation), cancellation, Boundary);
        private IContextRequestLease<int> Acquire(WindowsLdapContext? context, bool reusable, CancellationToken cancellation)
        {
            lock (gate) Reusable.Add(reusable);
            var key = LdapConnectionProvider.ConnectionKey.CreateContextScoped(Options, ReferralChasingOption.External, context);
            var lease = Pool.Acquire(key, () =>
            {
                if (CreateThrows) throw new IOException("synthetic creation");
                lock (gate) { var resource = new Resource(Resources.Count + 1, DisposeThrows); Resources.Add(resource); return resource; }
            }, cancellation, reusable: reusable);
            return new Adapter(this, lease);
        }
        private sealed class Adapter(Harness owner, BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, Resource>.Lease lease)
            : IContextRequestLease<int>
        {
            public void Prepare() => owner.Preparing?.Invoke();
            public int Send()
            {
                Interlocked.Increment(ref owner.Sends);
                var resource = lease.Value;
                Assert.Equal(1, Interlocked.Increment(ref resource.Users));
                try { return owner.Sending?.Invoke(resource) ?? resource.Id; }
                finally { Assert.Equal(0, Interlocked.Decrement(ref resource.Users)); }
            }
            public void Invalidate() => lease.Invalidate();
            public void Dispose() => lease.Dispose();
        }
        public void Dispose() => Pool.Dispose();
    }

    [Fact]
    public void Diagnostic_boundaries_are_ordered_one_shot_and_unwind_scopes()
    {
        using var h = new Harness();
        var stages = new List<string>();
        int depth = 0;
        h.Boundary = new((stage, run) =>
        {
            stages.Add(stage); depth++;
            try { run(); } finally { depth--; }
        });
        Assert.Equal(1, h.Run()); Assert.Equal(0, depth);
        Assert.Equal(new[] { "acquired", "send", "complete", "return" }, stages);
        Assert.False(h.Boundary.Failed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Diagnostic_hook_cannot_skip_or_repeat_the_send(bool repeat)
    {
        using var h = new Harness();
        h.Boundary = new((stage, run) =>
        {
            if (stage != "send") { run(); return; }
            if (repeat) { run(); try { run(); } catch { } }
        });
        Assert.Throws<InvalidOperationException>(() => h.Run());
        Assert.Equal(repeat ? 1 : 0, h.Sends);
        Assert.True(h.Boundary.Failed); Assert.Equal(0, h.Pool.Snapshot.Total);
    }

    [Fact]
    public void Diagnostic_continuations_cannot_escape_to_later_or_another_thread()
    {
        using var h = new Harness();
        Action? escaped = null;
        h.Boundary = new((stage, run) => { if (stage == "send") escaped = run; else run(); });
        Assert.Throws<InvalidOperationException>(() => h.Run());
        Assert.Throws<InvalidOperationException>(() => escaped!());
        Assert.Equal(0, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
        using var other = new Harness();
        other.Boundary = new((stage, run) =>
        {
            if (stage == "send") Task.Factory.StartNew(() => Assert.Throws<InvalidOperationException>(run),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).GetAwaiter().GetResult();
            else run();
        });
        Assert.Throws<InvalidOperationException>(() => other.Run());
        Assert.Equal(0, other.Sends); Assert.Equal(0, other.Pool.Snapshot.Total);
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("return")]
    public void Hook_failure_does_not_replace_native_failure_or_escape_cleanup(string point)
    {
        using var h = new Harness();
        var original = new IOException("synthetic native error");
        h.Sending = _ => throw original;
        h.Boundary = new((stage, run) => { if (stage == point) throw new ArgumentException(); run(); });
        Assert.Same(original, Assert.Throws<IOException>(() => h.Run()));
        Assert.True(h.Boundary.Failed); Assert.Equal(1, h.Sends);
        Assert.Equal(0, h.Pool.Snapshot.Total); Assert.Equal(1, h.Resources.Single().Disposed);
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("return")]
    public void Completed_success_survives_post_send_hook_failure_but_is_not_cached(string point)
    {
        using var h = new Harness();
        h.Boundary = new((stage, run) => { if (stage == point) throw new ArgumentException(); run(); });
        Assert.Equal(1, h.Run()); Assert.True(h.Boundary.Failed);
        Assert.Equal(1, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
        Assert.Equal(1, h.Resources.Single().Disposed);
    }

    [Fact]
    public void Return_hook_failure_after_continuation_invalidates_before_actual_disposal()
    {
        using var h = new Harness();
        h.Boundary = new((stage, run) => { run(); if (stage == "return") throw new ArgumentException(); });
        Assert.Equal(1, h.Run()); Assert.True(h.Boundary.Failed);
        Assert.Equal(0, h.Pool.Snapshot.Total); Assert.Equal(1, h.Resources.Single().Disposed);
        h.Boundary = null;
        Assert.Equal(2, h.Run()); // No idle reuse from the failed diagnostic return.
    }

    [Fact]
    public void Transport_negative_control_rejects_fixture_and_authentication_errors()
    {
        Assert.True(WindowsContextCandidateDiagnostic.IsTransportFailure(new LdapException(81)));
        Assert.False(WindowsContextCandidateDiagnostic.IsTransportFailure(new LdapException(49)));
        Assert.False(WindowsContextCandidateDiagnostic.IsTransportFailure(new InvalidOperationException()));
        Assert.False(WindowsContextCandidateDiagnostic.IsTransportFailure(null));
    }

    [Fact]
    public void Synthetic_schema_entry_has_valid_ber_and_requested_schema_fields()
    {
        var fields = new Dictionary<string, string> { ["schemaNamingContext"] = "CN=synthetic-schema" };
        var bytes = WindowsReferralEndpoint.Entry(17, "synthetic", fields);
        var reader = new System.Formats.Asn1.AsnReader(bytes, System.Formats.Asn1.AsnEncodingRules.BER);
        var message = reader.ReadSequence(); Assert.Equal(17, (int)message.ReadInteger());
        var entry = message.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.Application, 4, true));
        Assert.Equal("CN=target", System.Text.Encoding.UTF8.GetString(entry.ReadOctetString()));
        var attributes = entry.ReadSequence(); var attribute = attributes.ReadSequence();
        Assert.Equal("schemaNamingContext", System.Text.Encoding.UTF8.GetString(attribute.ReadOctetString()));
        var values = attribute.ReadSetOf();
        Assert.Equal("CN=synthetic-schema", System.Text.Encoding.UTF8.GetString(values.ReadOctetString()));
        values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty();
        entry.ThrowIfNotEmpty(); message.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
    }

    [Fact]
    public void Candidate_schedule_gates_only_dependent_identities_and_guards_offline_entry()
    {
        var native = WindowsAuthenticatedDiagnostic.Schedule((_, _) => new("passed", 0, 0, 0, 0, 0, 0));
        native["a-direct"] = new("failed", 0, 0, 0, 0, 0, 0);
        native["anonymous-direct"] = new("failed", 0, 0, 0, 0, 0, 0);
        var result = WindowsContextCandidateDiagnostic.Schedule(native, _ => new("passed", 1, 1, 1, 1, 1, 1, 0, false, true, 0));
        Assert.Equal(31, result.Count);
        Assert.Equal("skipped", result["a/stable"].Status);
        Assert.Equal("skipped", result["b-to-a/return"].Status);
        Assert.Equal("passed", result["b/findone"].Status);
        Assert.Equal("passed", result["anonymous/repeated"].Status);
        Assert.Throws<InvalidOperationException>(() => new ContextScopedReadDiagnostic());
    }

    [Fact]
    public void Query_diagnostics_preserve_classification_and_never_include_identifiers()
    {
        var stats = new WindowsLdapContextQuery.Statistics { TokenId = 123456789, AuthenticationId = 987654321,
            ModifiedId = 99887766, TokenType = 2, ImpersonationLevel = 2 };
        Assert.NotNull(WindowsLdapContextQuery.Classify(stats, true, false, 0, 0, out var good));
        Assert.Equal("eligible", good.Stage);
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, false, 1, 0, out var restricted));
        Assert.Equal("restricted", restricted.Stage);
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, true, 0, 0, out var anonymous));
        Assert.Equal("anonymous", anonymous.Stage);
        var encoded = System.Text.Json.JsonSerializer.Serialize(new[] { good, restricted, anonymous });
        Assert.DoesNotContain("123456789", encoded); Assert.DoesNotContain("987654321", encoded);
        Assert.DoesNotContain("99887766", encoded);
        if (OfflineTestGuard.Enabled || !OperatingSystem.IsWindows())
        {
            Assert.Null(WindowsLdapContextQuery.Capture(out var guarded));
            Assert.Contains(guarded.Stage, new[] { "offline", "platform" });
            Assert.Throws<InvalidOperationException>(() => WindowsContextQueryProbe.Run());
        }
    }

    [Fact]
    public void Stable_context_reuses_and_context_changes_partition_actual_pool()
    {
        using var h = new Harness();
        Assert.Equal(1, h.Run()); Assert.Equal(1, h.Run());
        h.Capture = () => B; Assert.Equal(2, h.Run());
        h.Capture = () => A; Assert.Equal(1, h.Run());
        Assert.Equal(2, h.Resources.Count); Assert.Equal(4, h.Sends);
        Assert.All(h.Reusable, Assert.True);
    }

    [Fact]
    public void Every_context_component_and_legacy_key_are_isolated()
    {
        var contexts = new[] { A, A with { TokenId = 2 }, A with { AuthenticationId = 11 },
            A with { ModifiedId = 101 }, A with { TokenType = 1 }, A with { ImpersonationLevel = 3 },
            A with { ThreadToken = false } };
        var keys = contexts.Select(c => LdapConnectionProvider.ConnectionKey.CreateContextScoped(Options, ReferralChasingOption.External, c)).ToList();
        keys.Add(LdapConnectionProvider.ConnectionKey.CreateContextScoped(Options, ReferralChasingOption.External, null));
        keys.Add(LdapConnectionProvider.ConnectionKey.Create(Options, ReferralChasingOption.External));
        Assert.Equal(keys.Count, keys.Distinct().Count());
        Assert.Equal("Windows LDAP context (redacted)", A.ToString());
    }

    [Fact]
    public void Unknown_or_throwing_query_never_promotes_a_fresh_connection()
    {
        using var h = new Harness { Capture = () => null };
        Assert.Equal(1, h.Run()); Assert.Equal(2, h.Run());
        h.Capture = () => throw new UnauthorizedAccessException();
        Assert.Equal(3, h.Run());
        Assert.All(h.Reusable, value => Assert.False(value));
        Assert.All(h.Resources, r => Assert.Equal(1, r.Disposed));
        Assert.Equal(0, h.Pool.Snapshot.Total);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void Change_after_acquisition_or_immediately_before_send_falls_back_once(int changedRead)
    {
        using var h = new Harness();
        int reads = 0;
        h.Capture = () => Interlocked.Increment(ref reads) < changedRead ? A : B;
        Assert.Equal(2, h.Run());
        Assert.Equal(new[] { true, false }, h.Reusable);
        Assert.Equal(1, h.Sends);
        Assert.All(h.Resources, r => Assert.Equal(1, r.Disposed));
    }

    [Fact]
    public void Query_failure_after_acquisition_falls_back_not_process_identity()
    {
        using var h = new Harness();
        int reads = 0;
        h.Capture = () => ++reads == 1 ? A : throw new UnauthorizedAccessException();
        Assert.Equal(2, h.Run()); Assert.Equal(1, h.Sends);
        Assert.Equal(new[] { true, false }, h.Reusable);
    }

    [Fact]
    public void Context_change_during_prepare_is_seen_before_any_send()
    {
        using var h = new Harness();
        var current = A;
        h.Capture = () => current;
        h.Preparing = () => current = B;
        Assert.Equal(2, h.Run()); Assert.Equal(1, h.Sends);
        Assert.Equal(new[] { true, false }, h.Reusable);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(5)]
    public void Change_at_completion_or_return_preserves_success_and_evicts(int changedRead)
    {
        using var h = new Harness();
        int reads = 0;
        h.Capture = () => ++reads < changedRead ? A : B;
        Assert.Equal(1, h.Run()); Assert.Equal(1, h.Sends);
        Assert.Equal(1, h.Resources.Single().Disposed); Assert.Equal(0, h.Pool.Snapshot.Total);
    }

    [Fact]
    public void Send_failure_is_not_replayed_or_replaced_by_query_or_disposal_failure()
    {
        using var h = new Harness { DisposeThrows = true };
        var original = new InvalidOperationException("synthetic send");
        h.Sending = _ => { h.Capture = () => throw new UnauthorizedAccessException(); throw original; };
        Assert.Same(original, Assert.Throws<InvalidOperationException>(() => h.Run()));
        Assert.Equal(1, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
        Assert.Equal(1, h.Resources.Single().Disposed);
    }

    [Fact]
    public void Successful_send_survives_post_query_and_disposal_failure_without_caching()
    {
        using var h = new Harness { DisposeThrows = true };
        h.Sending = _ => { h.Capture = () => null; return 42; };
        Assert.Equal(42, h.Run()); Assert.Equal(1, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
    }

    [Fact]
    public void Creation_and_prepare_failure_release_reservations_without_sending()
    {
        using var h = new Harness { CreateThrows = true };
        Assert.Throws<IOException>(() => h.Run()); Assert.Equal(0, h.Pool.Snapshot.Total);
        h.CreateThrows = false; h.Preparing = () => throw new ArgumentException("synthetic preparation");
        Assert.Throws<ArgumentException>(() => h.Run());
        Assert.Equal(0, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
        Assert.Equal(1, h.Resources.Single().Disposed);
    }

    [Fact]
    public void Cancellation_before_acquire_or_send_does_not_send_or_cache()
    {
        using var h = new Harness();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.Throws<OperationCanceledException>(() => h.Run(canceled.Token)); Assert.Empty(h.Resources);
        using var during = new CancellationTokenSource();
        h.Preparing = during.Cancel;
        Assert.Throws<OperationCanceledException>(() => h.Run(during.Token));
        Assert.Equal(0, h.Sends); Assert.Equal(0, h.Pool.Snapshot.Total);
    }

    [Fact]
    public async Task Concurrent_scopes_get_exclusive_resources_and_return_them()
    {
        using var h = new Harness();
        using var arrived = new CountdownEvent(2);
        h.Sending = r => { arrived.Signal(); Assert.True(arrived.Wait(TimeSpan.FromSeconds(5))); return r.Id; };
        var tasks = Enumerable.Range(0, 2).Select(_ => Task.Factory.StartNew(() => h.Run(),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        var ids = await Task.WhenAll(tasks);
        Assert.Equal(2, ids.Distinct().Count()); Assert.Equal(2, h.Pool.Snapshot.Total);
        h.Pool.Dispose(); Assert.All(h.Resources, r => Assert.Equal(1, r.Disposed));
    }

    [Fact]
    public async Task Waiting_scope_cancellation_releases_waiter_without_an_extra_send()
    {
        using var h = new Harness();
        using var arrived = new CountdownEvent(2);
        using var release = new ManualResetEventSlim();
        h.Sending = r => { arrived.Signal(); Assert.True(release.Wait(TimeSpan.FromSeconds(5))); return r.Id; };
        var tasks = Enumerable.Range(0, 2).Select(_ => Task.Factory.StartNew(() => h.Run(),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        try
        {
            Assert.True(arrived.Wait(TimeSpan.FromSeconds(5)));
            using var canceled = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            Assert.Throws<OperationCanceledException>(() => h.Run(canceled.Token));
            Assert.Equal(0, h.Pool.Snapshot.Waiting); Assert.Equal(2, h.Sends);
        }
        finally { release.Set(); await Task.WhenAll(tasks); }
    }

    [Fact]
    public void Native_classifier_rejects_unsupported_contexts_and_normalizes_primary_level()
    {
        var stats = new WindowsLdapContextQuery.Statistics
        { TokenId = 1, AuthenticationId = 10, ModifiedId = 100, TokenType = 2, ImpersonationLevel = 2 };
        Assert.Equal(A, WindowsLdapContextQuery.Classify(stats, true, false, 0, 0));
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, true, 0, 0));
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, null, 0, 0));
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, false, 1, 0));
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, false, 0, 1));
        foreach (uint level in new uint[] { 0, 1, 3, 99 })
        { stats.ImpersonationLevel = level; Assert.Null(WindowsLdapContextQuery.Classify(stats, true, false, 0, 0)); }
        stats.TokenType = 1;
        Assert.Equal(0u, WindowsLdapContextQuery.Classify(stats, false, false, 0, 0)!.Value.ImpersonationLevel);
        Assert.Null(WindowsLdapContextQuery.Classify(stats, true, false, 0, 0));
        Assert.Equal(56, Marshal.SizeOf<WindowsLdapContextQuery.Statistics>());
        Assert.Equal(48, Marshal.OffsetOf<WindowsLdapContextQuery.Statistics>("ModifiedId").ToInt32());
        Assert.True(WindowsLdapContextQuery.IsAnonymousSid(new byte[] { 1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0 }));
        Assert.False(WindowsLdapContextQuery.IsAnonymousSid(new byte[] { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }));
        Assert.True(WindowsLdapContextQuery.CanUseProcessToken(1008));
        foreach (int error in new[] { 0, 5, 1347, 122 }) Assert.False(WindowsLdapContextQuery.CanUseProcessToken(error));
        // Never execute token queries from this pure class, even in live test mode.
        if (OfflineTestGuard.Enabled || !OperatingSystem.IsWindows()) Assert.Null(WindowsLdapContextQuery.Capture());
    }

    [Fact]
    public void Token_user_parser_checks_embedded_pointer_revision_and_length_without_native_queries()
    {
        int offset = IntPtr.Size == 8 ? 16 : 8;
        var buffer = Marshal.AllocHGlobal(128);
        try
        {
            var sid = IntPtr.Add(buffer, offset);
            Marshal.WriteIntPtr(buffer, sid);
            Marshal.Copy(new byte[] { 1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0 }, 0, sid, 12);
            Assert.True(WindowsLdapContextQuery.ReadAnonymousSid(buffer, (uint)(offset + 12)));
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(buffer, (uint)(offset + 11)));
            Marshal.WriteByte(sid, 0, 0);
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(buffer, 128));
            Marshal.WriteByte(sid, 0, 1); Marshal.WriteByte(sid, 1, 16);
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(buffer, 128));
            Marshal.WriteIntPtr(buffer, IntPtr.Add(buffer, 129));
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(buffer, 128));
            Marshal.WriteIntPtr(buffer, IntPtr.Subtract(buffer, 1));
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(buffer, 128));
            Assert.Null(WindowsLdapContextQuery.ReadAnonymousSid(IntPtr.Zero, 128));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [Fact]
    public void Scoped_materialization_requests_fresh_external_schema_despite_root_policy()
    {
        using var root = new AdForLinux.DirectoryServices.DirectoryEntry("LDAP://127.0.0.1:1636/CN=synthetic");
        root.Options.Referral = ReferralChasingOption.None;
        var sentinel = new InvalidOperationException("synthetic factory stop");
        root.OperationSessionFactory = (_, count, referral, fresh, _) =>
        {
            Assert.Equal(1, count); Assert.Equal(ReferralChasingOption.External, referral); Assert.True(fresh);
            throw sentinel; // Stop before any native allocation/bind.
        };
        Assert.Same(sentinel, Assert.Throws<InvalidOperationException>(() =>
            root.AcquireContextScopedReadSchemaConnection(root.CaptureBindingAuthority())));
    }

    [Fact]
    public void Candidate_scope_is_narrow_and_all_ordinary_paths_remain_guarded()
    {
        Assert.False(LdapConnectionProvider.ContextScopedProductionEnabled);
        var request = new SearchRequest("CN=synthetic", "(objectClass=*)", SearchScope.Base);
        Assert.True(LdapConnectionProvider.IsContextScopedReadConfiguration(Options, ReferralChasingOption.External, request));
        foreach (var mode in new[] { ReferralChasingOption.None, ReferralChasingOption.Subordinate, ReferralChasingOption.All })
            Assert.False(LdapConnectionProvider.IsContextScopedReadConfiguration(Options, mode, request));
        request.Scope = SearchScope.Subtree;
        Assert.False(LdapConnectionProvider.IsContextScopedReadConfiguration(Options, ReferralChasingOption.External, request));
        request.Scope = SearchScope.Base; request.Controls.Add(new PageResultRequestControl(1));
        Assert.False(LdapConnectionProvider.IsContextScopedReadConfiguration(Options, ReferralChasingOption.External, request));
        Assert.Equal(OperatingSystem.IsLinux(), LdapConnectionProvider.CanReuse(Options, ReferralChasingOption.External));
        Assert.True(LdapConnectionProvider.CanReuse(Options, ReferralChasingOption.None));
        Assert.Throws<InvalidOperationException>(() => LdapConnectionProvider.SendContextScopedReadDiagnostic(Options, request));
    }
}
