using System.Buffers.Binary;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Fact]
    public void Restricted_worker_profile_is_typed_bounded_and_requires_explicit_source()
    {
        var configuration = new LdapWorkerKerberosProfile("EXAMPLE.INVALID", "directory.invalid", "/recording/private-plugins");
        var generated = Encoding.ASCII.GetString(configuration.Generate("directory.invalid"));
        Assert.Contains("default_realm = EXAMPLE.INVALID", generated);
        Assert.Contains("directory.invalid = EXAMPLE.INVALID", generated);
        Assert.Contains("enable_only = realm", generated);
        Assert.Contains("dns_canonicalize_hostname = false", generated);
        Assert.DoesNotContain("include", generated); Assert.DoesNotContain("module =", generated);
        Assert.True(Encoding.ASCII.GetByteCount(generated) < LdapWorkerKerberosProfile.MaximumBytes);
        var profile = new LdapWorkerStart("directory.invalid", 389, false, true, true, 1, TimeSpan.FromSeconds(5), RestrictedConfiguration: configuration);
        Assert.Throws<ArgumentException>(() => LdapWorkerProtocol.ValidateStart(profile));
        LdapWorkerProtocol.ValidateStart(profile with { CredentialSource = new(LdapCredentialSourceKind.File, "/recording/cache") });
        Assert.Throws<ArgumentException>(() => configuration.Generate("different.invalid"));
    }
    [Theory]
    [InlineData("/recording/plugins\ninclude /etc/krb5.conf")]
    [InlineData("/recording/%{LIBDIR}")]
    [InlineData("/recording/plugins#comment")]
    [InlineData("/recording/plugins;comment")]
    [InlineData("/recording/plugins module=evil")]
    public void Restricted_worker_configuration_rejects_raw_syntax_and_expansion(string path)
    {
        Assert.Throws<ArgumentException>(() => new LdapWorkerKerberosProfile("EXAMPLE.INVALID", "directory.invalid", path).Generate("directory.invalid"));
    }

    [Fact]
    public async Task Restricted_worker_endpoint_is_typed_and_preserved_by_protocol_roundtrip()
    {
        var configuration = new LdapWorkerKerberosProfile("ADFL.TEST", "127.0.0.1", "/recording/plugins");
        var original = configuration.Generate("127.0.0.1");
        Assert.Equal(original, (configuration with { Kdc = null }).Generate("127.0.0.1"));
        var routed = configuration with { Kdc = new("127.0.0.1", 10088) };
        Assert.EndsWith("[realms]\n ADFL.TEST = {\n  kdc = 127.0.0.1:10088\n }\n", Encoding.ASCII.GetString(routed.Generate("127.0.0.1")));
        var profile = new LdapWorkerStart("127.0.0.1", 10389, false, true, true, 1, TimeSpan.FromSeconds(5),
            new(LdapCredentialSourceKind.File, "/recording/cache"), routed);
        using var channel = new MemoryStream();
        await LdapWorkerProtocol.WriteAsync(channel, LdapWorkerProtocol.Frame(1, 0, "START", profile.Timeout, profile), default);
        channel.Position = 0;
        var copied = LdapWorkerProtocol.Payload<LdapWorkerStart>(await LdapWorkerProtocol.ReadAsync(channel, default));
        Assert.Equal(profile, copied);
        LdapWorkerProtocol.ValidateStart(copied);
    }
    [Theory]
    [InlineData("127.0.0.1", 0)]
    [InlineData("127.0.0.1", 65536)]
    [InlineData("127.0.0.1:88", 88)]
    [InlineData("bad\ninclude", 88)]
    [InlineData("https://kdc", 88)]
    [InlineData("::1", 88)]
    [InlineData("", 88)]
    public void Restricted_worker_endpoint_rejects_raw_syntax_and_invalid_ports(string host, int port)
    {
        Assert.Throws<ArgumentException>(() => new LdapWorkerKdcEndpoint(host, port).HostSpec());
    }

    [Fact]
    public async Task Production_worker_requires_source_and_policy_and_never_activates_from_metadata()
    {
        var profile = new LdapWorkerStart("directory.invalid", 389, false, true, true, 1, TimeSpan.FromSeconds(5));
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerKerberosProfile.RequireProductionPolicy(profile));
        var sourced = profile with { CredentialSource = new(LdapCredentialSourceKind.File, "/recording/cache") };
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerKerberosProfile.RequireProductionPolicy(sourced));
        LdapWorkerKerberosProfile.RequireProductionPolicy(sourced with
            { RestrictedConfiguration = new("EXAMPLE.INVALID", "directory.invalid", "/recording/plugins", new("kdc.invalid", 88)) });
        // Exercise the actual default host, with no injected backend or native load.
        using var channel = new MemoryStream();
        await LdapWorkerProtocol.WriteAsync(channel, LdapWorkerProtocol.Frame(1, 0, "START", profile.Timeout, sourced), default);
        var replyOffset = channel.Length;
        channel.Position = 0;
        await LdapWorkerHost.RunAsync(channel);
        channel.Position = replyOffset;
        var reply = await LdapWorkerProtocol.ReadAsync(channel, default);
        Assert.Equal("ERROR", reply.Kind);
        Assert.Equal("unsupported", LdapWorkerProtocol.Payload<LdapWorkerFailure>(reply).Category);
    }

    [Fact]
    public void Restricted_production_profile_refuses_unproven_source_and_security_modes()
    {
        var supported = new LdapWorkerStart("directory.invalid", 389, false, true, true, 1, TimeSpan.FromSeconds(5))
        {
            CredentialSource = new(LdapCredentialSourceKind.File, "/recording/cache"),
            RestrictedConfiguration = new("EXAMPLE.INVALID", "directory.invalid", "/recording/plugins", new("kdc.invalid", 88))
        };
        LdapWorkerKerberosProfile.RequireProductionPolicy(supported);
        var unsupported = new[]
        {
            supported with { CredentialSource = new(LdapCredentialSourceKind.DirectoryCollection, "/recording/cache") },
            supported with { UseSsl = true }, supported with { Signing = false }, supported with { Sealing = false },
            supported with { RestrictedConfiguration = supported.RestrictedConfiguration with { Kdc = null } }
        };
        foreach (var profile in unsupported)
            Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerKerberosProfile.RequireProductionPolicy(profile));
    }

    [Fact]
    public void Worker_submission_gate_runs_before_uncertainty_and_cannot_be_reentered()
    {
        LdapSubmission? submission = null;
        submission = new(() => { Assert.False(submission!.Started); throw new IOException("GO unavailable"); });
        Assert.Throws<IOException>(submission.BeforeSend); Assert.False(submission.Started);
        Assert.Throws<InvalidOperationException>(submission.BeforeSend);
        var successful = new LdapSubmission(() => { }); successful.BeforeSend(); Assert.True(successful.Started);
    }

    [Theory]
    [InlineData("{\"Version\":5,\"Version\":5,\"Id\":1,\"Session\":0,\"Kind\":\"READY\",\"TimeoutTicks\":0,\"Payload\":null}")]
    [InlineData("{\"Version\":5,\"Id\":1,\"Session\":0,\"Kind\":\"READY\",\"Payload\":null}")]
    [InlineData("{\"Version\":5,\"Id\":1,\"Session\":2,\"Kind\":\"READY\",\"TimeoutTicks\":0,\"Payload\":null}")]
    public async Task Worker_frames_reject_duplicate_missing_and_invalid_fields(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json); using var stream = new MemoryStream();
        var header = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(header, bytes.Length);
        stream.Write(header); stream.Write(bytes); stream.Position = 0;
        await Assert.ThrowsAnyAsync<Exception>(async () => await LdapWorkerProtocol.ReadAsync(stream, default));
    }

    [Fact]
    public async Task Worker_frames_reject_oversized_input_before_payload_allocation()
    {
        var header = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(header, LdapWorkerProtocol.MaximumFrame + 1);
        using var stream = new MemoryStream(header);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await LdapWorkerProtocol.ReadAsync(stream, default));
    }

    [Fact]
    public async Task Worker_parent_cancellation_does_not_wait_for_an_uncooperative_channel()
    {
        using var token = new CancellationTokenSource(); using var channel = new WorkerStalledStream();
        var retired = 0;
        var start = LdapWorkerClient.StartAsync(channel, () => retired++,
            new("offline.invalid", 389, false, true, true, 1, TimeSpan.FromSeconds(5)), TimeSpan.FromSeconds(5), token.Token);
        await channel.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5)); token.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => start.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, retired); Assert.True(channel.Disposed);
        channel.Release.TrySetResult(0);
    }

    [Theory]
    [InlineData("budget")]
    [InlineData("cancel")]
    [InlineData("error")]
    public async Task Retired_worker_cursor_cleanup_preserves_partial_budget_and_original_failures(string outcome)
    {
        using var replies = new MemoryStream();
        var caps = LdapTransportCapabilities.Search | LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        await LdapWorkerProtocol.WriteAsync(replies, LdapWorkerProtocol.Frame(1, 0, "READY", TimeSpan.Zero,
            new LdapWorkerReady([caps, LdapTransportCapabilities.Search])), default);
        await LdapWorkerProtocol.WriteAsync(replies, LdapWorkerProtocol.Frame<object?>(2, 0, "OK", TimeSpan.Zero, null), default);
        await LdapWorkerProtocol.WriteAsync(replies, LdapWorkerProtocol.Frame(3, 0, "ENTRY", TimeSpan.Zero,
            TransportRow("CN=kept", new() { ["cn"] = ["kept"] })), default);
        if (outcome == "error")
            await LdapWorkerProtocol.WriteAsync(replies, LdapWorkerProtocol.Frame(4, 0, "ERROR", TimeSpan.Zero, new LdapWorkerFailure("state")), default);
        else
            await LdapWorkerProtocol.WriteAsync(replies, LdapWorkerProtocol.Frame(4, 0, "PAGE", TimeSpan.Zero,
                new LdapSearchEvent.PageEnd(Envelope(System.DirectoryServices.Protocols.ResultCode.Success), true)), default);
        using var channel = new WorkerScriptedStream(replies.ToArray());
        var retired = 0;
        using var client = await LdapWorkerClient.StartAsync(channel, () => retired++,
            new("directory.invalid", 389, false, true, true, 2, TimeSpan.FromSeconds(10)), TimeSpan.FromSeconds(10));
        var sessions = LdapRestrictedOperation.Wrap(client.Sessions, client, RestrictedRecipe().Options());
        using var sibling = sessions[1]; using var cancellation = new CancellationTokenSource();
        var limits = 0; var rows = new List<LdapTransportEntry>();
        await using var iterator = LdapConversation.Search(() => sessions[0], SearchCommand(), 1,
            cancellation.Token, nextServerLimit: () => ++limits == 1 ? TimeSpan.FromSeconds(30) : null).GetAsyncEnumerator();
        Assert.True(await iterator.MoveNextAsync());
        rows.Add(Assert.IsType<LdapSearchEvent.Entry>(iterator.Current).Value);
        if (outcome == "cancel") cancellation.Cancel();
        var error = await Record.ExceptionAsync(async () => { while (await iterator.MoveNextAsync()) { } });
        if (outcome == "budget") Assert.Null(error);
        else if (outcome == "cancel") Assert.IsAssignableFrom<OperationCanceledException>(error);
        else Assert.Equal("Worker operation failed (state).", Assert.IsType<IOException>(error).Message);
        Assert.Single(rows); Assert.Equal(1, retired); Assert.True(channel.Disposed);
        Assert.Throws<ObjectDisposedException>(() => sibling.ExecuteTransport(value => value.Timeout));
        using var writes = new MemoryStream(channel.Writes.ToArray());
        var kinds = new List<string>();
        while (writes.Position < writes.Length) kinds.Add((await LdapWorkerProtocol.ReadAsync(writes, default)).Kind);
        Assert.DoesNotContain("CLOSE", kinds); Assert.DoesNotContain("NEXT", kinds);
        Assert.Equal(outcome == "cancel" ? 3 : 4, kinds.Count);
    }

    private sealed class WorkerScriptedStream(byte[] replies) : Stream
    {
        private readonly MemoryStream input = new(replies);
        internal readonly MemoryStream Writes = new();
        internal bool Disposed;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { ObjectDisposedException.ThrowIf(Disposed, this); return input.ReadAsync(buffer, cancellationToken); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        { ObjectDisposedException.ThrowIf(Disposed, this); return Writes.WriteAsync(buffer, cancellationToken); }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { } public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class WorkerStalledStream : Stream
    {
        internal readonly TaskCompletionSource ReadEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<int> Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Disposed;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { ReadEntered.TrySetResult(); return new(Release.Task); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { } public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
    }
}
