using System.Buffers.Binary;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
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
    [InlineData("{\"Version\":1,\"Version\":1,\"Id\":1,\"Session\":0,\"Kind\":\"READY\",\"TimeoutTicks\":0,\"Payload\":null}")]
    [InlineData("{\"Version\":1,\"Id\":1,\"Session\":0,\"Kind\":\"READY\",\"Payload\":null}")]
    [InlineData("{\"Version\":1,\"Id\":1,\"Session\":2,\"Kind\":\"READY\",\"TimeoutTicks\":0,\"Payload\":null}")]
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
