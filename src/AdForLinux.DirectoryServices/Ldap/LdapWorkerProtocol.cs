using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace AdForLinux.DirectoryServices.Ldap;

// JSON carries a source recipe, never credential bytes or native handles. Owned
// credentials cross separately through the supervisor's sealed inherited fd6.
internal sealed record LdapWorkerStart(string Host, int Port, bool UseSsl, bool Signing, bool Sealing,
    int SessionCount, TimeSpan Timeout, LdapCredentialSource? CredentialSource = null, LdapWorkerKerberosProfile? RestrictedConfiguration = null)
{
    // Parent-only startup material. Never serialize credentials into the JSON protocol.
    internal byte[]? OwnedCache { get; init; }
    internal Func<IDisposable>? RetainOwnedCache { get; init; }
}
internal sealed record LdapWorkerReady(LdapTransportCapabilities[] Capabilities, uint CredentialLifetimeSeconds = 0);
internal sealed record LdapWorkerNext(TimeSpan? ServerTimeLimit);
internal sealed record LdapWorkerFailure(string Category);
internal sealed record LdapWorkerFrame(int Version, long Id, int Session, string Kind, long TimeoutTicks, JsonElement Payload);
internal static class LdapWorkerProtocol
{
    internal const int Version = 6, MaximumFrame = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = Options();
    private static JsonSerializerOptions Options()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info => { foreach (var property in info.Properties) property.IsRequired = true; });
        return new() { MaxDepth = 32, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            PropertyNameCaseInsensitive = false, TypeInfoResolver = resolver };
    }
    internal static LdapWorkerFrame Frame<T>(long id, int session, string kind, TimeSpan timeout, T payload) =>
        new(Version, id, session, kind, timeout.Ticks, Element(payload));
    internal static T Payload<T>(LdapWorkerFrame frame) => frame.Payload.Deserialize<T>(Json)
        ?? throw new InvalidDataException("Missing worker payload.");
    internal static async ValueTask WriteAsync(Stream stream, LdapWorkerFrame frame, CancellationToken token)
    {
        var bytes = Encode(frame);
        if (bytes.Length > MaximumFrame) throw new InvalidDataException("Worker frame exceeds the protocol limit.");
        var header = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(header, bytes.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }
    internal static async ValueTask<LdapWorkerFrame> ReadAsync(Stream stream, CancellationToken token)
    {
        var header = new byte[4]; await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length <= 0 || length > MaximumFrame) throw new InvalidDataException("Invalid worker frame length.");
        var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        ValidateProperties(document.RootElement);
        var frame = JsonSerializer.Deserialize<LdapWorkerFrame>(bytes, Json) ?? throw new InvalidDataException("Missing worker frame.");
        if (frame.Version != Version || frame.Id <= 0 || frame.Session < 0 || frame.Session > 1 ||
            frame.Kind is null || frame.Kind.Length > 24 || frame.TimeoutTicks < 0 || frame.Payload.ValueKind == JsonValueKind.Undefined)
            throw new InvalidDataException("Invalid worker frame header.");
        return frame;
    }
    private static byte[] Encode<T>(T value)
    {
        using var stream = new CappedStream(); JsonSerializer.Serialize(stream, value, Json); return stream.ToArray();
    }
    private static JsonElement Element<T>(T value)
    { using var document = JsonDocument.Parse(Encode(value)); return document.RootElement.Clone(); }
    private sealed class CappedStream : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        { Check(count); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer)
        { Check(buffer.Length); base.Write(buffer); }
        private void Check(int count)
        { if (Length + count > MaximumFrame) throw new InvalidDataException("Worker frame exceeds the protocol limit."); }
    }
    private static void ValidateProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            { if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate worker property."); ValidateProperties(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            if (value.GetArrayLength() > 65536) throw new InvalidDataException("Worker collection exceeds the protocol limit.");
            foreach (var item in value.EnumerateArray()) ValidateProperties(item);
        }
    }
    internal static void ValidateStart(LdapWorkerStart profile)
    {
        profile.CredentialSource?.Validate();
        if (profile.RestrictedConfiguration is { } configuration)
        {
            if (profile.CredentialSource is null) throw new ArgumentException("Restricted worker configuration requires an explicit credential source.");
            configuration.Generate(profile.Host);
        }
        if (string.IsNullOrWhiteSpace(profile.Host) || profile.Host.Length > 1024 || profile.Host.Contains('\0') ||
            profile.Port is < 1 or > 65535 || profile.SessionCount is < 1 or > 2 ||
            profile.Timeout <= TimeSpan.Zero || profile.Timeout > TimeSpan.FromHours(1))
            throw new InvalidDataException("Invalid worker operation profile.");
    }
}
