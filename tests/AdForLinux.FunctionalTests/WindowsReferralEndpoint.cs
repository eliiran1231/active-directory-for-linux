using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.FunctionalTests;

// Wire-level fixture, not an AD server. Only listens on loopback and accepts
// the synthetic identities below. SASL is rejected without a challenge, so the
// fixture never authenticates the runner's account or collects its credentials.
internal sealed class WindowsReferralEndpoint : IAsyncDisposable
{
    internal const string FirstIdentity = "CN=first synthetic reader";
    internal const string SecondIdentity = "CN=second synthetic reader";
    internal const string Password = "synthetic fixture password";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly List<(TcpClient Client, Task Serving)> clients = [];
    private readonly Task accepting;
    private readonly X509Certificate2? certificate;
    private int abandons, rejectedTlsProbes;
    private readonly bool rejectTlsOnPlaintext;
    private int binds, searches, connections, closed, saslBinds, credentialedSimpleBinds, anonymousBinds, tlsHandshakes;
    internal string? ReferralUrl { get; set; }
    internal bool RejectBinds { get; set; }
    internal bool ServeSyntheticSchema { get; set; }
    internal bool ServeBindingResolution { get; set; }
    private int bindingReads;
    internal int BindingReads => Volatile.Read(ref bindingReads);
    private int schemaReads;
    internal int SchemaReads => Volatile.Read(ref schemaReads);
    internal volatile bool DisconnectOnSearch;
    internal int RejectedTlsProbes => Volatile.Read(ref rejectedTlsProbes);
    internal int Abandons => Volatile.Read(ref abandons);
    internal int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    internal int Binds => Volatile.Read(ref binds);
    internal int Searches => Volatile.Read(ref searches);
    internal int Connections => Volatile.Read(ref connections);
    internal int Closed => Volatile.Read(ref closed);
    internal int SaslBinds => Volatile.Read(ref saslBinds);
    internal int CredentialedSimpleBinds => Volatile.Read(ref credentialedSimpleBinds);
    internal int AnonymousBinds => Volatile.Read(ref anonymousBinds);
    internal int TlsHandshakes => Volatile.Read(ref tlsHandshakes);
    internal byte[] PublicCertificateBytes => certificate?.RawData
        ?? throw new InvalidOperationException("TLS endpoint required for certificate pinning.");
    internal ConcurrentQueue<string> BoundIdentities { get; } = new();

    internal ConcurrentQueue<string> FirstRecords { get; } = new();
    internal ConcurrentQueue<string> TransportFailures { get; } = new();

    // Tests wait for simultaneous target operations before allowing either response.
    internal WindowsDiagnosticTimeline? Timeline { get; set; }
    internal string TimelineRole { get; set; } = "target";
    internal Func<int, int, int, Task>? BeforeCorrelatedSearchResponse { get; set; }
    internal Func<Task>? BeforeSearchResponse { get; set; }

    internal WindowsReferralEndpoint(bool tls, bool allowDiagnosticCertificate = true, bool untrustedOwnedCertificate = false, bool rejectTlsOnPlaintext = false)
    {
        OfflineTestGuard.RequireLiveAccess();
        if (tls && rejectTlsOnPlaintext) throw new ArgumentException("Plaintext negative control required.");
        this.rejectTlsOnPlaintext = rejectTlsOnPlaintext;
        if (tls)
        {
            var ownedDirectory = allowDiagnosticCertificate ? Environment.GetEnvironmentVariable("ADFL_REFERRAL_OWNED_KEY_DIRECTORY") : null;
            var diagnosticPfx = allowDiagnosticCertificate ? Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") : null;
            if (!string.IsNullOrEmpty(ownedDirectory))
            {
                certificate = WindowsDiagnosticOwnedCertificate.Load(ownedDirectory, untrustedOwnedCertificate);
            }
            else if (untrustedOwnedCertificate) throw new InvalidOperationException("Owned diagnostic key required.");
            else if (!string.IsNullOrEmpty(diagnosticPfx))
            {
                if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true")
                    throw new InvalidOperationException("Diagnostic certificate is only for hosted Windows CI.");
#pragma warning disable SYSLIB0057
                certificate = new X509Certificate2(diagnosticPfx);
#pragma warning restore SYSLIB0057
            }
            else
            {
                using var key = RSA.Create(2048);
                var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var names = new SubjectAlternativeNameBuilder();
                names.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(names.Build());
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
                using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
                // Reimport for Schannel server use. Never install in a certificate store
                // or change machine trust. Default import relies on runtime key cleanup on
                // disposal, which does not establish cleanup after process termination.
#pragma warning disable SYSLIB0057
                certificate = new X509Certificate2(generated.Export(X509ContentType.Pfx));
#pragma warning restore SYSLIB0057
            }
        }
        listener.Start();
        accepting = Accept();
    }

    private async Task Accept()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stop.Token);
                int connection = Interlocked.Increment(ref connections);
                lock (clients) clients.Add((client, Serve(client, connection)));
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private async Task Serve(TcpClient client, int connection)
    {
        using (client)
        {
            Stream stream = client.GetStream();
            try
            {
                Timeline?.Add(TimelineRole, connection, 0, 0, "accept");
                // Observe protocol selection on TLS AND plaintext targets. No bytes
                // are consumed/logged; this cannot establish trust or identity by itself.
                var first = new byte[1];
                var count = await client.Client.ReceiveAsync(first.AsMemory(), SocketFlags.Peek, stop.Token);
                FirstRecords.Enqueue(count == 0 ? "EOF" : first[0] switch
                {
                    0x16 => "TLS handshake", 0x15 => "TLS alert", 0x30 => "LDAP BER", _ => "other",
                });
                if (ShouldRejectTlsProbe(rejectTlsOnPlaintext, certificate is not null, count == 0 ? null : first[0]))
                {
                    Interlocked.Increment(ref rejectedTlsProbes);
                    return; // Deliberate plaintext negative control: no handshake, bind or response.
                }
                if (certificate is not null)
                {
                    var secure = new SslStream(stream, leaveInnerStreamOpen: false);
                    stream = secure;
                    await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12,
                        ClientCertificateRequired = false,
                    }, stop.Token);
                    Interlocked.Increment(ref tlsHandshakes);
                    Timeline?.Add(TimelineRole, connection, 0, 0, "tls");
                }
                var identity = "unbound";
                while (!stop.IsCancellationRequested)
                {
                    var payload = await ReadMessage(stream);
                    var message = new AsnReader(payload, AsnEncodingRules.BER);
                    var id = (int)message.ReadInteger();
                    var tag = message.PeekTag();
                    if (tag.TagClass != TagClass.Application) throw new InvalidDataException("Expected LDAP operation.");
                    if (tag.TagValue == 2) return;
                    if (TryConsumeAbandon(message)) { Interlocked.Increment(ref abandons); continue; }
                    var operation = message.ReadSequence(tag);
                    if (tag.TagValue == 0)
                    {
                        Interlocked.Increment(ref binds);
                        Timeline?.Add(TimelineRole, connection, id, 0, "bind");
                        identity = "unbound";
                        _ = operation.ReadInteger();
                        var name = Encoding.UTF8.GetString(operation.ReadOctetString());
                        var auth = operation.PeekTag();
                        var code = ResultCode.InvalidCredentials;
                        if (auth.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                        {
                            var password = Encoding.UTF8.GetString(operation.ReadOctetString(auth));
                            if (name.Length != 0 || password.Length != 0)
                                Interlocked.Increment(ref credentialedSimpleBinds);
                            else Interlocked.Increment(ref anonymousBinds);
                            if (!RejectBinds && password == Password && name is FirstIdentity or SecondIdentity)
                            {
                                identity = name;
                                BoundIdentities.Enqueue(name);
                                code = ResultCode.Success;
                            }
                        }
                        else
                        {
                            Interlocked.Increment(ref saslBinds);
                            code = ResultCode.AuthMethodNotSupported;
                        }
                        await stream.WriteAsync(Result(id, 1, code), stop.Token);
                    }
                    else if (tag.TagValue == 3)
                    {
                        Interlocked.Increment(ref searches);
                        var baseDn = operation.ReadOctetString();
                        int synthetic = Timeline is null ? 0 : WindowsDiagnosticTimeline.Operation(baseDn);
                        Timeline?.Add(TimelineRole, connection, id, synthetic, "search");
                        if (BeforeCorrelatedSearchResponse is not null) await BeforeCorrelatedSearchResponse(connection, id, synthetic);
                        if (BeforeSearchResponse is not null) await BeforeSearchResponse();
                        if (DisconnectOnSearch) return; // Deterministic transport failure, including reconnects.
                        if (ServeBindingResolution && IsBindingResolution(baseDn, operation))
                        {
                            Interlocked.Increment(ref bindingReads);
                            await stream.WriteAsync(Entry(id, identity, new Dictionary<string, string>()), stop.Token);
                            await stream.WriteAsync(Result(id, 5, ResultCode.Success), stop.Token);
                        }
                        else if (ServeSyntheticSchema && (baseDn.Length == 0 || Encoding.UTF8.GetString(baseDn) == "CN=synthetic-schema"))
                        {
                            Interlocked.Increment(ref schemaReads);
                            var attributes = baseDn.Length == 0
                                ? new Dictionary<string, string> { ["schemaNamingContext"] = "CN=synthetic-schema" }
                                : new Dictionary<string, string> { ["lDAPDisplayName"] = "description", ["attributeSyntax"] = "2.5.5.12", ["oMSyntax"] = "64" };
                            await stream.WriteAsync(Entry(id, identity, attributes), stop.Token);
                            await stream.WriteAsync(Result(id, 5, ResultCode.Success), stop.Token);
                        }
                        else if (ReferralUrl is not null)
                        {
                            var referral = Timeline is null ? ReferralUrl :
                                ReferralUrl.Replace("/CN=target?", "/" + WindowsDiagnosticTimeline.BaseDn(synthetic) + "?", StringComparison.Ordinal);
                            Timeline?.Add(TimelineRole, connection, id, synthetic, "referral-send");
                            await stream.WriteAsync(Result(id, 5, ResultCode.Referral, referral), stop.Token);
                        }
                        else
                        {
                            Timeline?.Add(TimelineRole, connection, id, synthetic, "response-send");
                            await stream.WriteAsync(Entry(id, identity), stop.Token);
                            await stream.WriteAsync(Result(id, 5, ResultCode.Success), stop.Token);
                        }
                    }
                    else throw new InvalidDataException("Unexpected LDAP fixture operation.");
                }
            }
            catch (EndOfStreamException) { }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (AuthenticationException error) { TransportFailures.Enqueue(DescribeFailure(error)); }
            catch (IOException error) { TransportFailures.Enqueue(DescribeFailure(error)); } // Peer reset or deliberate fixture disconnect.
            catch (SocketException error) { TransportFailures.Enqueue(DescribeFailure(error)); }
            catch (ObjectDisposedException) { } // Deliberate fixture disconnect.
            catch { Timeline?.Add(TimelineRole, connection, 0, 0, "fault"); throw; }
            finally
            {
                Timeline?.Add(TimelineRole, connection, 0, 0, "close");
                stream.Dispose();
                Interlocked.Increment(ref closed);
            }
        }
    }

    // Only the preliminary DirectoryEntry object-resolution read is local.
    // Actual FindOne requests must still receive the configured referral.
    internal static bool IsBindingResolution(byte[] baseDn, AsnReader operation)
    {
        var scope = operation.ReadEnumeratedBytes();
        _ = operation.ReadEnumeratedBytes(); // dereference policy
        _ = operation.ReadInteger(); // size limit
        _ = operation.ReadInteger(); // time limit
        _ = operation.ReadBoolean();
        var filter = operation.ReadEncodedValue();
        var attributes = operation.ReadSequence();
        var names = new List<string>();
        while (attributes.HasData) names.Add(Encoding.UTF8.GetString(attributes.ReadOctetString()));
        operation.ThrowIfNotEmpty();
        return baseDn.AsSpan().SequenceEqual("CN=target"u8) && scope.Span.SequenceEqual(new byte[] { 0 }) &&
            filter.Span.SequenceEqual(new byte[] { 0x87, 11, (byte)'o', (byte)'b', (byte)'j', (byte)'e', (byte)'c', (byte)'t', (byte)'C', (byte)'l', (byte)'a', (byte)'s', (byte)'s' }) &&
            names.Count == 1 && names[0] == "1.1";
    }

    internal static bool ShouldRejectTlsProbe(bool enabled, bool tls, byte? first) => enabled && !tls && first == 0x16;

    internal static bool TryConsumeAbandon(AsnReader message)
    {
        var tag = message.PeekTag();
        if (tag.TagClass != TagClass.Application || tag.TagValue != 16) return false;
        // RFC 4511 4.11: primitive implicitly tagged MessageID; no response.
        var abandoned = message.ReadInteger(new Asn1Tag(TagClass.Application, 16));
        if (abandoned <= 0 || abandoned > int.MaxValue) throw new InvalidDataException("Invalid abandoned message ID.");
        return true;
    }

    private static string DescribeFailure(Exception error)
    {
        var details = new List<string>();
        for (Exception? current = error; current is not null; current = current.InnerException)
            details.Add($"{current.GetType().Name}:HResult={current.HResult:X8}" +
                (current is System.ComponentModel.Win32Exception native ? $":Native={native.NativeErrorCode}" : ""));
        return string.Join("/", details); // Never include exception messages or received bytes.
    }

    private async Task<byte[]> ReadMessage(Stream stream)
    {
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, stop.Token);
        if (header[0] != 0x30) throw new InvalidDataException("Expected LDAP message.");
        var length = (int)header[1];
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7f;
            if (count is < 1 or > 4) throw new InvalidDataException("Invalid LDAP length.");
            var bytes = new byte[count];
            await stream.ReadExactlyAsync(bytes, stop.Token);
            length = 0;
            foreach (var value in bytes) length = checked(length * 256 + value);
        }
        if (length > 65536) throw new InvalidDataException("Fixture message too large.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, stop.Token);
        return payload;
    }

    private static byte[] Result(int id, int operation, ResultCode code, string? referral = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.PushSequence();
        writer.WriteInteger(id);
        var tag = new Asn1Tag(TagClass.Application, operation, true);
        writer.PushSequence(tag);
        writer.WriteEnumeratedValue(code);
        writer.WriteOctetString([]);
        writer.WriteOctetString([]);
        if (referral is not null)
        {
            var refs = new Asn1Tag(TagClass.ContextSpecific, 3, true);
            writer.PushSequence(refs);
            writer.WriteOctetString(Encoding.UTF8.GetBytes(referral));
            writer.PopSequence(refs);
        }
        writer.PopSequence(tag);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static byte[] Entry(int id, string identity, IReadOnlyDictionary<string, string>? attributes = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.PushSequence();
        writer.WriteInteger(id);
        var tag = new Asn1Tag(TagClass.Application, 4, true);
        writer.PushSequence(tag);
        writer.WriteOctetString("CN=target"u8);
        writer.PushSequence();
        foreach (var pair in attributes ?? new Dictionary<string, string> { ["description"] = identity })
        {
            writer.PushSequence();
            writer.WriteOctetString(Encoding.UTF8.GetBytes(pair.Key));
            writer.PushSetOf();
            writer.WriteOctetString(Encoding.UTF8.GetBytes(pair.Value));
            writer.PopSetOf();
            writer.PopSequence();
        }
        writer.PopSequence();
        writer.PopSequence(tag);
        writer.PopSequence();
        return writer.Encode();
    }

    private enum ResultCode { Success = 0, AuthMethodNotSupported = 7, Referral = 10, InvalidCredentials = 49 }

    internal async Task DisconnectClients()
    {
        (TcpClient Client, Task Serving)[] current;
        lock (clients) current = clients.ToArray();
        foreach (var item in current) item.Client.Dispose();
        await Task.WhenAll(current.Select(item => item.Serving));
    }

    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        try { await accepting; await Task.WhenAll(clients.Select(item => item.Serving)); }
        finally { listener.Stop(); certificate?.Dispose(); stop.Dispose(); }
    }
}
