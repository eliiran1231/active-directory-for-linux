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
    private int binds, searches, connections, closed, saslBinds;
    internal string? ReferralUrl { get; set; }
    internal bool RejectBinds { get; set; }
    internal int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    internal int Binds => Volatile.Read(ref binds);
    internal int Searches => Volatile.Read(ref searches);
    internal int Connections => Volatile.Read(ref connections);
    internal int Closed => Volatile.Read(ref closed);
    internal int SaslBinds => Volatile.Read(ref saslBinds);
    internal ConcurrentQueue<string> BoundIdentities { get; } = new();

    internal WindowsReferralEndpoint(bool tls)
    {
        OfflineTestGuard.RequireLiveAccess();
        if (tls)
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
            // or change machine trust; the temporary key is deleted on disposal.
#pragma warning disable SYSLIB0057
            certificate = new X509Certificate2(generated.Export(X509ContentType.Pfx));
#pragma warning restore SYSLIB0057
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
                Interlocked.Increment(ref connections);
                lock (clients) clients.Add((client, Serve(client)));
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            Stream stream = client.GetStream();
            try
            {
                if (certificate is not null)
                {
                    var secure = new SslStream(stream, leaveInnerStreamOpen: false);
                    stream = secure;
                    await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12,
                        ClientCertificateRequired = false,
                    }, stop.Token);
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
                    var operation = message.ReadSequence(tag);
                    if (tag.TagValue == 0)
                    {
                        Interlocked.Increment(ref binds);
                        _ = operation.ReadInteger();
                        var name = Encoding.UTF8.GetString(operation.ReadOctetString());
                        var auth = operation.PeekTag();
                        var code = ResultCode.InvalidCredentials;
                        if (auth.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                        {
                            var password = Encoding.UTF8.GetString(operation.ReadOctetString(auth));
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
                        if (ReferralUrl is not null)
                            await stream.WriteAsync(Result(id, 5, ResultCode.Referral, ReferralUrl), stop.Token);
                        else
                        {
                            await stream.WriteAsync(Entry(id, identity), stop.Token);
                            await stream.WriteAsync(Result(id, 5, ResultCode.Success), stop.Token);
                        }
                    }
                    else throw new InvalidDataException("Unexpected LDAP fixture operation.");
                }
            }
            catch (EndOfStreamException) { }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (IOException) { } // Peer reset or deliberate fixture disconnect.
            catch (ObjectDisposedException) { } // Deliberate fixture disconnect.
            finally
            {
                stream.Dispose();
                Interlocked.Increment(ref closed);
            }
        }
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

    private static byte[] Entry(int id, string identity)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.PushSequence();
        writer.WriteInteger(id);
        var tag = new Asn1Tag(TagClass.Application, 4, true);
        writer.PushSequence(tag);
        writer.WriteOctetString("CN=target"u8);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteOctetString("description"u8);
        writer.PushSetOf();
        writer.WriteOctetString(Encoding.UTF8.GetBytes(identity));
        writer.PopSetOf();
        writer.PopSequence();
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
