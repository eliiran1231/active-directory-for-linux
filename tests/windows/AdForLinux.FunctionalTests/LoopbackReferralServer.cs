using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AdForLinux.FunctionalTests;

// A deliberately small LDAP referral source for disposable Samba integration tests.
// It returns no entries: successful search data must come from the referral target.
// Never supplies real credentials; the source accepts synthetic test Basic binds.
internal sealed class LoopbackReferralServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly List<Task> clients = [];
    private readonly Task accepting;
    private readonly string target;
    private int binds, searches;
    internal int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    internal int Binds => Volatile.Read(ref binds);
    internal int Searches => Volatile.Read(ref searches);

    internal LoopbackReferralServer(string target)
    {
        AdForLinux.DirectoryServices.Ldap.OfflineTestGuard.RequireLiveAccess();
        this.target = target;
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
                clients.Add(Serve(client));
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            var stream = client.GetStream();
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    // LDAP uses definite BER lengths. Bound input before allocation.
                    var header = new byte[2];
                    await stream.ReadExactlyAsync(header, stop.Token);
                    if (header[0] != 0x30) throw new InvalidDataException("Expected LDAP message sequence.");
                    var length = (int)header[1];
                    if ((length & 0x80) != 0)
                    {
                        var count = length & 0x7f;
                        if (count is < 1 or > 3) throw new InvalidDataException("Invalid LDAP message length.");
                        var bytes = new byte[count];
                        await stream.ReadExactlyAsync(bytes, stop.Token);
                        length = 0;
                        foreach (var value in bytes) length = checked(length * 256 + value);
                    }
                    if (length > 65536) throw new InvalidDataException("LDAP fixture message too large.");
                    var payload = new byte[length];
                    await stream.ReadExactlyAsync(payload, stop.Token);
                    var request = new AsnReader(payload, AsnEncodingRules.BER);
                    var id = (int)request.ReadInteger();
                    var operation = request.PeekTag();
                    if (operation.TagClass != TagClass.Application) throw new InvalidDataException("Expected LDAP operation.");
                    if (operation.TagValue == 2) return; // Unbind
                    if (operation.TagValue == 0)
                    {
                        Interlocked.Increment(ref binds);
                        await stream.WriteAsync(Result(id, 1, referral: false), stop.Token);
                    }
                    else if (operation.TagValue == 3)
                    {
                        Interlocked.Increment(ref searches);
                        await stream.WriteAsync(Result(id, 5, referral: true), stop.Token);
                    }
                    else throw new InvalidDataException("Unexpected LDAP fixture operation.");
                }
            }
            catch (EndOfStreamException) { } // Normal client disposal.
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (IOException) when (stop.IsCancellationRequested) { }
        }
    }

    private byte[] Result(int id, int operation, bool referral)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.PushSequence();
        writer.WriteInteger(id);
        var tag = new Asn1Tag(TagClass.Application, operation, isConstructed: true);
        writer.PushSequence(tag);
        writer.WriteEnumeratedValue(referral ? LdapResult.Referral : LdapResult.Success);
        writer.WriteOctetString([]); // matchedDN
        writer.WriteOctetString([]); // diagnosticMessage
        if (referral)
        {
            var refs = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);
            writer.PushSequence(refs);
            writer.WriteOctetString(Encoding.UTF8.GetBytes(target));
            writer.PopSequence(refs);
        }
        writer.PopSequence(tag);
        writer.PopSequence();
        return writer.Encode();
    }

    private enum LdapResult { Success = 0, Referral = 10 }

    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        try
        {
            await accepting;
            await Task.WhenAll(clients);
        }
        finally
        {
            listener.Stop();
            stop.Dispose();
        }
    }
}
