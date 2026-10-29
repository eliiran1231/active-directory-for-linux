using System.Security.Cryptography;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Owns explicit MIT FILE-cache bytes and their publication to restricted workers.
/// No cache path, environment or user credential store is read. Callers supply
/// complete cache bytes; the isolated MIT backend validates them before binding.
/// </summary>
public sealed class KerberosCredentialContext : IDisposable
{
    private readonly object gate = new();
    private readonly TimeProvider clock;
    private Generation? current;
    private long version;
    internal Guid Id { get; } = Guid.NewGuid();

    public KerberosCredentialContext(ReadOnlySpan<byte> credentialCache)
        : this(credentialCache, TimeProvider.System) { }

    internal KerberosCredentialContext(ReadOnlySpan<byte> credentialCache, TimeProvider clock)
    {
        this.clock = clock;
        current = new Generation(Copy(credentialCache), ++version, clock);
    }

    /// <summary>
    /// Publishes a replacement as a new incompatible generation, even if its
    /// principal has the same name. Already-admitted operations may finish;
    /// subsequent admissions cannot use the previous generation. This does not
    /// revoke server-side authorization of an operation already in progress.
    /// </summary>
    public void Publish(ReadOnlySpan<byte> credentialCache)
    {
        var bytes = Copy(credentialCache);
        Generation previous;
        lock (gate)
        {
            if (current is null) { CryptographicOperations.ZeroMemory(bytes); throw new ObjectDisposedException(nameof(KerberosCredentialContext)); }
            previous = current;
            try { current = new Generation(bytes, checked(++version), clock); }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        previous.Revoke();
    }

    private static byte[] Copy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > 1048576) throw new ArgumentException("Supply a complete cache of at most one MiB.", nameof(bytes));
        return bytes.ToArray();
    }

    internal Generation Capture()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(current is null, this);
            current!.RequireValid(); current.Retain(); return current;
        }
    }

    internal bool Register(Generation generation, LdapConnectionProvider.ConnectionKey key, object pool, Action retire)
    {
        lock (gate)
        {
            if (!ReferenceEquals(current, generation)) return false;
            generation.RequireValid(); generation.Retirements.TryAdd((pool, key), retire); return true;
        }
    }

    // This lock is the publication/admission linearization point. Never hold it
    // across process creation, pool waits, binding, IO or worker destruction.
    internal bool Admit(Generation generation)
    {
        lock (gate)
        {
            if (!ReferenceEquals(current, generation)) return false;
            generation.RequireValid(); return true;
        }
    }

    public void Dispose()
    {
        Generation? previous;
        lock (gate) { previous = current; current = null; }
        previous?.Revoke();
    }

    internal sealed class Generation(byte[] bytes, long version, TimeProvider clock) : IDisposable
    {
        private int references = 1, revoked;
        private long validUntil = long.MaxValue;
        internal byte[] Bytes { get; } = bytes;
        internal long Version { get; } = version;
        internal Dictionary<(object Pool, LdapConnectionProvider.ConnectionKey Key), Action> Retirements { get; } = [];
        internal bool Revoked => Volatile.Read(ref revoked) != 0;
        internal long Timestamp => clock.GetTimestamp();
        internal void Retain() => Interlocked.Increment(ref references);
        internal IDisposable RetainStartup() { Retain(); return new StartupRetention(this); }
        private sealed class StartupRetention(Generation owner) : IDisposable
        {
            private Generation? retained = owner;
            public void Dispose() => Interlocked.Exchange(ref retained, null)?.Dispose();
        }
        internal void SetValidity(long started, uint seconds)
        {
            if (seconds <= 5 || seconds == uint.MaxValue) throw new InvalidOperationException("Credentials have no usable finite lifetime.");
            var deadline = checked(started + (long)((seconds - 5d) * clock.TimestampFrequency));
            long previous;
            do { previous = Volatile.Read(ref validUntil); if (deadline >= previous) return; }
            while (Interlocked.CompareExchange(ref validUntil, deadline, previous) != previous);
        }
        internal void RequireValid()
        {
            if (clock.GetTimestamp() >= Volatile.Read(ref validUntil))
                throw new InvalidOperationException("Managed Kerberos credentials expired; publish a replacement.");
        }
        internal void Revoke()
        {
            if (Interlocked.Exchange(ref revoked, 1) != 0) return;
            try { foreach (var retire in Retirements.Values) retire(); }
            finally { Dispose(); }
        }
        public void Dispose()
        {
            if (Interlocked.Decrement(ref references) == 0) CryptographicOperations.ZeroMemory(Bytes);
        }
    }
}
