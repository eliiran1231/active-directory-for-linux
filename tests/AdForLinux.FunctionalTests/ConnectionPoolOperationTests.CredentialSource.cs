using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class SourceRecordingApi : NativeLdapBindingBackend.ISourceBindingApi
    {
        internal readonly RecordingBindingApi Inner = new();
        internal readonly List<NativeLdapBindingBackend.CredentialSource> Sources = [];
        public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancel, IntPtr state, out IntPtr authority)
            => throw new InvalidOperationException("Explicit sources must not enter ambient resolution.");
        public int ResolveFrom(ref NativeLdapBindingBackend.Profile profile, ref NativeLdapBindingBackend.CredentialSource source,
            NativeLdapBindingBackend.Cancelled cancel, IntPtr state, out IntPtr authority)
        { Sources.Add(source); return Inner.Resolve(ref profile, cancel, state, out authority); }
        public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
            NativeLdapBindingBackend.Cancelled cancel, IntPtr state, out IntPtr session) => Inner.Bind(authority, ref profile, cancel, state, out session);
        public void CloseAuthority(ref IntPtr authority) => Inner.CloseAuthority(ref authority);
        public void CloseSession(ref IntPtr session) => Inner.CloseSession(ref session);
    }

    [Fact]
    public void Explicit_source_routes_once_through_owner_and_never_falls_back_to_ambient_API()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        var source = new LdapCredentialSource(LdapCredentialSourceKind.File, "/recording/source");
        var api = new SourceRecordingApi(); api.Inner.AfterFirstBind = () => api.Inner.Source = 9;
        using (var owner = NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 2, api: api, source: source))
        {
            Assert.Equal(new[] { 7, 7 }, api.Inner.Consumed);
            Assert.Equal(source.AbsolutePath, Assert.Single(api.Sources).AbsolutePath);
            Assert.Equal(1u, api.Sources[0].Kind);
        }
        using (var next = NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 1, api: api,
            source: new(LdapCredentialSourceKind.DirectoryCollection, "/recording/collection")))
        { Assert.Equal(9, api.Inner.Consumed[^1]); Assert.Equal(2u, api.Sources[^1].Kind); }
        var legacy = new RecordingBindingApi();
        Assert.Throws<PlatformNotSupportedException>(() => NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 1, api: legacy, source: source));
        Assert.Equal(0, legacy.Resolutions); Assert.Equal(0, pool.Snapshot.Total);
        Assert.Equal(OfflineTestGuard.Message, Assert.Throws<InvalidOperationException>(() =>
            NativeLdapBindingBackend.ResolveForBinding(NativeOwnerOptions(), ReferralChasingOption.None, source: source)).Message);
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("FILE:/recording/cache")]
    [InlineData("DIR::/recording/cache")]
    [InlineData("/recording/../cache")]
    [InlineData("/recording//cache")]
    [InlineData("/recording/cache/")]
    [InlineData("/")]
    [InlineData("C:\\cache")]
    public void Source_paths_are_explicit_lexical_recipes_without_environment_or_filesystem_resolution(string path)
    {
        var profile = new LdapWorkerStart("offline.invalid", 389, false, true, true, 1, TimeSpan.FromSeconds(5),
            new(LdapCredentialSourceKind.File, path));
        Assert.Throws<ArgumentException>(() => LdapWorkerProtocol.ValidateStart(profile));
    }

    [Fact]
    public async Task Worker_source_descriptor_roundtrips_without_claiming_an_identity()
    {
        var source = new LdapCredentialSource(LdapCredentialSourceKind.DirectoryCollection, "/recording/collection");
        var profile = new LdapWorkerStart("offline.invalid", 389, false, true, true, 2, TimeSpan.FromSeconds(5), source);
        using var channel = new MemoryStream();
        await LdapWorkerProtocol.WriteAsync(channel, LdapWorkerProtocol.Frame(1, 0, "START", profile.Timeout, profile), default);
        channel.Position = 0;
        var copied = LdapWorkerProtocol.Payload<LdapWorkerStart>(await LdapWorkerProtocol.ReadAsync(channel, default));
        Assert.Equal(source, copied.CredentialSource); LdapWorkerProtocol.ValidateStart(copied);
        Assert.Throws<PlatformNotSupportedException>(() => new LdapCredentialSource((LdapCredentialSourceKind)3, "/recording/cache").Validate());
        Assert.Throws<ArgumentException>(() => new LdapCredentialSource(LdapCredentialSourceKind.File, "/recording/ca\0che").Validate());
        Assert.False(NativeLdapBindingBackend.SupportsFacadeRequests);
    }
}
