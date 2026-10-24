namespace AdForLinux.DirectoryServices.Ldap;

// Not an activation switch. Each guarded invocation explicitly carries its own
// diagnostic capability; public callers cannot obtain it or install hooks.
internal sealed class ContextScopedReadDiagnostic : IDisposable
{
    private readonly HashSet<LdapConnectionProvider.ConnectionKey> keys = [];
    internal ContextRequestBoundary? Boundary { get; }
    internal bool InstrumentationFailed => Boundary?.Failed == true;
    internal ContextScopedReadDiagnostic(Action<string, Action>? scope = null)
    { Validate(); if (scope is not null) Boundary = new(scope); }
    internal static void Validate()
    {
        OfflineTestGuard.RequireLiveAccess();
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_REFERRAL_OWNED_KEY_DIRECTORY")))
            throw new InvalidOperationException("Restricted standalone context-scoped diagnostic required.");
    }
    internal void Track(LdapConnectionProvider.ConnectionKey key) { lock (keys) keys.Add(key); }
    public void Dispose()
    {
        Exception? failure = null;
        lock (keys)
        {
            foreach (var key in keys)
                try { LdapConnectionProvider.RetireContextScopedDiagnostic(key); }
                catch (Exception error) { failure ??= error; }
            keys.Clear();
        }
        if (failure is not null) throw failure;
    }
}
