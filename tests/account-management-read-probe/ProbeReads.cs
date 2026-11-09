using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Sid = AdForLinux.Security.Principal.SecurityIdentifier;

namespace AdForLinux.ReadProbe;

internal static class ProbeReads
{
    private static readonly string[] Attributes = ["objectGUID", "objectSid", "sAMAccountName", "description", "displayName"];
    private sealed record Snapshot(Guid Guid, string Sid, string Sam, string? Description, string? DisplayName);

    // Actual stock Protocols paths; no neutral backend or narrowed materializer.
    // All exceptions are sanitized by the executable boundary, never dumped.
    internal static void Run(ProbeConfiguration input, LdapReadOnlyProbePolicy policy, string bindDn, string password,
        Func<LdapConnectionOptions, LdapConnection>? controlledBaseline = null,
        Action<DirectoryEntry>? controlledEntry = null, Action<PrincipalContext>? controlledContext = null,
        Action<DirectorySearcher>? controlledSearcher = null)
    {
        if ((controlledBaseline is not null || controlledEntry is not null || controlledContext is not null || controlledSearcher is not null)
            && !OfflineTestGuard.Enabled) throw new InvalidOperationException("Controlled probe execution requires offline mode.");
        var recipe = new LdapConnectionOptions
        {
            Host = input.Host, Port = 636, UseSsl = true, AuthenticationType = AuthType.Basic,
            BindDn = bindDn, BindPassword = password, Timeout = TimeSpan.FromSeconds(10), ReadOnlyProbe = policy,
        };
        Snapshot baseline;
        using (var connection = controlledBaseline is null ? LdapConnectionFactory.CreateBound(recipe) : controlledBaseline(recipe))
        {
            var response = (SearchResponse)connection.SendRequestTracked(new SearchRequest(input.FixtureDn,
                "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, Attributes) { SizeLimit = 2 });
            var row = response.Entries[0];
            object[] Values(string name) => row.Attributes[name] is { } value
                ? value.GetValues(name is "objectGUID" or "objectSid" ? typeof(byte[]) : typeof(string)) : [];
            baseline = Read(Values);
            Require(baseline.Guid == input.Guid && baseline.Sam == input.Sam);
        }
        using (var entry = new DirectoryEntry("LDAP://" + input.Host + ":636/" + input.FixtureDn, recipe.Clone()))
        {
            controlledEntry?.Invoke(entry);
            entry.RefreshCache(Attributes);
            Require(Read(name => entry.Properties[name].Cast<object>().ToArray()) == baseline);
        }
        using (var context = new PrincipalContext(policy, bindDn, password))
        using (var query = new UserPrincipal(context) { SamAccountName = input.Sam })
        using (var searcher = new PrincipalSearcher(query))
        {
            controlledContext?.Invoke(context);
            var directorySearcher = (DirectorySearcher)searcher.GetUnderlyingSearcher();
            controlledSearcher?.Invoke(directorySearcher);
            directorySearcher.SearchScope = AdForLinux.DirectoryServices.SearchScope.Base;
            directorySearcher.PageSize = 0; directorySearcher.CacheResults = true; directorySearcher.Asynchronous = false;
            directorySearcher.ReferralChasing = ReferralChasingOption.None;
            directorySearcher.SizeLimit = 2;
            directorySearcher.ClientTimeout = TimeSpan.FromSeconds(10);
            directorySearcher.ServerTimeLimit = TimeSpan.FromSeconds(10);
            using var results = searcher.FindAll();
            using var cursor = results.GetEnumerator();
            Require(cursor.MoveNext());
            using var user = cursor.Current;
            Require(user is UserPrincipal && user.Guid == baseline.Guid && user.Sid?.Value == baseline.Sid
                && string.Equals(user.DistinguishedName, input.FixtureDn, StringComparison.OrdinalIgnoreCase)
                && user.SamAccountName == baseline.Sam && user.Description == baseline.Description
                && user.DisplayName == baseline.DisplayName);
            Require(!cursor.MoveNext());
        }
        // Resources have all been disposed before the final policy/deadline gate.
        policy.Check();
    }

    private static Snapshot Read(Func<string, object[]> values)
    {
        var guid = values("objectGUID"); var sid = values("objectSid"); var sam = values("sAMAccountName");
        Require(guid is [byte[] { Length: 16 }] && sid is [byte[]] && sam is [string]);
        var parsedSid = new Sid((byte[])sid[0], 0);
        Require(parsedSid.BinaryLength == ((byte[])sid[0]).Length);
        return new(new Guid((byte[])guid[0]), parsedSid.Value,
            (string)sam[0], Optional(values("description")), Optional(values("displayName")));
    }
    private static string? Optional(object[] values)
    {
        Require(values.Length == 0 || values is [string]);
        return values.Length == 0 ? null : (string)values[0];
    }
    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Probe comparison failed."); }
}
