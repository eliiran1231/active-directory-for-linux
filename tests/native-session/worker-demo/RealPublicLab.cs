using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;

// Run only inside the approved disposable realm. No activation override, injected
// binding API or test native export: these are ordinary selected public objects.
internal static class RealPublicLab
{
    internal static async Task<int> Run()
    {
        var stage = 1;
        try
        {
            foreach (var client in new[] { "client-a", "client-b" })
            {
                var profile = new RestrictedKerberosProfile("/bundle/production-v1", "/run/adfl/" + client + ".ccache",
                    "ADFL.TEST", "127.0.0.1", 10389, "127.0.0.1", 10088);
                using var entry = profile.CreateDirectoryEntry("cn=" + client + ",dc=adfl,dc=test");
                stage = 21;
                entry.RefreshCache(["description"]);
                stage = 22;
                if ((string?)entry.Properties["description"].Value != client)
                    throw new InvalidDataException("Public read did not reach the expected protected entry.");
                // Server ACL requires both this exact authenticated identity and
                // SSF>=56; the other identity must not see its protected entry.
                stage = 3;
                using var root = profile.CreateDirectoryEntry("dc=adfl,dc=test");
                using var search = new DirectorySearcher(root, "(objectClass=organizationalRole)", ["description"], SearchScope.Subtree)
                { ReferralChasing = ReferralChasingOption.None, PageSize = 1, CacheResults = true,
                    ServerTimeLimit = TimeSpan.FromSeconds(30), ServerPageTimeLimit = TimeSpan.FromSeconds(7) };
                using var results = search.FindAll();
                var seen = results.Cast<SearchResult>().ToArray();
                if (seen.Length != 2 || seen.Any(value => (string?)value.Properties["description"][0] != client))
                    throw new InvalidDataException("Public cursor identity isolation failed.");
                stage = 4;
                using var context = RestrictedKerberosContext.Create(profile, "dc=adfl,dc=test");
                using var query = new UserPrincipal(context);
                using var principalSearch = new PrincipalSearcher(query);
                // Preserve the public searcher default; explicitly select the
                // no-referral policy required by this exact-target profile.
                var underlying = (DirectorySearcher)principalSearch.GetUnderlyingSearcher();
                underlying.ReferralChasing = ReferralChasingOption.None;
                // Keep PrincipalSearcher's separate 30-second server limit.
                using var principals = principalSearch.FindAll();
                if (principals.Any()) throw new InvalidDataException("Test directory unexpectedly contained AD user objects.");
            }
            stage = 6;
            var cache = File.ReadAllBytes("/run/adfl/client-a.ccache");
            using (var owned = new KerberosCredentialContext(cache))
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(cache);
                var profile = new RestrictedKerberosProfile("/bundle/production-v1", owned,
                    "ADFL.TEST", "127.0.0.1", 10389, "127.0.0.1", 10088);
                using var root = profile.CreateDirectoryEntry("dc=adfl,dc=test");
                using var search = new DirectorySearcher(root, "(objectClass=organizationalRole)", ["description"], SearchScope.Subtree)
                { ReferralChasing = ReferralChasingOption.None, PageSize = 1, CacheResults = true };
                var before = LdapRestrictedOperation.GroupCounters;
                var firstCreated = before.Created;
                for (var operation = 0; operation < 2; operation++)
                {
                    using var results = search.FindAll();
                    var rows = results.Cast<SearchResult>().ToArray();
                    if (rows.Length != 2 || rows.Any(row => (string?)row.Properties["description"][0] != "client-a"))
                        throw new InvalidDataException("Owned group identity or paging mismatch.");
                    if (operation == 0) firstCreated = LdapRestrictedOperation.GroupCounters.Created;
                }
                var after = LdapRestrictedOperation.GroupCounters;
                if (firstCreated <= before.Created || after.Created != firstCreated || after.Reused <= before.Reused)
                    throw new InvalidDataException("Separate public searches did not reuse a bound worker group.");
                cache = File.ReadAllBytes("/run/adfl/client-b.ccache");
                try { owned.Publish(cache); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(cache); }
                using var replacement = search.FindAll();
                var changed = replacement.Cast<SearchResult>().ToArray();
                if (changed.Length != 2 || changed.Any(row => (string?)row.Properties["description"][0] != "client-b"))
                    throw new InvalidDataException("Published identity did not replace the pooled group.");
                if (LdapRestrictedOperation.GroupCounters.Created <= after.Created)
                    throw new InvalidDataException("Publication did not replace the bound groups.");
            }
            stage = 5;
            var deadline = System.Diagnostics.Stopwatch.StartNew();
            while (LdapRestrictedOperation.Snapshot.Tracked != 0 && deadline.Elapsed < TimeSpan.FromSeconds(15))
                await Task.Delay(20);
            if (LdapRestrictedOperation.Snapshot.Tracked != 0) throw new InvalidOperationException("Public workers not reaped.");
            Console.WriteLine("PASS: selected public entry, paged cursor and principal context use admitted production host; protected ACL proves identity and SSF; workers reaped.");
            return 0;
        }
        catch (Exception error)
        {
            var category = error switch
            {
                PlatformNotSupportedException => 1, InvalidDataException => 2,
                System.IO.IOException => 3, TimeoutException => 4,
                DirectoryServicesCOMException => 5, InvalidOperationException => 6, _ => 9
            };
            Console.Error.WriteLine("Public lab failure category " + category);
            if (error is DirectoryServicesCOMException directoryError)
                Console.Error.WriteLine("Public lab directory error " + directoryError.ErrorCode);
            var known = new[] { "Worker operation failed.", "Cannot inspect deployment metadata.", "Cannot open deployment artifact.", "Deployment artifact changed during admission.", "Worker operation failed (marshal).", "Worker operation failed (library).", "Worker operation failed (argument).", "Worker operation failed (state)." };
            Console.Error.WriteLine("Public lab known failure " + Array.IndexOf(known, error.Message));
            Console.Error.WriteLine("Public lab ended channel " + (error is EndOfStreamException ? 1 : 0));
            for (var code = 2; code <= 13; code++)
                if (error.Message == "Worker native operation failed (status " + code + ").")
                    Console.Error.WriteLine("Public lab native status " + code);
            Console.Error.WriteLine("Public lab startup failure " + ((error.StackTrace?.Contains("StartAsync", StringComparison.Ordinal) ?? false) ? 1 : 0));
            var cleanup = System.Diagnostics.Stopwatch.StartNew();
            while (LdapRestrictedOperation.Snapshot.Tracked != 0 && cleanup.Elapsed < TimeSpan.FromSeconds(5))
                await Task.Delay(20);
            Console.Error.WriteLine("Public lab exit outcome " + LdapRestrictedOperation.LastExitOutcome);
            return stage;
        } // no credential/native diagnostic output
    }
}
