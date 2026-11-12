using System.Security.Cryptography;
using System.Text.Json;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.ReadProbe;

internal static class ProbeProgram
{
    internal static int Run(string[] args)
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_OFFLINE_TESTS"))) return Block("offline-guard");
        if (!args.Contains("--allow-live-read", StringComparer.Ordinal)) return Block("missing-cli-opt-in");
        if (Environment.GetEnvironmentVariable("ADFL_ACCOUNT_READ_PROBE") != "1") return Block("missing-environment-opt-in");
        if (!OperatingSystem.IsWindows() && (Environment.GetEnvironmentVariable("LDAPTLS_REQCERT") != "demand"
            || Environment.GetEnvironmentVariable("LDAPTLS_REQSAN") != "demand")) return Block("strict-native-tls-policy-required");
        ProbeConfiguration input;
        LdapReadOnlyProbePolicy policy;
        try
        {
            if (args.Count(value => value == "--supervised-read") != 1 || !Console.IsInputRedirected) return Block("supervisor-required");
            input = ProbeConfiguration.Parse(args.Where(value => value != "--supervised-read").ToArray());
            policy = new(input.Host, input.FixtureDn, input.SchemaDn);
        }
        catch { return Block("invalid-explicit-configuration"); }

        // No CLI or environment override: live admission stays blocked until
        // this candidate's separate security/containment review is complete.
        if (!ProbeReadiness.LiveEnabled) return Block("containment-review-pending");

        var phase = "credential-input";
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        using var watchdog = new Timer(_ => Abort("deadline"), null, TimeSpan.FromSeconds(55), Timeout.InfiniteTimeSpan);
        try
        {
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            Console.Out.WriteLine("READY " + nonce); Console.Out.Flush();
            var frame = new System.Text.StringBuilder();
            for (var index = 0; ; index++)
            {
                var value = Console.In.Read();
                if (value == '\n') break;
                if (value < 0 || index >= 65536) throw new InvalidOperationException();
                frame.Append((char)value);
            }
            using var json = JsonDocument.Parse(frame.ToString());
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 3
                || root.GetProperty("nonce").GetString() != nonce) throw new InvalidOperationException();
            var user = root.GetProperty("bindDn").GetString(); var password = root.GetProperty("password").GetString();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password)
                || user.Contains('\0') || password.Contains('\0')) throw new InvalidOperationException();
            // The launcher retains the pipe until completion. EOF or extra data
            // means supervision was lost or the framing contract was violated.
            new Thread(() => { try { Console.In.Read(); } catch { } Abort("supervision"); }) { IsBackground = true }.Start();
            policy.Check(); phase = "read-comparison";
            ProbeReads.Run(input, policy, user, password);
            policy.Check();
            if (System.Diagnostics.Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(55)) throw new TimeoutException();
            Console.Out.WriteLine("PASS read-only-protocols-entry-accountmanagement");
            return 0;
        }
        catch { Console.Error.WriteLine("FAIL " + phase); return 1; }
    }
    private static int Block(string reason) { Console.Error.WriteLine("BLOCKED " + reason); return 2; }
    private static void Abort(string reason)
    {
        // Emergency termination must not wait on a broken pipe or graceful
        // shutdown handler. Kill only this process; never produce a dump.
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        try { process.Kill(); }
        finally { Thread.Sleep(Timeout.Infinite); }
    }
}

internal static class ProbeReadiness
{
    internal static bool LiveEnabled => false;
}
