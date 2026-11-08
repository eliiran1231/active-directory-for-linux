// Admission-only scaffold. This executable contains no LDAP types, credential
// reads, connections, contexts, entries, native calls or live execution path.
if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_OFFLINE_TESTS")))
    return Block("offline-guard");
if (!args.Contains("--allow-live-read", StringComparer.Ordinal))
    return Block("missing-cli-opt-in");
if (Environment.GetEnvironmentVariable("ADFL_ACCOUNT_READ_PROBE") != "1")
    return Block("missing-environment-opt-in");
if (!OperatingSystem.IsWindows() &&
    (Environment.GetEnvironmentVariable("LDAPTLS_REQCERT") != "demand" ||
     Environment.GetEnvironmentVariable("LDAPTLS_REQSAN") != "demand"))
    return Block("strict-native-tls-policy-required");

try
{
    var options = Parse(args);
    Require(options.Count == 5);
    Require(Uri.CheckHostName(options["host"]) == UriHostNameType.Dns);
    Require(options["port"] == "636");
    Require(!string.IsNullOrWhiteSpace(options["fixture-dn"]) && !options["fixture-dn"].Contains('\0'));
    Require(!string.IsNullOrWhiteSpace(options["sam"]) && !options["sam"].Contains('\0'));
    Require(Guid.TryParse(options["guid"], out var guid) && guid != Guid.Empty);
}
catch (Exception error) when (error is ArgumentException or KeyNotFoundException or InvalidOperationException)
{
    return Block("invalid-explicit-configuration");
}

// Current public Basic/SSL principal materialization can reopen an entry with
// the default External referral policy. Opt-ins cannot weaken the fixture's
// exact-endpoint requirement. A separately reviewed containment seam is needed.
return Block("referral-containment-unavailable");

static int Block(string reason) { Console.Error.WriteLine("BLOCKED " + reason); return 2; }
static void Require(bool condition) { if (!condition) throw new InvalidOperationException(); }
static Dictionary<string, string> Parse(string[] arguments)
{
    var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < arguments.Length; index++)
    {
        var argument = arguments[index];
        if (argument == "--allow-live-read") continue;
        Require(argument is "--host" or "--port" or "--fixture-dn" or "--sam" or "--guid");
        Require(index + 1 < arguments.Length);
        Require(parsed.TryAdd(argument[2..], arguments[++index]));
    }
    return parsed;
}
