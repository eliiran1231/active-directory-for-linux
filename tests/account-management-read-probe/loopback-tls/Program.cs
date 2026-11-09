using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;

// Separate native SDK experiment. No production probe reference, live-enable
// switch, target-host argument, inherited credential or default LDAP config.
if (!OperatingSystem.IsLinux() || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_OFFLINE_TESTS"))
    || Environment.GetEnvironmentVariable("ADFL_LOOPBACK_TLS_TESTS") != "1"
    || Environment.GetEnvironmentVariable("LDAPNOINIT") != "1" || args.Length != 3
    || !int.TryParse(args[0], out var port) || port is < 1025 or > 65535
    || args[1] is not ("strict" or "insecure-control") || !File.Exists(args[2])) return 2;
var addresses = Dns.GetHostAddresses("localhost");
if (addresses.Length == 0 || addresses.Any(address => !address.Equals(IPAddress.Loopback) && !address.Equals(IPAddress.IPv6Loopback))) return 2;
var stage = "setup";
int? errorNumber = null;
try
{
    // LDAPNOINIT prevents reading system/user LDAP defaults, including possible
    // client keys. Explicit process-local native options are NOT evidence that
    // the production launcher's environment-based TLS settings are honored.
    Native.SetString(0x6002, Path.GetFullPath(args[2])); // CACERTFILE: fresh public fixture CA only
    var requirement = args[1] == "strict" ? 2 : 0;
    Native.SetInt(0x6006, requirement); // REQUIRE_CERT: DEMAND or isolated negative control
    Native.SetInt(0x601a, requirement); // REQUIRE_SAN
    Native.SetInt(0x600f, 0); // NEWCTX: client
    if (Native.GetInt(0x6006) != requirement || Native.GetInt(0x601a) != requirement) return 2;
    using var connection = new LdapConnection(new LdapDirectoryIdentifier("localhost", port, true, false))
    {
        AuthType = AuthType.Basic,
        Credential = new NetworkCredential("cn=loopback-fixture", "synthetic-only"),
        Timeout = TimeSpan.FromSeconds(2),
    };
    connection.SessionOptions.ProtocolVersion = 3;
    connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
    connection.SessionOptions.SecureSocketLayer = true;
    if (connection.SessionOptions.ReferralChasing != ReferralChasingOptions.None) return 2;
    stage = "bind";
    connection.Bind();
    stage = "search";
    var response = (SearchResponse)connection.SendRequest(new SearchRequest("cn=fixture,dc=loopback",
        "(objectClass=*)", SearchScope.Base, "cn") { SizeLimit = 2, TimeLimit = TimeSpan.FromSeconds(1) }, TimeSpan.FromSeconds(2));
    var outcome = response.References.Count > 0 ? "reference-observed"
        : response.Referral.Length > 0 ? "referral-observed" : response.Entries.Count == 1 ? "search-ok" : "unexpected-response";
    Report(outcome, null);
    return outcome == "unexpected-response" ? 1 : 0;
}
catch (DirectoryOperationException error) when (error.Response?.ResultCode == ResultCode.Referral)
{ Report("referral-observed", error.GetType().Name); return 0; }
catch (Exception error) { errorNumber = (error as LdapException)?.ErrorCode; Report("failure", error.GetType().Name + "/" + error.GetBaseException().GetType().Name); return 1; }

void Report(string outcome, string? error) => Console.WriteLine(JsonSerializer.Serialize(new
{
    outcome, stage, error,
    runtime = RuntimeInformation.FrameworkDescription,
    ldap_error = errorNumber,
    protocols = typeof(LdapConnection).Assembly.GetName().Version?.ToString(),
    tls_policy = "explicit-native-options; LDAPNOINIT=1",
}));

static class Native
{
    [DllImport("libldap-2.5.so.0", EntryPoint = "ldap_set_option", CallingConvention = CallingConvention.Cdecl)]
    private static extern int SetInteger(IntPtr handle, int option, ref int value);
    [DllImport("libldap-2.5.so.0", EntryPoint = "ldap_set_option", CallingConvention = CallingConvention.Cdecl)]
    private static extern int SetText(IntPtr handle, int option, [MarshalAs(UnmanagedType.LPUTF8Str)] string value);
    [DllImport("libldap-2.5.so.0", EntryPoint = "ldap_get_option", CallingConvention = CallingConvention.Cdecl)]
    private static extern int GetInteger(IntPtr handle, int option, out int value);
    internal static void SetInt(int option, int value) { if (SetInteger(IntPtr.Zero, option, ref value) != 0) throw new InvalidOperationException(); }
    internal static void SetString(int option, string value) { if (SetText(IntPtr.Zero, option, value) != 0) throw new InvalidOperationException(); }
    internal static int GetInt(int option) { if (GetInteger(IntPtr.Zero, option, out var value) != 0) throw new InvalidOperationException(); return value; }
}
