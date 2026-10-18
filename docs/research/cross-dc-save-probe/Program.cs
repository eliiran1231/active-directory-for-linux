using System.DirectoryServices.Protocols;
using System.Net;
using System.Text.Json;
using Sid = AdForLinux.Security.Principal.SecurityIdentifier;

// User-run only; never part of the offline workflow. No fixture creation,
// automatic retries, rollback, credential forwarding or referral following.
if (args.Length != 1 || args[0] is not ("--read-only" or "--execute-guid-move" or "--execute-guid-modify"))
{
    Console.Error.WriteLine("Choose --read-only, --execute-guid-move or --execute-guid-modify. See README.md; mutation modes require an existing disposable fixture and explicit user authorization.");
    return 2;
}
var outcome = "preflight";
try
{
    var expectedDomain = Guid.Parse(Required("DOMAIN_GUID"));
    var expectedDomainSid = new Sid(Required("DOMAIN_SID")).Value;
    var expectedObject = Guid.Parse(Required("OBJECT_GUID"));
    var expectedObjectSid = new Sid(Required("OBJECT_SID")).Value;
    var containerGuid = Guid.Parse(Required("CONTAINER_GUID"));
    if (new Sid(expectedObjectSid).AccountDomainSid?.Value != expectedDomainSid)
        throw new InvalidOperationException("Object domain mismatch.");
    using var source = Connect("SOURCE");
    using var destination = Connect("DESTINATION");
    var sourceNc = Text(Read(source, "", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"), "defaultNamingContext");
    var destinationNc = Text(Read(destination, "", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"), "defaultNamingContext");
    var sourceDomain = Read(source, sourceNc, "(objectClass=domainDNS)", SearchScope.Base, "objectGUID", "objectSid");
    var destinationDomain = Read(destination, destinationNc, "(objectClass=domainDNS)", SearchScope.Base, "objectGUID", "objectSid");
    Identity(sourceDomain, expectedDomain, expectedDomainSid); Identity(destinationDomain, expectedDomain, expectedDomainSid);
    var original = Find(source, sourceNc, expectedObject); var replica = Find(destination, destinationNc, expectedObject);
    Identity(original, expectedObject, expectedObjectSid); Identity(replica, expectedObject, expectedObjectSid);
    var container = Find(destination, destinationNc, containerGuid);
    if (GuidValue(container) != containerGuid) throw new InvalidOperationException("Container mismatch.");
    var objectAddress = $"<GUID={expectedObject:D}>";
    var containerAddress = $"<GUID={containerGuid:D}>";
    Emit(new { phase = "preflight", mode = args[0], sourceDn = original.DistinguishedName,
        destinationDn = replica.DistinguishedName, containerDn = container.DistinguishedName,
        objectAddress, containerAddress, domainGuid = expectedDomain, objectGuid = expectedObject });
    if (args[0] == "--read-only") return 0;

    DirectoryRequest request;
    string? expectedDn = null, description = null;
    if (args[0] == "--execute-guid-move")
    {
        var rdn = Required("NEW_RDN");
        expectedDn = rdn + "," + container.DistinguishedName;
        request = new ModifyDNRequest(objectAddress, containerAddress, rdn) { DeleteOldRdn = true };
        Emit(new { phase = "request", operation = "ModifyDN", objectAddress, containerAddress, newRdn = rdn });
    }
    else
    {
        description = Required("DESCRIPTION");
        var change = new DirectoryAttributeModification { Name = "description", Operation = DirectoryAttributeOperation.Replace };
        change.Add(description);
        var modify = new ModifyRequest(objectAddress); modify.Modifications.Add(change); request = modify;
        Emit(new { phase = "request", operation = "Modify", objectAddress, attribute = "description" });
    }
    outcome = "uncertain";
    var response = destination.SendRequest(request);
    if (response.ResultCode != ResultCode.Success) throw new DirectoryOperationException(response);
    outcome = "acknowledged";
    var after = Find(destination, destinationNc, expectedObject);
    Identity(after, expectedObject, expectedObjectSid);
    var matches = expectedDn is not null
        ? after.DistinguishedName.Equals(expectedDn, StringComparison.OrdinalIgnoreCase)
        : Text(after, "description") == description;
    Emit(new { phase = "readback", outcome, matches, actualDn = after.DistinguishedName, objectGuid = GuidValue(after) });
    return matches ? 0 : 1;
}
catch (DirectoryOperationException error) when (error.Response is not null && outcome != "acknowledged")
{
    Emit(new { phase = "failure", outcome = "rejected", resultCode = error.Response.ResultCode.ToString() });
    return 1;
}
catch (Exception error)
{
    // No automatic compensating write: a timeout is not rejection evidence.
    Emit(new { phase = "failure", outcome, errorType = error.GetType().FullName });
    return 1;
}

static string Required(string suffix) => Environment.GetEnvironmentVariable("ADFL_CROSS_DC_" + suffix) is { Length: > 0 } value
    ? value : throw new InvalidOperationException("Missing ADFL_CROSS_DC_" + suffix);
static LdapConnection Connect(string endpoint)
{
    var identifier = new LdapDirectoryIdentifier(Required(endpoint + "_HOST"), 636, false, false);
    var connection = new LdapConnection(identifier,
        new NetworkCredential(Required(endpoint + "_USER"), Required(endpoint + "_PASSWORD")), AuthType.Basic);
    connection.Timeout = TimeSpan.FromSeconds(20);
    connection.SessionOptions.ProtocolVersion = 3;
    connection.SessionOptions.SecureSocketLayer = true;
    connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
    try { connection.Bind(); return connection; } catch { connection.Dispose(); throw; }
}
static SearchResultEntry Read(LdapConnection connection, string dn, string filter, SearchScope scope, params string[] attributes)
{
    var response = (SearchResponse)connection.SendRequest(new SearchRequest(dn, filter, scope, attributes));
    if (response.Entries.Count != 1 || response.References.Count != 0) throw new InvalidOperationException("Identity proof is missing, ambiguous or referred.");
    return response.Entries[0];
}
static SearchResultEntry Find(LdapConnection connection, string nc, Guid guid) => Read(connection, nc,
    "(objectGUID=" + string.Concat(guid.ToByteArray().Select(b => "\\" + b.ToString("X2"))) + ")", SearchScope.Subtree,
    "objectGUID", "objectSid", "description");
static string Text(SearchResultEntry entry, string name) => entry.Attributes[name] is { Count: 1 } values
    ? (string)values.GetValues(typeof(string))[0] : throw new InvalidOperationException("Missing scalar.");
static Guid GuidValue(SearchResultEntry entry) => entry.Attributes["objectGUID"] is { Count: 1 } values
    && values[0] is byte[] { Length: 16 } bytes ? new Guid(bytes) : throw new InvalidOperationException("Missing GUID.");
static void Identity(SearchResultEntry entry, Guid guid, string sid)
{
    if (GuidValue(entry) != guid || entry.Attributes["objectSid"] is not { Count: 1 } values
        || values[0] is not byte[] bytes || new Sid(bytes, 0).Value != sid)
        throw new InvalidOperationException("GUID/SID mismatch.");
}
static void Emit(object value) => Console.WriteLine(JsonSerializer.Serialize(value));
