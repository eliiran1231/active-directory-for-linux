// Offline research: actual configuration ownership + explicitly simulated resolver/epoch behavior.
// No GetConnection, Bind, Search, ObjectSecurity getter, Principal.Save or directory I/O.
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;

Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; {RuntimeInformation.RuntimeIdentifier}");
using var entry = new DirectoryEntry("LDAP://dc.example.invalid/DC=example,DC=invalid", "fixture-user", "fixture-only-password", AuthenticationTypes.None);
var originalOptions = Options(entry);
Check(Field(originalOptions, "Host") is "dc.example.invalid", "explicit endpoint");
Check(Field(originalOptions, "BindDn") is "fixture-user", "configured identity");
Check((TimeSpan)Field(originalOptions, "Timeout")! == TimeSpan.FromSeconds(30), "default timeout");
var optionsWrapper = entry.Options;
optionsWrapper.SecurityMasks = SecurityMasks.Dacl;
entry.Username = "fixture-user-2";
Check(ReferenceEquals(optionsWrapper, entry.Options), "options wrapper retained");
Check(optionsWrapper.SecurityMasks == (SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl), "credential mutation resets options");
Check(Field(Options(entry), "BindDn") is "fixture-user-2", "new options use changed identity");
Check(Field(originalOptions, "BindDn") is "fixture-user", "old options retain old credential binding: not a safe resolver lifetime token");
using var child = (DirectoryEntry)Invoke(entry, "CreateEntryForDn", "CN=fixture,DC=example,DC=invalid");
entry.Username = "fixture-user-3";
Check(Field(Options(child), "BindDn") is "fixture-user-2", "derived entry owns credential snapshot");
entry.Close();
Check(!IsDisposed(entry), "Close keeps entry reusable");
Check(Field(Options(entry), "BindDn") is "fixture-user-3", "Close does not erase configured bind identity");
using var context = new PrincipalContext(ContextType.Domain, "dc.example.invalid", "DC=example,DC=invalid", ContextOptions.SimpleBind, "fixture-context", "fixture-only-password");
using var contextEntry = (DirectoryEntry)Invoke(context, "CreateDirectoryEntry", "CN=fixture,DC=example,DC=invalid");
context.Dispose();
Expect<ObjectDisposedException>(() => Options(context), "disposed PrincipalContext rejects new option acquisition");
Check(Field(Options(contextEntry), "BindDn") is "fixture-context", "already-created entry remains independently configured after context disposal");
child.Dispose();
Expect<ObjectDisposedException>(() => Options(child), "disposed entry rejects new option acquisition");
Console.WriteLine("PASS actual repository: lazy configuration, credential reset, Close, derived-entry snapshots and PrincipalContext/entry disposal ownership.");

// Actual configuration path, then proposed refusal policy. No connection or OS identity probe.
using var ambientEntry = new DirectoryEntry("LDAP://dc.example.invalid/DC=example,DC=invalid");
var ambientOptions = Options(ambientEntry);
Check(Field(ambientOptions, "AuthenticationType")!.ToString() == "Negotiate", "default Secure maps to Negotiate");
Check(Field(ambientOptions, "IsAnonymous") is false, "default Negotiate is not anonymous");
Check(ambientOptions.GetType().GetMethod("ToCredential")!.Invoke(ambientOptions, null) is null, "no explicit credential");
var ambientQueryCalls = 0;
Expect<InvalidOperationException>(() =>
{
    // Model gate only: configuration has no proof of effective authenticated identity.
    RequireAuthority(ambientOrDefault: true, provenPinnedLease: false);
    ambientQueryCalls++;
}, "ambient automatic lookup lacks proven pinned authority");
Check(ambientQueryCalls == 0, "ambient refusal occurs before simulated query");
Console.WriteLine("PASS actual default Negotiate/null-credential classification; MODEL refusal before lookup. OS identity continuity NOT tested.");

var sid = SidCodec.Parse("S-1-1-0");
var binaryFilter = "(objectSid=" + LdapFilter.EscapeBytes(sid) + ")";
Check(binaryFilter == @"(objectSid=\01\01\00\00\00\00\00\01\00\00\00\00)", "all SID octets escaped");
Check(LdapFilter.EscapeValue("a*)(x=\\\0") == @"a\2a\29\28x=\5c\00", "text assertion escaping");
Console.WriteLine("PASS existing codecs: exact binary SID filter and hostile text escaping. No LDAP request sent.");

using var modelEntry = new DirectoryEntry("LDAP://dc.example.invalid/DC=example,DC=invalid", "fixture", "fixture-only-password", AuthenticationTypes.None);
var owner = new ModelOwner(modelEntry);
var sink = new FakeLookup();
var cap = owner.Borrow();
var descriptor = new ModelDescriptor(cap);
Check(descriptor.GetSid() == "S-1-5-21-1-2-3-1001" && sink.Calls == 0, "SID getter offline");
Check(descriptor.GetName(sink) == "EXAMPLE\\fixture" && sink.Calls == 1, "attached name lookup");
owner.Rotate(() => modelEntry.Username = "fixture-new");
Expect<InvalidOperationException>(() => descriptor.GetName(sink), "stale descriptor capability rejects credential rotation");
Check(sink.Calls == 1 && descriptor.GetSid() == "S-1-5-21-1-2-3-1001", "stale failure sends nothing, raw identity remains usable");
var explicitCurrent = owner.Borrow();
Check(explicitCurrent.Resolve(sink) == "EXAMPLE\\fixture", "explicit reacquisition uses current owner epoch");
var mutation = new ModelDescriptor(explicitCurrent);
sink.AfterQuery = () => owner.Rotate(modelEntry.Close);
Expect<InvalidOperationException>(() => mutation.AddResolvedRule(sink), "rotation during lookup prevents mutation publication");
Check(mutation.EditCount == 0, "failed lookup has no mutation");
sink.AfterQuery = null;
var disposedCap = owner.Borrow();
modelEntry.Dispose();
Expect<ObjectDisposedException>(() => disposedCap.Resolve(sink), "disposed owner capability");
var detached = new ModelDescriptor(null);
Expect<InvalidOperationException>(() => detached.GetName(sink), "detached descriptor has no context");
Check(detached.GetSid() == "S-1-5-21-1-2-3-1001", "detached SID data remains usable");
Console.WriteLine("PASS model only: borrowed epoch revocation, no-lookup SID reads, explicit reacquisition, mid-lookup invalidation, disposal and detached data.");
Console.WriteLine("LDAP resolution, production invalidation hooks, Windows oracle and credential/network isolation: NOT exercised.");

// Copy-policy fixture: synthetic bytes/intent, not a real security descriptor or validator.
var sourceAuthority = new CopyAuthority("SOURCE");
var destinationAuthority = new CopyAuthority("DESTINATION");
var sourceCopy = new CopyDescriptor(new byte[] { 1, 2 }, 1, sourceAuthority);
var destinationCopy = CopyDescriptor.Assign(sourceCopy.ExportData(), destinationAuthority, true, 1);
Check(!ReferenceEquals(sourceCopy, destinationCopy), "cross-entry state independent");
Check(destinationCopy.Name() == "DESTINATION" && sourceCopy.Name() == "SOURCE", "destination uses own authority");
destinationCopy.Bytes[0] = 9;
Check(sourceCopy.Bytes[0] == 1, "destination edit does not change source");
sourceCopy.Bytes[1] = 8;
Check(destinationCopy.Bytes[1] == 2, "source edit does not change destination");
sourceAuthority.Valid = false;
Check(destinationCopy.Name() == "DESTINATION", "source authority expiry does not affect destination");
sourceAuthority.Valid = true;
destinationAuthority.Valid = false;
Expect<InvalidOperationException>(() => destinationCopy.Name(), "destination expired; no source fallback");
Check(sourceCopy.Name() == "SOURCE", "destination expiry leaves source unchanged");
var noAuthorityCopy = CopyDescriptor.Assign(sourceCopy.ExportData(), null, true, 1);
Expect<InvalidOperationException>(() => noAuthorityCopy.Name(), "copy without destination authority");
var ambientAuthority = new CopyAuthority("AMBIENT") { Ambient = true };
var ambientCopy = CopyDescriptor.Assign(sourceCopy.ExportData(), ambientAuthority, true, 1);
Expect<InvalidOperationException>(() => ambientCopy.Name(), "copy cannot establish ambient identity pinning");
var previousDestination = destinationCopy;
Expect<InvalidOperationException>(() => destinationCopy = CopyDescriptor.Assign(sourceCopy.ExportData(), null, false, 1), "copy validation failure before publication");
Expect<InvalidOperationException>(() => destinationCopy = CopyDescriptor.Assign(sourceCopy.ExportData(), null, true, 0), "unpermitted intent refuses transfer");
Check(ReferenceEquals(previousDestination, destinationCopy) && sourceCopy.Intent == 1, "failed assignments preserve states and intent");
Check(sourceAuthority.Calls == 2 && destinationAuthority.Calls == 2 && ambientAuthority.Calls == 0, "no hidden lookup during assignment or fallback");
Console.WriteLine("PASS MODEL cross-entry copy: independent data, destination-only authority, expiry isolation, missing/ambient refusal and validation-before-publication. Production assignment/OS identity NOT tested.");

static void RequireAuthority(bool ambientOrDefault, bool provenPinnedLease)
{
    if (ambientOrDefault && !provenPinnedLease)
        throw new InvalidOperationException("Effective authenticated authority is not pinned.");
}
static object Invoke(object owner, string method, params object[] args)
{
    var candidates = owner.GetType().GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
        .Where(m => m.Name == method && m.GetParameters().Length == args.Length).ToArray();
    try { return candidates.Single().Invoke(owner, args)!; }
    catch (TargetInvocationException ex) when (ex.InnerException is not null)
    { ExceptionDispatchInfo.Capture(ex.InnerException).Throw(); throw; }
}
static object Options(object owner) => Invoke(owner, "BuildOptions");
static object? Field(object value, string name) => value.GetType().GetProperty(name)!.GetValue(value);
static bool IsDisposed(DirectoryEntry value) => (bool)value.GetType().GetProperty("IsDisposed", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(value)!;
static void Check(bool ok, string label) { if (!ok) throw new Exception(label); }
static void Expect<T>(Action action, string label) where T : Exception
{
    try { action(); } catch (T ex) when (ex.GetType() == typeof(T)) { Console.WriteLine($"EXPECTED {typeof(T).Name}: {label}"); return; }
    throw new Exception("Missing expected error: " + label);
}

// Proposed ownership model, not attached to production lifecycle events. Contains no credential copies.
sealed class ModelOwner(DirectoryEntry entry)
{
    public DirectoryEntry Entry { get; } = entry;
    public int Epoch { get; private set; }
    public BorrowedCapability Borrow() => new(this, Epoch);
    public void Rotate(Action change) { Epoch++; change(); }
}
sealed class BorrowedCapability(ModelOwner owner, int epoch)
{
    private readonly WeakReference<ModelOwner> weakOwner = new(owner);
    private readonly int capturedEpoch = epoch;
    private ModelOwner Validate()
    {
        if (!weakOwner.TryGetTarget(out var current)) throw new InvalidOperationException("Owner expired.");
        // Read-only configuration access is the actual repository disposal check; no bind occurs.
        try { _ = current.Entry.GetType().GetMethod("BuildOptions", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(current.Entry, null); }
        catch (TargetInvocationException ex) when (ex.InnerException is ObjectDisposedException) { throw new ObjectDisposedException("DirectoryEntry"); }
        if (current.Epoch != capturedEpoch) throw new InvalidOperationException("Stale resolution context.");
        return current;
    }
    public string Resolve(FakeLookup sink)
    {
        var live = Validate();
        var result = sink.Query(); // Fixed data only; not a directory resolver.
        _ = Validate();
        GC.KeepAlive(live);
        return result;
    }
}
sealed class FakeLookup
{
    public int Calls;
    public Action? AfterQuery;
    public string Query() { Calls++; AfterQuery?.Invoke(); return "EXAMPLE\\fixture"; }
}
sealed class ModelDescriptor(BorrowedCapability? capability)
{
    public int EditCount;
    public string GetSid() => "S-1-5-21-1-2-3-1001";
    public string GetName(FakeLookup sink) => (capability ?? throw new InvalidOperationException("Explicit context required.")).Resolve(sink);
    public void AddResolvedRule(FakeLookup sink) { _ = GetName(sink); EditCount++; }
}

// Data transfer has no authority field. Intent and validation flags are fixture-only stand-ins.
sealed record CopyData(byte[] Bytes, int Intent);
sealed class CopyAuthority(string label)
{
    public bool Valid = true;
    public bool Ambient;
    public int Calls;
    public string Resolve()
    {
        if (!Valid || Ambient) throw new InvalidOperationException("Destination authority unavailable or unpinned.");
        Calls++;
        return label;
    }
}
sealed class CopyDescriptor(byte[] bytes, int intent, CopyAuthority? authority)
{
    public byte[] Bytes { get; } = bytes;
    public int Intent { get; } = intent;
    public CopyData ExportData() => new((byte[])Bytes.Clone(), Intent);
    public string Name() => (authority ?? throw new InvalidOperationException("No destination authority.")).Resolve();
    public static CopyDescriptor Assign(CopyData data, CopyAuthority? destinationAuthority, bool validated, int permittedIntent)
    {
        if (!validated || (data.Intent & ~permittedIntent) != 0)
            throw new InvalidOperationException("Provenance/coverage/intent validation required.");
        return new((byte[])data.Bytes.Clone(), data.Intent, destinationAuthority);
    }
}
