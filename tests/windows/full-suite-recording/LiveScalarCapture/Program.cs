using System.Reflection;
using System.Text.Json;
using AdForLinux.DifferentialTests;
var count = 0;
void Check(bool ok, string name) { if (!ok) throw new Exception(name); count++; }
var snapshot = typeof(SuiteCapture).GetMethod("Snapshot", BindingFlags.NonPublic | BindingFlags.Static)!;
JsonElement Snap(object? value, bool allow) => JsonSerializer.SerializeToElement(snapshot.Invoke(null, [value, allow]));
string Kind(object? value, bool allow) => Snap(value, allow).GetProperty("type").GetString()!;
Check(Kind(null, false) == "null", "default null");
foreach (var value in new object[] { 42, true, Signed.Min }) Check(Kind(value, false) == "redacted", "default redaction");
Check(Kind(true, true) == "boolean", "live boolean");
foreach (var value in new object[] { (byte)1, (sbyte)-1, (short)-2, (ushort)2, -3, 3u, long.MinValue, ulong.MaxValue })
    Check(Snap(value, true).GetProperty("replayable").GetBoolean(), "integral primitive");
foreach (var value in new object[] { "secret-password", "alice@example.test", new byte[] { 1, 2 }, DateTime.UnixEpoch,
    Guid.Empty, 1.5, 1.5m, 'x', new Poison(), new PoisonEnumerable(), typeof(Poison) })
    Check(Kind(value, true) == "redacted", "unsupported redaction without evaluation");
Check(Snap(Unsigned.Max, true).GetProperty("value").GetUInt64() == ulong.MaxValue, "unsigned full width");
Check(Snap(Signed.Min, true).GetProperty("value").GetInt64() == long.MinValue, "signed full width");
Check(Kind(typeof(ArgumentException), false) == "exception-type", "finite exception type");
Check(Kind("ArgumentException", true) == "exception-type", "finite exception string");
Check(Kind("SecretArgumentException", true) == "redacted", "no suffix admission");
Check(SuiteCapture.ReadReview(null, null, "") is null, "default no token");
void Reject(Action action, string name)
{
    var rejected = false;
    try { action(); } catch (InvalidOperationException) { rejected = true; }
    Check(rejected, name);
}
Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, null, ""), "flag alone rejected");
Reject(() => SuiteCapture.ReadReview("unknown", null, ""), "unknown mode rejected");
Reject(() => SuiteCapture.ReadReview(null, "unexpected", ""), "contradictory review rejected");
var root = Path.Combine(Path.GetTempPath(), "adfl-synthetic-scalars-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var path = Path.Combine(root, "review.json");
    var hash = new string('a', 64);
    var review = new SuiteCapture.LiveScalarReview(1, SuiteCapture.LiveScalarPolicy,
        "isolated-lab-scalar-values-reviewed", new string('b', 64), hash);
    void Save(SuiteCapture.LiveScalarReview r) => File.WriteAllText(path, JsonSerializer.Serialize(r,
        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
    Save(review);
    Check(SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, hash) == review, "matching attestation");
    Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, new string('c', 64)), "wrong assembly");
    Save(review with { PrivacyScope = "production" });
    Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, hash), "wrong scope");
    Save(review with { SourceTreeSha256 = "secret" });
    Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, hash), "malformed source pin");
    Save(review);
    File.WriteAllText(path, File.ReadAllText(path).Replace("{", "{\"schemaVersion\":1,"));
    Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, hash), "duplicate key");
    File.WriteAllText(path, new string(' ', 4097));
    Reject(() => SuiteCapture.ReadReview(SuiteCapture.LiveScalarPolicy, path, hash), "oversize");
    var current = (AsyncLocal<SuiteCapture.Session?>)typeof(SuiteCapture).GetField("Current", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
    path = Path.Combine(root, "observations.jsonl");
    var session = new SuiteCapture.Session { Path = path, Test = "synthetic-only", Execution = "synthetic", Review = review };
    current.Value = session;
    SuiteCapture.Comparison("equal", 7, 8, "Synthetic.cs", "Fixture", 1);
    SuiteCapture.Expected(9, "equal", 2, "Synthetic.cs", "Fixture");
    session.Review = null;
    SuiteCapture.Expected(10, "equal", 3, "Synthetic.cs", "Fixture");
    current.Value = null;
    var rows = File.ReadAllLines(path).Select(line => JsonDocument.Parse(line).RootElement.Clone()).ToArray();
    Check(rows[0].GetProperty("origin").GetString() == "explicit-microsoft-comparison", "pair source role only");
    Check(rows[1].GetProperty("origin").GetString() == "assertion-operand-unverified", "assertion remains unverified");
    Check(rows[0].GetProperty("value").GetProperty("value").GetInt32() == 7 && rows[0].GetProperty("other").GetProperty("value").GetInt32() == 8, "pair values");
    Check(rows[2].GetProperty("value").GetProperty("type").GetString() == "redacted", "default unknown site");
}
finally { Directory.Delete(root, recursive: true); }
Console.WriteLine($"Passed {count} synthetic live-scalar checks. No live suite execution.");
enum Unsigned : ulong { Max = ulong.MaxValue }
enum Signed : long { Min = long.MinValue }
sealed class Poison { public override string ToString() => throw new Exception("must not evaluate"); }
sealed class PoisonEnumerable : System.Collections.IEnumerable
{
    public System.Collections.IEnumerator GetEnumerator() => throw new Exception("must not enumerate");
}
