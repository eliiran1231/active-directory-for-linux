#pragma warning disable CA1416
using System.ComponentModel;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static JsonDocument ReadBoundaryRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Boundary.net10.json.gz";
#else
        const string resource = "AclOracle.Boundary.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        return JsonDocument.Parse(gzip);
    }

    public static IEnumerable<object[]> BoundaryRecordings()
    {
        using var document = ReadBoundaryRecordings();
        foreach (var row in document.RootElement.GetProperty("Observations").EnumerateArray())
        {
            // All 220 rows are retained and compared in the research report. The
            // explicitly listed 46 size rows have unresolved native behavior;
            // do not count them as passing parity or preservation exceptions.
            if (BoundarySizeGaps.ContainsKey(row.GetProperty("Case").GetInt32())) continue;
            yield return new object[] { row.GetProperty("Case").GetInt32(), row.GetProperty("Label").GetString()!, row.GetRawText() };
        }
    }

    [Fact]
    public void Boundary_research_inventory_keeps_unresolved_size_rows_explicit()
    {
        using var document = ReadBoundaryRecordings();
        var rows = document.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        Assert.Equal(Enumerable.Range(0, 220), rows.Select(x => x.GetProperty("Case").GetInt32()));
        Assert.Equal(46, BoundarySizeGaps.Count);
        Assert.Equal(64, BoundaryRefusals.Count);
        var inputs = SddlBoundaryInputs.Create().ToArray();
        foreach (var row in rows)
        {
            var id = row.GetProperty("Case").GetInt32();
            Assert.Equal(inputs[id].Label, row.GetProperty("Label").GetString());
            Assert.Equal(SddlBoundaryInputs.Utf16Hex(inputs[id].Text), row.GetProperty("InputUtf16Hex").GetString());
            if (BoundarySizeGaps.TryGetValue(id, out var hash))
            {
                Assert.Equal(hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(row.GetRawText()))).ToLowerInvariant());
                Assert.False(BoundaryRefusals.ContainsKey(id));
            }
        }
    }

    [Theory]
    [MemberData(nameof(BoundaryRecordings))]
    public void Recorded_boundary_representation_preserves_bytes_or_refuses_measured_loss(int caseId, string label, string json)
    {
        using var document = JsonDocument.Parse(json);
        var row = document.RootElement;
        var text = A.SddlUtf16.Decode(Convert.FromHexString(row.GetProperty("InputUtf16Hex").GetString()!));
        var input = SddlBoundaryInputs.Create().ElementAt(caseId);
        Assert.Equal(label, input.Label);
        Assert.Equal(input.Text, text);
        var refusal = BoundaryRefusals.GetValueOrDefault(caseId);
        if (refusal.Kind is not null)
            Assert.Equal(refusal.Hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant());
        if (refusal.Kind == "literal-nul-import")
        {
            Assert.Contains('\0', text);
            Assert.Equal(JsonValueKind.Null, row.GetProperty("Parse").GetProperty("ExceptionType").ValueKind);
            Assert.Equal("sddlForm", Assert.Throws<ArgumentException>(() => new A.RawSecurityDescriptor(text)).ParamName);
            return; // Native discards input after NUL; this is a pinned preservation refusal.
        }
        A.RawSecurityDescriptor? raw = null;
        var parsed = CaptureBoundary(() =>
        {
            raw = new A.RawSecurityDescriptor(text);
            return new { Hex = Convert.ToHexString(BoundaryBytes(raw)), raw.BinaryLength, Control = (int)raw.ControlFlags };
        });
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(row.GetProperty("Parse").GetRawText()), JsonNode.Parse(JsonSerializer.Serialize(parsed))),
            $"Native parse mismatch for boundary case {caseId}: {label}");
        if (raw is null) return;
        var before = BoundaryBytes(raw);
        Assert.Equal(before, BoundaryBytes(new A.RawSecurityDescriptor(before, 0)));
        if (refusal.Kind == "ace-omission-export")
        {
            var nativeText = A.SddlUtf16.Decode(Convert.FromHexString(row.GetProperty("FormatAll").GetProperty("Outcome").GetProperty("Utf16Hex").GetString()!));
            Assert.True(raw.SystemAcl!.Count > 0);
            Assert.Equal(0, new A.RawSecurityDescriptor(nativeText).SystemAcl!.Count);
            Assert.Throws<NotSupportedException>(() => raw.GetSddlForm(AccessControlSections.All));
        }
        else
        {
            var formatted = CaptureBoundary(() =>
            {
                var output = raw.GetSddlForm(AccessControlSections.All);
                return new { Utf16Hex = SddlBoundaryInputs.Utf16Hex(output), CodeUnits = output.Length };
            });
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(row.GetProperty("FormatAll").GetRawText()), JsonNode.Parse(JsonSerializer.Serialize(formatted))),
                $"Native format mismatch for boundary case {caseId}: {label}");
            Assert.Equal(before, BoundaryBytes(new A.RawSecurityDescriptor(raw.GetSddlForm(AccessControlSections.All))));
        }
        Assert.True(row.GetProperty("BinaryUnchangedByFormat").GetBoolean());
        Assert.Equal(before, BoundaryBytes(raw));
    }

    private static readonly Dictionary<int, (string Kind, string Hash)> BoundaryRefusals = ReadBoundaryRefusals();
    private static readonly Dictionary<int, string> BoundarySizeGaps = ReadBoundarySizeGaps();
    private static Dictionary<int, string> ReadBoundarySizeGaps()
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Boundary.SizeGaps.json")!;
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.EnumerateArray().ToDictionary(x => x.GetProperty("Case").GetInt32(), x => x.GetProperty("NativeRowSha256").GetString()!);
    }
    private static Dictionary<int, (string Kind, string Hash)> ReadBoundaryRefusals()
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Boundary.Refusals.json")!;
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.EnumerateArray().ToDictionary(x => x.GetProperty("Case").GetInt32(),
            x => (x.GetProperty("Kind").GetString()!, x.GetProperty("RowSha256").GetString()!));
    }

    private static byte[] BoundaryBytes(A.RawSecurityDescriptor raw)
    {
        var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0); return bytes;
    }
    private static object CaptureBoundary(Func<object> action)
    {
        object? result = null; string? type = null, parameter = null; int? code = null;
        try { result = action(); }
        catch (Exception ex) { type = ex.GetType().FullName; parameter = (ex as ArgumentException)?.ParamName; code = (ex as Win32Exception)?.NativeErrorCode; }
        return new { Outcome = result, ExceptionType = type, ParamName = parameter, NativeErrorCode = code };
    }
}
