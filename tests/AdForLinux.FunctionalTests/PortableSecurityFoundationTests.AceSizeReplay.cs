using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> AceSizeRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.AceSize.net10.jsonl.gz";
#else
        const string resource = "AclOracle.AceSize.net8.jsonl.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip);
        while (reader.ReadLine() is { } line)
        {
            using var attempt = JsonDocument.Parse(line);
            using var native = JsonDocument.Parse(reader.ReadLine()!);
            using var managed = JsonDocument.Parse(reader.ReadLine()!);
            var id = attempt.RootElement.GetProperty("Case").GetInt32();
            Assert.Equal("Attempt", attempt.RootElement.GetProperty("Kind").GetString());
            Assert.Equal("Native", native.RootElement.GetProperty("Kind").GetString());
            Assert.Equal("Managed", managed.RootElement.GetProperty("Kind").GetString());
            Assert.Equal(id, native.RootElement.GetProperty("Case").GetInt32());
            Assert.Equal(id, managed.RootElement.GetProperty("Case").GetInt32());
            yield return new object[] { id, attempt.RootElement.GetProperty("Label").GetString()!,
                attempt.RootElement.GetProperty("InputUtf16Hex").GetString()!, managed.RootElement.GetRawText() };
        }
    }

    [Fact]
    public void Ace_size_precedence_inventory_contains_every_directed_input()
    {
        var rows = AceSizeRecordings().ToArray();
        var inputs = SddlAceSizeInputs.Create().ToArray();
        Assert.Equal(108, inputs.Length);
        Assert.Equal(Enumerable.Range(0, inputs.Length), rows.Select(x => (int)x[0]));
        foreach (var row in rows)
        {
            var input = inputs[(int)row[0]];
            Assert.Equal(input.Label, row[1]);
            Assert.Equal(SddlBoundaryInputs.Utf16Hex(input.Text), row[2]);
        }
    }

    [Theory]
    [MemberData(nameof(AceSizeRecordings))]
    public void Recorded_callback_ace_size_and_competing_errors_match_native_import(int caseId, string label, string inputHex, string json)
    {
        var input = SddlAceSizeInputs.Create().ElementAt(caseId);
        Assert.Equal(label, input.Label);
        Assert.Equal(input.Text, A.SddlUtf16.Decode(Convert.FromHexString(inputHex)));
        using var document = JsonDocument.Parse(json);
        var expected = document.RootElement.GetProperty("StringConstructor");
        A.RawSecurityDescriptor? raw = null;
        var actual = CaptureBoundary(() =>
        {
            raw = new A.RawSecurityDescriptor(input.Text);
            return new { Hex = Convert.ToHexString(BoundaryBytes(raw)), raw.BinaryLength, Control = (int)raw.ControlFlags };
        });
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected.GetRawText()), JsonNode.Parse(JsonSerializer.Serialize(actual))),
            $"Native ACE-size/precedence mismatch: {label}");
        if (raw is null) return;
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected.GetRawText()),
            JsonNode.Parse(document.RootElement.GetProperty("BinaryConstructor").GetRawText())));
        Assert.True(document.RootElement.GetProperty("BinaryInputUnchanged").GetBoolean());
        var bytes = BoundaryBytes(raw);
        Assert.Equal(bytes, BoundaryBytes(new A.RawSecurityDescriptor(bytes, 0)));
        Assert.Equal(bytes, BoundaryBytes(raw));
    }
}
