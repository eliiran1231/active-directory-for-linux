using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static JsonDocument ReadSizeRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Size.net10.json.gz";
#else
        const string resource = "AclOracle.Size.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        return JsonDocument.Parse(gzip);
    }

    private static readonly Dictionary<int, (string Kind, string Hash)> SizeExceptions = ReadSizeExceptions();
    private static Dictionary<int, (string Kind, string Hash)> ReadSizeExceptions()
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Size.Exceptions.json")!;
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.EnumerateArray().ToDictionary(x => x.GetProperty("Case").GetInt32(),
            x => (x.GetProperty("Kind").GetString()!, x.GetProperty("RowSha256").GetString()!));
    }

    public static IEnumerable<object[]> SizeRecordings()
    {
        using var document = ReadSizeRecordings();
        foreach (var row in document.RootElement.GetProperty("Observations").EnumerateArray())
        {
            var id = row.GetProperty("Case").GetInt32();
            // Unresolved native allocation behavior is inventoried, not parity.
            if (SizeExceptions.GetValueOrDefault(id).Kind == "unresolved-size") continue;
            yield return new object[] { id, row.GetProperty("Label").GetString()!, row.GetRawText() };
        }
    }

    [Theory]
    [MemberData(nameof(SizeRecordings))]
    public void Recorded_size_representation_preserves_bytes_or_refuses_measured_loss(int caseId, string label, string json)
        => VerifyBoundaryObservation(caseId, label, json, SddlBoundaryInputs.CreateSizeFollowup().ElementAt(caseId), SizeExceptions.GetValueOrDefault(caseId));

    [Fact]
    public void Size_research_inventory_keeps_unresolved_allocation_rows_explicit()
    {
        using var document = ReadSizeRecordings();
        var rows = document.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        Assert.Equal(Enumerable.Range(0, 316), rows.Select(x => x.GetProperty("Case").GetInt32()));
        Assert.Equal(243, SizeExceptions.Values.Count(x => x.Kind == "unresolved-size"));
        Assert.Equal(26, SizeExceptions.Values.Count(x => x.Kind == "ace-omission-export"));
        var inputs = SddlBoundaryInputs.CreateSizeFollowup().ToArray();
        foreach (var row in rows)
        {
            var id = row.GetProperty("Case").GetInt32();
            Assert.Equal(inputs[id].Label, row.GetProperty("Label").GetString());
            Assert.Equal(SddlBoundaryInputs.Utf16Hex(inputs[id].Text), row.GetProperty("InputUtf16Hex").GetString());
            if (SizeExceptions.TryGetValue(id, out var exception))
                Assert.Equal(exception.Hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(row.GetRawText()))).ToLowerInvariant());
        }
    }
}
