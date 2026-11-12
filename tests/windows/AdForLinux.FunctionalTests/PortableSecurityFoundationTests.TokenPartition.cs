using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> TokenPartitionRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.TokenPartition.net10.jsonl.gz";
#else
        const string resource = "AclOracle.TokenPartition.net8.jsonl.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip);
        while (reader.ReadLine() is { } attempt)
        {
            var control = reader.ReadLine()!;
            var native = reader.ReadLine()!;
            var replay = reader.ReadLine()!;
            using var document = JsonDocument.Parse(attempt);
            yield return new object[] { document.RootElement.GetProperty("Case").GetInt32(), attempt, control, native, replay };
        }
    }

    [Fact]
    public void Token_partition_experiment_has_exactly_six_fixed_total_inputs()
    {
        var rows = TokenPartitionRecordings().ToArray();
        Assert.Equal(Enumerable.Range(0,6), rows.Select(row => (int)row[0]));
        for (var after = 0; after < 2; after++)
        {
            var lengths = new HashSet<int>();
            foreach (var row in rows.Where(row => (int)row[0] % 2 == after))
            {
                using var attempt = JsonDocument.Parse((string)row[1]);
                var a = attempt.RootElement.GetProperty("AttributeUnits").GetInt32();
                var b = attempt.RootElement.GetProperty("LiteralUnits").GetInt32();
                Assert.Equal(32703, a+b);
                Assert.Equal("A" + new string('x',32702), "A" + new string('x',a-1) + new string('x',b));
                lengths.Add(attempt.RootElement.GetProperty("InputUtf16Hex").GetString()!.Length);
            }
            Assert.Single(lengths);
        }
    }

    [Theory]
    [MemberData(nameof(TokenPartitionRecordings))]
    public void Fixed_total_condition_tokens_match_native_compile_without_claiming_failed_converter_parity(
        int id, string attemptJson, string controlJson, string nativeJson, string replayJson)
    {
        using var attempt = JsonDocument.Parse(attemptJson);
        using var control = JsonDocument.Parse(controlJson);
        using var native = JsonDocument.Parse(nativeJson);
        using var replay = JsonDocument.Parse(replayJson);
        var documents = new[] { attempt, control, native, replay };
        var kinds = new[] { "Attempt", "CompileControl", "Native", "Replay" };
        for (var i=0; i<documents.Length; i++)
        {
            Assert.Equal(id, documents[i].RootElement.GetProperty("Case").GetInt32());
            Assert.Equal(kinds[i], documents[i].RootElement.GetProperty("Kind").GetString());
        }
        var a = new[] { 1,16351,32702 }[id/2];
        var b = 32703-a;
        var condition = $"(@User.A{new string('x',a-1)} == \"{new string('x',b)}\")";
        var text = $"D:(XA;;RP;;;WD;{condition})" + (id%2==1 ? "(A;;RP;;;WD)" : "");
        Assert.Equal(a, attempt.RootElement.GetProperty("AttributeUnits").GetInt32());
        Assert.Equal(b, attempt.RootElement.GetProperty("LiteralUnits").GetInt32());
        Assert.Equal(65532, attempt.RootElement.GetProperty("Capacity").GetInt32());
        Assert.Equal(text, Encoding.Unicode.GetString(Convert.FromHexString(attempt.RootElement.GetProperty("InputUtf16Hex").GetString()!)));
        Assert.True(control.RootElement.GetProperty("Established").GetBoolean());
        var steps = control.RootElement.GetProperty("Steps");
        var aclBytes = Convert.FromHexString(steps[1].GetProperty("Post").GetProperty("Hex").GetString()!);
        var original = (byte[])aclBytes.Clone();
        var acl = new A.RawAcl(aclBytes,0);
        var ace = Assert.IsType<A.CommonAce>(acl[0]);
        Assert.Equal(65444, ace.BinaryLength);
        var payload = ace.GetOpaque();
        Assert.Equal(payload, A.SddlConditionCodec.Parse(condition));
        Assert.Equal(payload, A.SddlConditionCodec.Parse(A.SddlConditionCodec.Format(payload!)));
        Assert.Equal(original, aclBytes);
        Assert.True(replay.RootElement.GetProperty("ControlEstablished").GetBoolean());
        foreach (var step in replay.RootElement.GetProperty("Steps").EnumerateArray())
            Assert.True(step.GetProperty("Success").GetBoolean());

        // Successful whole conversion permits full portable byte comparison.
        // Pin the three measured native-failure/portable-success gaps separately.
        var full = native.RootElement.GetProperty("Full");
        var portable = new A.RawSecurityDescriptor(text);
        Assert.Equal(65472 + (id%2)*20, portable.BinaryLength);
        Assert.Equal(payload, Assert.IsType<A.CommonAce>(portable.DiscretionaryAcl![0]).GetOpaque());
        if (full.GetProperty("Success").GetBoolean())
        {
            Assert.Equal(1, id%2);
            var binary = Convert.FromHexString(full.GetProperty("Hex").GetString()!);
            Assert.Equal(binary, BoundaryBytes(portable));
            Assert.Equal(binary, BoundaryBytes(new A.RawSecurityDescriptor(binary,0)));
            Assert.True(native.RootElement.GetProperty("MatchesCompiledLargeAce").GetBoolean());
        }
        else
        {
            Assert.Equal(0, id%2);
            Assert.Equal(87, full.GetProperty("LastError").GetInt32());
            Assert.Equal(JsonValueKind.Null, full.GetProperty("Hex").ValueKind);
        }
    }
}
