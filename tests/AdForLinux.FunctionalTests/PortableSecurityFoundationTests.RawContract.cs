#pragma warning disable CA1416
using System.Security.AccessControl;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> RawContractCases() => Enumerable.Range(0, 80).Select(i => new object[] { i });

    [Theory]
    [MemberData(nameof(RawContractCases))]
    public void Raw_formatting_contracts_match_native_without_weakening_retained_facade_preservation(int id)
    {
        var input = SddlRawContractContracts.Inputs().ElementAt(id);
        A.InteropSnapshot? before = null, after = null;
        byte[]? commonRaw = null, commonOriginal = null, commonLive = null;
        long generation = -1, readVersion = -1;
        var actual = JsonSerializer.SerializeToNode(SddlExportContracts.Observe(input, id,
            (p, c, original) =>
            {
                before = p.CaptureInteropSnapshot(); readVersion = p.ReadVersion;
                commonRaw = c.MutationState.Descriptor.GetBinaryForm(); commonOriginal = c.MutationState.OriginalDescriptor.GetBinaryForm();
                commonLive = A.FacadeMutation.Bytes(c); generation = c.MutationVersion;
                Assert.Equal(original, before.Raw); Assert.Equal(original, before.Original);
                Assert.Equal(original, commonRaw); Assert.Equal(original, commonOriginal);
                Assert.Equal(SecurityMasks.None, before.Pending); Assert.False(p.HasRawReadContext);
            },
            (p, c, original) =>
            {
                after = p.CaptureInteropSnapshot();
                Assert.Equal(original, after.Raw); Assert.Equal(original, after.Original);
                Assert.Equal(commonRaw, c.MutationState.Descriptor.GetBinaryForm());
                Assert.Equal(commonOriginal, c.MutationState.OriginalDescriptor.GetBinaryForm());
                Assert.Equal(commonLive, A.FacadeMutation.Bytes(c)); Assert.Equal(generation, c.MutationVersion);
                Assert.Equal(readVersion, p.ReadVersion); Assert.False(p.HasRawReadContext);
                Assert.Equal(SecurityMasks.None, c.MutationState.WriteIntent);
                Assert.Equal(SecurityMasks.None, p._securityDescriptor.MutationState.WriteIntent);
                Assert.Equal(new[] { false, false, false, false }, p.Flags());
            }))!;
        Assert.NotNull(before); Assert.NotNull(after);
        Assert.Equal(before.Observable, after.Observable); Assert.Equal(before.Generation, after.Generation);
        Assert.Equal(before.Source, after.Source); Assert.Equal(before.Attachment, after.Attachment);
        Assert.Equal(before.Retrieved, after.Retrieved); Assert.Equal(SecurityMasks.None, after.Pending);
        Assert.True(actual["CallerInputUnchanged"]!.GetValue<bool>());
        Assert.True(actual["RawObjectUnchanged"]!.GetValue<bool>());
        VerifyRawContractNative(id, actual);
    }

    private static readonly Lazy<JsonArray> RawContractNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.RawContract.net10.json.gz";
#else
        const string resource = "AclOracle.RawContract.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> RawContractRefusals = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.RawContract.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });

    [Fact]
    public void Raw_contract_inventory_requires_all_eighteen_original_compatibility_facets_to_match()
    {
        var inputs = SddlRawContractContracts.Inputs().ToArray();
        Assert.Equal(80, inputs.Length);
        Assert.Equal(Enumerable.Range(0,80), RawContractNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        foreach (var (input,row) in inputs.Zip(RawContractNative.Value))
        {
            Assert.Equal(input.Label,row!["Label"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(input.Fixture.Bytes),row["InputHex"]!.GetValue<string>());
            Assert.Equal((int)input.Sections,row["SelectedSections"]!.GetValue<int>());
        }
        var facets = 0;
        foreach (var id in new[] {162,164,167,170,172,175,203,204,207,243,244,247})
        {
            var actual = JsonSerializer.SerializeToNode(SddlExportContracts.Observe(id))!;
            var fields = id is 162 or 164 or 167 ? new[] {"RawExport","Result","CommonResult"} : new[] {"RawExport"};
            foreach (var field in fields)
            {
                Assert.True(JsonNode.DeepEquals(RetainedNative.Value[id]![field],actual[field]), $"Original facet {id}/{field}");
                Assert.DoesNotContain(RetainedDifferences.Value.Where(p => p!["Case"]!.GetValue<int>() == id)
                    .SelectMany(p => p!["Facets"]!.AsArray()), f => f!["Facet"]!.GetValue<string>() == field);
                facets++;
            }
        }
        Assert.Equal(18,facets);
        Assert.Equal(RawContractRefusals.Value.Count,RawContractRefusals.Value.Select(p => p!["Case"]!.GetValue<int>()).Distinct().Count());
    }

    private static void VerifyRawContractNative(int id, JsonNode actual)
    {
        var expected = RawContractNative.Value[id]!;
        var pin = RawContractRefusals.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            Assert.Equal(expected["Label"]!.GetValue<string>(),pin["Label"]!.GetValue<string>());
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(),
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected.ToJsonString()))).ToLowerInvariant());
            foreach (var facet in pin["Facets"]!.AsArray())
            {
                var field = facet!["Facet"]!.GetValue<string>();
                Assert.Contains(field,new[] {"RawExport","CommonResult","Result"});
                Assert.Null(expected[field]!["ExceptionType"]);
                Assert.Equal(facet["PortableExceptionType"]!.GetValue<string>(),actual[field]!["ExceptionType"]?.GetValue<string>());
                Assert.Null(actual[field]!["Outcome"]); Assert.Null(actual[field]!["ParamName"]); Assert.Null(actual[field]!["NativeErrorCode"]);
                var output = expected[field]!["Outcome"]!;
                var classification = facet["Classification"]!.GetValue<string>();
                if (classification == "nonroundtrippable-alarm")
                {
                    Assert.Equal("RawExport",field);
                    Assert.Equal("System.ArgumentException",output["Reparse"]!["ExceptionType"]!.GetValue<string>());
                    Assert.Equal("sddlForm",output["Reparse"]!["ParamName"]!.GetValue<string>());
                }
                else
                {
                    Assert.Equal("retained-byte-loss",classification);
                    Assert.Null(output["Reparse"]!["ExceptionType"]);
                    var input = SddlRawContractContracts.Inputs().ElementAt(id);
                    var original = new A.RawSecurityDescriptor(input.Fixture.Bytes,0);
                    var parsed = new A.RawSecurityDescriptor(Convert.FromHexString(output["Reparse"]!["Outcome"]!["Hex"]!.GetValue<string>()),0);
                    var source = input.Fixture.Dacl ? original.DiscretionaryAcl! : original.SystemAcl!;
                    var target = input.Fixture.Dacl ? parsed.DiscretionaryAcl! : parsed.SystemAcl!;
                    Assert.Contains(source.Cast<A.GenericAce>(), ace => !target.Cast<A.GenericAce>().Any(p => Image(p).AsSpan().SequenceEqual(Image(ace))));
                }
                actual[field] = expected[field]!.DeepClone(); // Only this exact, individually hashed refusal facet differs.
            }
        }
        Assert.True(JsonNode.DeepEquals(expected,actual), $"Raw contract mismatch: {id}");
        static byte[] Image(A.GenericAce ace) { var bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes,0); return bytes; }
    }
}
