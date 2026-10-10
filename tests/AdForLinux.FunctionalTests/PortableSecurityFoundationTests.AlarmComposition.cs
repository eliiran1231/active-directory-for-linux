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
    public static IEnumerable<object[]> AlarmCases() => Enumerable.Range(0, 96).Select(i => new object[] { i });

    [Theory]
    [MemberData(nameof(AlarmCases))]
    public void Alarm_export_composition_preserves_raw_state_and_separates_native_formatting_from_reparse(int id)
    {
        var input = SddlAlarmContracts.Inputs().ElementAt(id);
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
        VerifyAlarmNative(id,actual);
    }

    private static readonly Lazy<JsonArray> AlarmNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Alarm.net10.json.gz";
#else
        const string resource = "AclOracle.Alarm.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream,CompressionMode.Decompress);
        return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> AlarmRefusals = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Alarm.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });

    [Fact]
    public void Alarm_inventory_covers_audit_flags_sections_layouts_and_exact_legacy_parse_strings()
    {
        var inputs = SddlAlarmContracts.Inputs().ToArray();
        Assert.Equal(96,inputs.Length);
        Assert.Equal(Enumerable.Range(0,96),AlarmNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        foreach (var (input,row) in inputs.Zip(AlarmNative.Value))
        {
            Assert.Equal(input.Label,row!["Label"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(input.Fixture.Bytes),row["InputHex"]!.GetValue<string>());
            Assert.Equal((int)input.Sections,row["SelectedSections"]!.GetValue<int>());
        }
        foreach (var (legacyId,id) in new[] {(937,92),(987,94)})
        {
            var legacy = JsonNode.Parse((string)ClosureRecordings().Single(r => (int)r[0] == legacyId)[2])!;
            var output = AlarmNative.Value[id]!["RawExport"]!;
            Assert.Null(output["ExceptionType"]); // Actual formatting succeeds; the defect is composition.
            Assert.Equal(legacy["Arguments"]!["Text"]!.GetValue<string>(),
                A.SddlUtf16.Decode(Convert.FromHexString(output["Outcome"]!["Utf16Hex"]!.GetValue<string>())));
            Assert.Equal(legacy["ExceptionType"]!.GetValue<string>(),output["Outcome"]!["Reparse"]!["ExceptionType"]!.GetValue<string>());
            Assert.Equal(legacy["ParamName"]!.GetValue<string>(),output["Outcome"]!["Reparse"]!["ParamName"]!.GetValue<string>());
        }
        Assert.Equal(44,AlarmRefusals.Value.Count);
        var facets = AlarmRefusals.Value.SelectMany(p => p!["Facets"]!.AsArray()).ToArray();
        Assert.Equal(21,facets.Count(f => f!["Classification"]!.GetValue<string>() == "native-alarm-nonroundtrippable-text"));
        Assert.Equal(88,facets.Count(f => f!["Classification"]!.GetValue<string>() == "existing-facade-alarm-omission"));
        Assert.Equal(AlarmRefusals.Value.Count,AlarmRefusals.Value.Select(p => p!["Case"]!.GetValue<int>()).Distinct().Count());
    }

    private static void VerifyAlarmNative(int id,JsonNode actual)
    {
        var expected = AlarmNative.Value[id]!;
        var pin = AlarmRefusals.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
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
                if (facet["Classification"]!.GetValue<string>() == "native-alarm-nonroundtrippable-text")
                {
                    Assert.Equal("RawExport",field);
                    Assert.Equal("System.ArgumentException",output["Reparse"]!["ExceptionType"]!.GetValue<string>());
                    Assert.Equal("sddlForm",output["Reparse"]!["ParamName"]!.GetValue<string>());
                    var text = A.SddlUtf16.Decode(Convert.FromHexString(output["Utf16Hex"]!.GetValue<string>()));
                    Assert.Equal("sddlForm",Assert.Throws<ArgumentException>(() => new A.RawSecurityDescriptor(text)).ParamName);
                }
                else
                {
                    Assert.Equal("existing-facade-alarm-omission",facet["Classification"]!.GetValue<string>());
                    Assert.Contains(field,new[] {"CommonResult","Result"});
                    Assert.Null(output["Reparse"]!["ExceptionType"]);
                    var input = SddlAlarmContracts.Inputs().ElementAt(id);
                    var original = new A.RawSecurityDescriptor(input.Fixture.Bytes,0);
                    var parsed = new A.RawSecurityDescriptor(Convert.FromHexString(output["Reparse"]!["Outcome"]!["Hex"]!.GetValue<string>()),0);
                    Assert.Contains(original.SystemAcl!.Cast<A.GenericAce>(),ace => (int)ace.AceType is 3 or 8 or 14 or 16);
                    Assert.DoesNotContain(parsed.SystemAcl!.Cast<A.GenericAce>(),ace => (int)ace.AceType is 3 or 8 or 14 or 16);
                }
                actual[field] = expected[field]!.DeepClone(); // Pin only this complete native export facet, never the whole row.
            }
        }
        Assert.True(JsonNode.DeepEquals(expected,actual), $"Alarm composition mismatch: {id}");
    }
}
