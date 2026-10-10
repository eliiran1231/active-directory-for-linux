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
    public static IEnumerable<object[]> CallbackCompositionCases() => Enumerable.Range(0, 48).Select(i => new object[] { i });

    [Theory]
    [MemberData(nameof(CallbackCompositionCases))]
    public void Callback_composition_preserves_empty_callback_identity_or_refuses_without_mutation(int id)
    {
        var input = SddlCompositionContracts.Inputs().ElementAt(id);
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
        var source = new A.RawSecurityDescriptor(input.Fixture.Bytes, 0);
        var sourceAcl = input.Fixture.Dacl ? source.DiscretionaryAcl! : source.SystemAcl!;
        var callback = Assert.IsAssignableFrom<A.QualifiedAce>(sourceAcl[sourceAcl.Count - 1]);
        Assert.True(callback.IsCallback);
        var empty = input.Fixture.Family == "composition-empty-callback";
        Assert.Equal(empty, callback.OpaqueLength == 0);
        var selected = input.Operation != "export-unselected";
        var supported = (int)callback.AceType is 9 or 10 or 11 or 13;
        var expectedException = !selected || !empty ? null : supported ? "System.NotSupportedException" : "System.InvalidOperationException";
        foreach (var field in new[] { "RawExport", "CommonResult", "Result" })
        {
            Assert.Equal(expectedException, actual[field]!["ExceptionType"]?.GetValue<string>());
            if (expectedException is not null) Assert.Null(actual[field]!["Outcome"]);
            else Assert.Null(actual[field]!["Outcome"]!["Reparse"]!["ExceptionType"]);
        }
        VerifyCallbackCompositionNative(id, actual);
    }

    private static readonly Lazy<JsonArray> CallbackNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Composition.net10.json.gz";
#else
        const string resource = "AclOracle.Composition.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> CallbackRefusals = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Composition.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });

    [Fact]
    public void Callback_composition_inventory_keeps_legacy_formatting_success_separate_from_reparse_failure()
    {
        var inputs = SddlCompositionContracts.Inputs().ToArray();
        Assert.Equal(48, inputs.Length);
        Assert.Equal(Enumerable.Range(0, inputs.Length), CallbackNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        foreach (var (input, row) in inputs.Zip(CallbackNative.Value))
        {
            Assert.Equal(input.Label, row!["Label"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(input.Fixture.Bytes), row["InputHex"]!.GetValue<string>());
            Assert.Equal((int)input.Sections, row["SelectedSections"]!.GetValue<int>());
        }
        Assert.Equal(21, CallbackRefusals.Value.Count);
        var facets = CallbackRefusals.Value.SelectMany(p => p!["Facets"]!.AsArray()).ToArray();
        Assert.Equal(51, facets.Count(f => f!["Classification"]!.GetValue<string>() == "nonroundtrippable-empty-callback"));
        Assert.Equal(8, facets.Count(f => f!["Classification"]!.GetValue<string>() == "existing-retained-alarm-omission"));
        foreach (var (legacyId, currentId) in new[] { (857, 45), (858, 46), (859, 47) })
        {
            var legacy = JsonNode.Parse((string)ClosureRecordings().Single(r => (int)r[0] == legacyId)[2])!;
            var current = CallbackNative.Value[currentId]!;
            Assert.Equal(legacy["Arguments"]!["Hex"]!.GetValue<string>(), current["InputHex"]!.GetValue<string>());
            Assert.Null(legacy["ExceptionType"]); Assert.Null(current["RawExport"]!["ExceptionType"]);
            Assert.Equal(legacy["Outcome"]!.GetValue<string>(), A.SddlUtf16.Decode(Convert.FromHexString(current["RawExport"]!["Outcome"]!["Utf16Hex"]!.GetValue<string>())));
            Assert.Equal("System.ArgumentException", current["RawExport"]!["Outcome"]!["Reparse"]!["ExceptionType"]!.GetValue<string>());
        }
    }

    private static void VerifyCallbackCompositionNative(int id, JsonNode actual)
    {
        var expected = CallbackNative.Value[id]!;
        var pin = CallbackRefusals.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            Assert.Equal(expected["Label"]!.GetValue<string>(), pin["Label"]!.GetValue<string>());
            var canonical = expected.ToJsonString();
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(), Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant());
            foreach (var facet in pin["Facets"]!.AsArray())
            {
                var field = facet!["Facet"]!.GetValue<string>();
                Assert.Contains(field, new[] { "RawExport", "CommonResult", "Result" });
                Assert.Null(expected[field]!["ExceptionType"]); // Formatting success remains recorded verbatim.
                Assert.Equal(facet["PortableExceptionType"]!.GetValue<string>(), actual[field]!["ExceptionType"]?.GetValue<string>());
                Assert.Null(actual[field]!["Outcome"]); Assert.Null(actual[field]!["ParamName"]); Assert.Null(actual[field]!["NativeErrorCode"]);
                var output = expected[field]!["Outcome"]!;
                if (facet["Classification"]!.GetValue<string>() == "nonroundtrippable-empty-callback")
                {
                    Assert.Equal("System.ArgumentException", output["Reparse"]!["ExceptionType"]!.GetValue<string>());
                    Assert.Equal("sddlForm", output["Reparse"]!["ParamName"]!.GetValue<string>());
                    Assert.Null(output["Reparse"]!["Outcome"]); Assert.Null(output["Reparse"]!["NativeErrorCode"]);
                    var text = A.SddlUtf16.Decode(Convert.FromHexString(output["Utf16Hex"]!.GetValue<string>()));
                    Assert.Equal("sddlForm", Assert.Throws<ArgumentException>(() => new A.RawSecurityDescriptor(text)).ParamName);
                }
                else
                {
                    Assert.Equal("existing-retained-alarm-omission", facet["Classification"]!.GetValue<string>());
                    Assert.Contains(field, new[] { "CommonResult", "Result" });
                    Assert.Null(output["Reparse"]!["ExceptionType"]);
                    var input = SddlCompositionContracts.Inputs().ElementAt(id);
                    var original = new A.RawSecurityDescriptor(input.Fixture.Bytes, 0);
                    var parsed = new A.RawSecurityDescriptor(Convert.FromHexString(output["Reparse"]!["Outcome"]!["Hex"]!.GetValue<string>()), 0);
                    var lostType = original.SystemAcl![original.SystemAcl.Count - 1].AceType;
                    Assert.Contains((int)lostType, new[] { 14, 16 });
                    Assert.DoesNotContain(parsed.SystemAcl!.Cast<A.GenericAce>(), ace => ace.AceType == lostType);
                }
                actual[field] = expected[field]!.DeepClone();
            }
        }
        Assert.True(JsonNode.DeepEquals(expected, actual), $"Callback composition mismatch: {id}");
    }
}
