#pragma warning disable CA1416
using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.AccessControl;
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
    public static IEnumerable<object[]> RetainedExportCases() => Enumerable.Range(0, 296).Select(i => new object[] { i });

    [Fact]
    public void Retained_export_minimal_label_cannot_disappear_through_common_projection()
    {
        const string text = "S:(ML;;NW;;;LW)";
        var raw = new A.RawSecurityDescriptor(text);
        var common = new A.CommonSecurityDescriptor(true, true, text);
        var before = common.MutationState.Descriptor.GetBinaryForm();
        Assert.Throws<NotSupportedException>(() => raw.GetSddlForm(AccessControlSections.Audit));
        Assert.Throws<NotSupportedException>(() => common.GetSddlForm(AccessControlSections.Audit));
        Assert.Equal(before, common.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, common.MutationState.WriteIntent);
    }

    [Theory]
    [MemberData(nameof(RetainedExportCases))]
    public void Retained_export_refusal_families_preserve_raw_and_pending_state_without_blocking_reviewed_normalization(int id)
    {
        var input = SddlExportInputs.Create().ElementAt(id);
        A.InteropSnapshot? before = null, after = null;
        byte[]? commonRaw = null, commonOriginal = null, commonObservable = null;
        long commonVersion = -1, readVersion = -1;
        SecurityMasks commonIntent = 0, intent = 0;
        bool[]? flags = null;
        var actual = JsonSerializer.SerializeToNode(SddlExportContracts.Observe(id,
            (p, c, original) =>
            {
                before = p.CaptureInteropSnapshot(); flags = p.Flags();
                readVersion = p.ReadVersion; intent = p._securityDescriptor.MutationState.WriteIntent;
                commonRaw = c.MutationState.Descriptor.GetBinaryForm();
                commonOriginal = c.MutationState.OriginalDescriptor.GetBinaryForm();
                commonObservable = A.FacadeMutation.Bytes(c);
                commonVersion = c.MutationVersion; commonIntent = c.MutationState.WriteIntent;
                var expected = (byte[])original.Clone();
                if (input.Operation == "owner-then-export") ReplaceIdentity(expected, true);
                Assert.Equal(expected, before.Raw); Assert.Equal(expected, commonRaw);
                Assert.Equal(original, before.Original); Assert.Equal(original, commonOriginal);
                var prior = input.Operation == "owner-then-export" ? SecurityMasks.Owner : SecurityMasks.None;
                Assert.Equal(prior, before.Pending); Assert.Equal(prior, intent); Assert.Equal(prior, commonIntent);
                Assert.False(p.HasRawReadContext);
            },
            (p, c, original) =>
            {
                after = p.CaptureInteropSnapshot();
                Assert.Equal(original, after.Original);
                Assert.Equal(commonOriginal, c.MutationState.OriginalDescriptor.GetBinaryForm());
                Assert.Equal(readVersion, p.ReadVersion); Assert.False(p.HasRawReadContext);
                var edit = input.Operation is "edit-owner" or "edit-group";
                var expected = before!.Raw;
                if (edit) ReplaceIdentity(expected, input.Operation == "edit-owner");
                Assert.Equal(expected, after.Raw); Assert.Equal(expected, c.MutationState.Descriptor.GetBinaryForm());
                if (edit)
                {
                    var owner = input.Operation == "edit-owner";
                    var section = owner ? SecurityMasks.Owner : SecurityMasks.Group;
                    Assert.Equal(section, after.Pending);
                    Assert.Equal(section, p._securityDescriptor.MutationState.WriteIntent);
                    Assert.Equal(section, c.MutationState.WriteIntent);
                    Assert.Equal(new[] { owner, !owner, false, false }, p.Flags());
                    Assert.True(after.Generation > before.Generation); Assert.True(c.MutationVersion > commonVersion);
                }
                else
                {
                    Assert.Equal(before.Observable, after.Observable); Assert.Equal(commonObservable, A.FacadeMutation.Bytes(c));
                    Assert.Equal(before.Pending, after.Pending); Assert.Equal(intent, p._securityDescriptor.MutationState.WriteIntent);
                    Assert.Equal(commonIntent, c.MutationState.WriteIntent); Assert.Equal(flags, p.Flags());
                    Assert.Equal(before.Generation, after.Generation); Assert.Equal(commonVersion, c.MutationVersion);
                }
            }))!;
        Assert.NotNull(before); Assert.NotNull(after);
        Assert.Equal(before.Source, after.Source); Assert.Equal(before.Attachment, after.Attachment);
        Assert.Equal((SecurityMasks)15, before.Retrieved); Assert.Equal(before.Retrieved, after.Retrieved);
        var editing = input.Operation is "edit-owner" or "edit-group";
        var selectsFixture = (input.Sections & (input.Fixture.Dacl ? AccessControlSections.Access : AccessControlSections.Audit)) != 0;
        var family = input.Fixture.Family;
        string? expectedException = !selectsFixture || editing || (family.StartsWith("reviewed-", StringComparison.Ordinal) || family == "retained-opaque-control") ? null
            : family is "wrong-section-special-ace" or "no-sddl-token-layout" or "missing-audit-flags"
                ? "System.InvalidOperationException" : "System.NotSupportedException";
        foreach (var field in new[] { "Result", "CommonResult" })
        {
            Assert.Equal(expectedException, actual[field]!["ExceptionType"]?.GetValue<string>());
            if (expectedException is not null)
            { Assert.Null(actual[field]!["Outcome"]); Assert.Null(actual[field]!["ParamName"]); Assert.Null(actual[field]!["NativeErrorCode"]); }
        }
        if (!editing)
        {
            var expectedRaw = family == "projected-opaque-contributor" ? null
                : selectsFixture && input.Fixture.Name == "inactive-audit" ? "System.InvalidOperationException" : expectedException;
            Assert.Equal(expectedRaw, actual["RawExport"]!["ExceptionType"]?.GetValue<string>());
        }
        Assert.True(actual["CallerInputUnchanged"]!.GetValue<bool>());
        Assert.True(actual["RawObjectUnchanged"]!.GetValue<bool>());
        VerifyRetainedNative(id, actual);

        static void ReplaceIdentity(byte[] bytes, bool owner)
        {
            var sid = new AdForLinux.Security.Principal.SecurityIdentifier(owner ? "S-1-5-19" : "S-1-5-32-545");
            var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(owner ? 4 : 8));
            Assert.Equal(8 + bytes[offset + 1] * 4, sid.BinaryLength); sid.GetBinaryForm(bytes, offset);
        }
    }

    private static readonly Lazy<JsonArray> RetainedNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.RetainedExport.net10.json.gz";
#else
        const string resource = "AclOracle.RetainedExport.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> RetainedDifferences = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.RetainedExport.Differences.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });

    [Fact]
    public void Retained_export_inventory_includes_every_input_and_classifies_each_differing_facet()
    {
        var inputs = SddlExportInputs.Create().ToArray();
        Assert.Equal(296, inputs.Length);
        Assert.Equal(Enumerable.Range(0, inputs.Length), RetainedNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        for (var id = 0; id < inputs.Length; id++)
        {
            var input = inputs[id]; var row = RetainedNative.Value[id]!;
            Assert.Equal(input.Label, row["Label"]!.GetValue<string>());
            Assert.Equal(input.Fixture.Family, row["Family"]!.GetValue<string>());
            Assert.Equal((int)input.Sections, row["SelectedSections"]!.GetValue<int>());
            Assert.Equal(input.Fixture.Text is null ? Convert.ToHexString(input.Fixture.Bytes) : null, row["InputHex"]?.GetValue<string>());
            Assert.Equal(input.Fixture.Text is null ? null : SddlBoundaryInputs.Utf16Hex(input.Fixture.Text), row["InputUtf16Hex"]?.GetValue<string>());
        }
        Assert.Equal(78, RetainedDifferences.Value.Count);
        Assert.Equal(78, RetainedDifferences.Value.Select(p => p!["Case"]!.GetValue<int>()).Distinct().Count());
        var facets = RetainedDifferences.Value.SelectMany(p => p!["Facets"]!.AsArray()).ToArray();
        Assert.Equal(171, facets.Count(p => p!["Classification"]!.GetValue<string>() == "retained-content-loss-refusal"));
        Assert.Equal(27, facets.Count(p => p!["Classification"]!.GetValue<string>() == "native-nonroundtrippable-export-refusal"));
        Assert.Equal(12, facets.Count(p => p!["Classification"]!.GetValue<string>() == "exception-contract-difference"));
        Assert.Equal(6, facets.Count(p => p!["Classification"]!.GetValue<string>() == "existing-raw-validation-difference"));
    }

    private static void VerifyRetainedNative(int id, JsonNode actual)
    {
        var expected = RetainedNative.Value[id]!;
        var input = SddlExportInputs.Create().ElementAt(id);
        var pin = RetainedDifferences.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            Assert.Equal(input.Label, pin["Label"]!.GetValue<string>());
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(),
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected.ToJsonString()))).ToLowerInvariant());
            foreach (var facet in pin["Facets"]!.AsArray())
            {
                var field = facet!["Facet"]!.GetValue<string>();
                Assert.Contains(field, new[] { "RawExport", "Result", "CommonResult" });
                Assert.Equal(facet["PortableExceptionType"]!.GetValue<string>(), actual[field]!["ExceptionType"]?.GetValue<string>());
                Assert.Null(actual[field]!["Outcome"]); Assert.Null(actual[field]!["ParamName"]); Assert.Null(actual[field]!["NativeErrorCode"]);
                Assert.Equal(facet["NativeExceptionType"]?.GetValue<string>(), expected[field]!["ExceptionType"]?.GetValue<string>());
                var classification = facet["Classification"]!.GetValue<string>();
                if (classification == "exception-contract-difference")
                {
                    // Existing unsupported-condition exception mapping is a compatibility
                    // difference, not a successful parity or native-loss observation.
                    Assert.Equal("unrepresentable-condition", input.Fixture.Family);
                    Assert.Equal("System.InvalidOperationException", expected[field]!["ExceptionType"]!.GetValue<string>());
                }
                else if (classification == "native-nonroundtrippable-export-refusal")
                {
                    Assert.Equal("non-audit-ace-audit-flags", input.Fixture.Family);
                    Assert.Null(expected[field]!["ExceptionType"]);
                    var exported = expected[field]!["Outcome"]!;
                    Assert.Equal("System.ArgumentException", exported["Reparse"]!["ExceptionType"]!.GetValue<string>());
                    Assert.Equal("sddlForm", exported["Reparse"]!["ParamName"]!.GetValue<string>());
                    var source = new A.RawSecurityDescriptor(Convert.FromHexString(expected["OriginalRaw"]!["Outcome"]!["Hex"]!.GetValue<string>()), 0);
                    var contributor = source.DiscretionaryAcl![source.DiscretionaryAcl.Count - 1];
                    Assert.Equal(AceFlags.SuccessfulAccess, contributor.AceFlags);
                    var token = (int)contributor.AceType switch { 9 => "XA", 10 => "XD", 11 => "ZA", _ => throw new InvalidOperationException() };
                    var text = A.SddlUtf16.Decode(Convert.FromHexString(exported["Utf16Hex"]!.GetValue<string>()));
                    // Native output strips SA and emits a callback without a condition;
                    // the actual native reparse above fails. Neither is safe export.
                    Assert.Contains("(" + token + ";;", text);
                }
                else
                {
                    Assert.Null(expected[field]!["ExceptionType"]);
                    Assert.Null(expected[field]!["Outcome"]!["Reparse"]!["ExceptionType"]);
                    var original = new A.RawSecurityDescriptor(Convert.FromHexString(expected["OriginalRaw"]!["Outcome"]!["Hex"]!.GetValue<string>()), 0);
                    var reparse = new A.RawSecurityDescriptor(Convert.FromHexString(expected[field]!["Outcome"]!["Reparse"]!["Outcome"]!["Hex"]!.GetValue<string>()), 0);
                    var sourceAcl = input.Fixture.Dacl ? original.DiscretionaryAcl! : original.SystemAcl!;
                    var exportedAcl = input.Fixture.Dacl ? reparse.DiscretionaryAcl! : reparse.SystemAcl!;
                    if (classification == "existing-raw-validation-difference")
                    {
                        // Native raw export retains these ordinary unaudited ACEs. Do
                        // not mislabel the pre-existing strict raw validation as loss.
                        Assert.Equal("RawExport", field);
                        Assert.Contains(input.Fixture.Name, new[] { "inactive-audit", "unaudited-active" });
                        Assert.Equal(sourceAcl.Count, exportedAcl.Count);
                        for (var i = 0; i < sourceAcl.Count; i++) Assert.Equal(AceBytes(sourceAcl[i]), AceBytes(exportedAcl[i]));
                    }
                    else
                    {
                        Assert.Equal("retained-content-loss-refusal", classification);
                        var contributor = AceBytes(sourceAcl[sourceAcl.Count - 1]);
                        Assert.DoesNotContain(exportedAcl.Cast<A.GenericAce>(), ace => AceBytes(ace).AsSpan().SequenceEqual(contributor));
                    }
                }
                actual[field] = expected[field]!.DeepClone(); // Only this exact, hashed facet may differ.
            }
        }
        Assert.True(JsonNode.DeepEquals(expected, actual), $"Native retained-export mismatch: {input.Label}");

        static byte[] AceBytes(A.GenericAce ace)
        { var bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); return bytes; }
    }
}
