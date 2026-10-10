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
    public static IEnumerable<object[]> MixedRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Mixed.net10.json.gz";
#else
        const string resource = "AclOracle.Mixed.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        using var document = JsonDocument.Parse(gzip);
        foreach (var row in document.RootElement.GetProperty("Observations").EnumerateArray())
            yield return new object[] { row.GetProperty("Case").GetInt32(), row.GetRawText() };
    }

    private static JsonArray MixedRefusals()
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Mixed.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    }

    [Fact]
    public void Mixed_operation_inventory_pins_every_input_and_only_four_loss_refusals()
    {
        var rows = MixedRecordings().ToArray();
        var inputs = SddlMixedInputs.Create().ToArray();
        Assert.Equal(64, inputs.Length);
        Assert.Equal(Enumerable.Range(0, 64), rows.Select(r => (int)r[0]));
        foreach (var row in rows)
        {
            var input = inputs[(int)row[0]];
            var native = JsonNode.Parse((string)row[1])!;
            Assert.InRange(input.Text.Length, 1, 2048);
            Assert.Equal(input.Label, native["Label"]!.GetValue<string>());
            Assert.Equal(SddlBoundaryInputs.Utf16Hex(input.Text), native["InputUtf16Hex"]!.GetValue<string>());
            Assert.Equal((int)input.Sections, native["SelectedSections"]!.GetValue<int>());
            Assert.Equal(input.Edit is null ? null : SddlBoundaryInputs.Utf16Hex(input.Edit), native["EditUtf16Hex"]?.GetValue<string>());
        }
        Assert.Equal(new[] { 51, 52, 59, 60 }, MixedRefusals().Select(p => p!["Case"]!.GetValue<int>()));
    }

    [Theory]
    [MemberData(nameof(MixedRecordings))]
    public void Mixed_operations_match_native_or_exact_pinned_loss_refusal_and_preserve_raw_state(int id, string json)
    {
        var input = SddlMixedInputs.Create().ElementAt(id);
        A.InteropSnapshot? before = null, after = null;
        var intentBefore = SecurityMasks.None; var intentAfter = SecurityMasks.None;
        long readVersion = -1;
        var actual = JsonSerializer.SerializeToNode(SddlMixedContracts.Observe(id,
            (p, original) =>
            {
                before = p.CaptureInteropSnapshot();
                intentBefore = p._securityDescriptor.MutationState.WriteIntent;
                readVersion = p.ReadVersion;
                Assert.Equal(original, before.Raw);
                Assert.Equal(original, before.Original);
                Assert.Equal(SecurityMasks.None, before.Pending);
                Assert.Equal(SecurityMasks.None, intentBefore);
                Assert.Equal(new[] { false, false, false, false }, p.Flags());
                Assert.False(p.HasRawReadContext); // Detached import grants no server read context.
            },
            (p, original) =>
            {
                after = p.CaptureInteropSnapshot();
                intentAfter = p._securityDescriptor.MutationState.WriteIntent;
                Assert.Equal(original, after.Original);
                Assert.Equal(readVersion, p.ReadVersion);
                Assert.False(p.HasRawReadContext); // Detached import grants no server read context.
            }))!;
        var expected = JsonNode.Parse(json)!;
        Assert.NotNull(before); Assert.NotNull(after);
        Assert.Equal(before.Source, after.Source);
        Assert.Equal(before.Attachment, after.Attachment);
        Assert.Equal(before.Retrieved, after.Retrieved);
        Assert.Equal((SecurityMasks)15, after.Retrieved);
        Assert.Equal(before.IsContainer, after.IsContainer);
        Assert.Equal(before.IsDirectory, after.IsDirectory);
        if (input.Operation is "edit-owner" or "edit-group")
        {
            var owner = input.Operation == "edit-owner";
            var sid = new AdForLinux.Security.Principal.SecurityIdentifier(owner ? "S-1-5-19" : "S-1-5-32-545");
            var bytes = before.Raw;
            var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(owner ? 4 : 8));
            Assert.Equal(8 + bytes[offset + 1] * 4, sid.BinaryLength);
            sid.GetBinaryForm(bytes, offset);
            Assert.Equal(bytes, after.Raw); // Every other byte, including raw ACL payloads/order, survives.
            var section = owner ? SecurityMasks.Owner : SecurityMasks.Group;
            Assert.Equal(section, after.Pending); Assert.Equal(section, intentAfter);
            Assert.True(after.Generation > before.Generation);
        }
        else
        {
            Assert.Equal(before.Raw, after.Raw);
            Assert.Equal(before.Observable, after.Observable);
            Assert.Equal(before.Pending, after.Pending);
            Assert.Equal(intentBefore, intentAfter);
            Assert.Equal(before.Generation, after.Generation);
        }

        var pin = MixedRefusals().SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            Assert.Equal(input.Label, pin["Label"]!.GetValue<string>());
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(),
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant());
            Assert.Null(expected["Result"]!["ExceptionType"]);
            Assert.Equal("System.NotSupportedException", actual["Result"]!["ExceptionType"]?.GetValue<string>());
            Assert.Null(actual["Result"]!["Outcome"]);
            Assert.Null(actual["Result"]!["ParamName"]);
            Assert.Null(actual["Result"]!["NativeErrorCode"]);
            // Prove the exact native omission, not merely a textual difference.
            var raw = new A.RawSecurityDescriptor(before.Raw, 0);
            var exported = expected["Result"]!["Outcome"]!["Reparse"]!["Outcome"]!["Hex"]!.GetValue<string>();
            var reparsed = new A.RawSecurityDescriptor(Convert.FromHexString(exported), 0);
            var omittedType = input.Fixture == "RA" ? 18 : 21;
            Assert.Contains(raw.SystemAcl!.Cast<A.GenericAce>(), a => (int)a.AceType == omittedType);
            Assert.DoesNotContain(reparsed.SystemAcl!.Cast<A.GenericAce>(), a => (int)a.AceType == omittedType);
            actual["Result"] = expected["Result"]!.DeepClone(); // Only this individually pinned facet differs.
        }
        Assert.True(JsonNode.DeepEquals(expected, actual), $"Mixed native mismatch: {input.Label}");
        Assert.True(actual["CallerInputUnchanged"]!.GetValue<bool>());
        Assert.True(actual["RawObjectUnchanged"]!.GetValue<bool>());
    }
}
