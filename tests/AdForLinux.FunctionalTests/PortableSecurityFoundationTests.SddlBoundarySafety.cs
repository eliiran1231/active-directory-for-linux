#pragma warning disable CA1416 // Numeric framework enums; all descriptor operations are portable.
using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Text.Json;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Boundary_probe_inputs_keep_exact_utf16_units_and_stable_unique_cases()
    {
        // This checks evidence transport, not any unmeasured Windows acceptance rule.
        var samples = new[] { ("\0", "0000"), ("A\ud800B", "410000D84200"),
            ("\udc00\ud800", "00DC00D8"), ("\ud83d\ude00", "3DD800DE"), ("%0000", "25003000300030003000") };
        foreach (var (text, expected) in samples) Assert.Equal(expected, SddlBoundaryInputs.Utf16Hex(text));
        var inputs = SddlBoundaryInputs.Create().ToArray();
        Assert.Equal(220, inputs.Length);
        Assert.Equal(inputs.Length, inputs.Select(x => x.Label).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(new[] { "FL", "RA", "XA" }, inputs.Select(x => x.Family).Distinct().Order());
        foreach (var input in inputs)
        {
            // Hex survives JSON roundtrip even when normal text encoding could replace
            // a lone surrogate or treat a literal NUL as termination.
            var json = JsonSerializer.Serialize(new { Input = SddlBoundaryInputs.Utf16Hex(input.Text) });
            using var document = JsonDocument.Parse(json);
            var bytes = Convert.FromHexString(document.RootElement.GetProperty("Input").GetString()!);
            var chars = new char[bytes.Length / 2];
            for (var i = 0; i < chars.Length; i++) chars[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i * 2));
            Assert.Equal(input.Text, new string(chars));
        }
    }

    [Theory]
    [InlineData("4100", false)]
    [InlineData("3DD800DE", false)]
    [InlineData("0000", false)]
    [InlineData("00D8", false)]
    [InlineData("00DC", false)]
    [InlineData("00DC00D8", false)]
    [InlineData("41", false)]
    [InlineData("4100", true)]
    public void Conditional_binary_unicode_exports_exact_payload_or_refuses_without_mutation(string literalHex, bool invalidLength)
    {
        var literal = Convert.FromHexString(literalHex);
        using var stream = new MemoryStream(); stream.Write("artx"u8);
        // @User.A == <raw UTF-16 string>. No production text parser constructs the input.
        stream.Write(new byte[] { 0xf9, 2, 0, 0, 0, 0x41, 0, 0x10 });
        var size = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(size, invalidLength ? int.MaxValue : literal.Length);
        stream.Write(size); stream.Write(literal); stream.WriteByte(0x80);
        while (stream.Length % 4 != 0) stream.WriteByte(0);
        var payload = stream.ToArray();
        var acl = new A.RawAcl(2, 1);
        acl.InsertAce(0, new A.CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 16, new P.SecurityIdentifier("S-1-1-0"), true, payload));
        var raw = new A.RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, acl);
        var before = AccessFilterImage(raw);
        string? result = null;
        var error = Record.Exception(() => result = raw.GetSddlForm(AccessControlSections.All));
        if (error is null)
        {
            var parsed = new A.RawSecurityDescriptor(result!);
            Assert.Equal(payload, ((A.QualifiedAce)parsed.DiscretionaryAcl![0]).GetOpaque());
        }
        else if (invalidLength) Assert.IsType<InvalidOperationException>(error);
        else Assert.IsType<NotSupportedException>(error);
        Assert.Equal(before, AccessFilterImage(raw));
        Assert.Equal(before, AccessFilterImage(new A.RawSecurityDescriptor(before, 0)));
    }

    [Theory]
    [InlineData(18, 0)] [InlineData(21, 0)]
    [InlineData(18, 4)] [InlineData(21, 4)]
    [InlineData(18, 4096)] [InlineData(21, 4096)]
    [InlineData(18, 65520)] [InlineData(21, 65520)]
    public void Binary_resource_and_filter_storage_survives_loss_refusal_at_large_sizes(int type, int length)
    {
        // Arbitrary payload bytes, not a claim that Windows accepts this as SDDL.
        // 65,520 keeps the complete custom ACE and ACL inside their binary size limit.
        var payload = Enumerable.Range(0, length).Select(i => (byte)(i % 256)).ToArray();
        var acl = new A.RawAcl(2, 1); acl.InsertAce(0, new A.CustomAce((AceType)type, AceFlags.None, payload));
        var raw = new A.RawSecurityDescriptor(ControlFlags.SystemAclPresent, new P.SecurityIdentifier("S-1-5-18"), null, acl, null);
        var before = AccessFilterImage(raw);
        var supplied = (byte[])before.Clone(); var copy = new A.RawSecurityDescriptor(supplied, 0);
        Array.Fill(supplied, (byte)0xff);
        Assert.Throws<NotSupportedException>(() => copy.GetSddlForm(AccessControlSections.All));
        Assert.Equal("O:SY", copy.GetSddlForm(AccessControlSections.Owner));
        Assert.Equal(before, AccessFilterImage(copy));
        Assert.Equal(before, AccessFilterImage(raw));
    }

    [Theory]
    [InlineData(2369)] [InlineData(2402)] [InlineData(2418)]
    [InlineData(2540)] [InlineData(3012)] [InlineData(3076)]
    public void Already_recorded_unicode_and_escaped_nul_inputs_keep_native_bytes_across_copies(int caseId)
    {
        var recording = ClosureRecordings().Single(row => (int)row[0] == caseId);
        using var document = JsonDocument.Parse((string)recording[2]);
        var row = document.RootElement;
        Assert.Equal("SddlParse", row.GetProperty("Operation").GetString());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("ExceptionType").ValueKind);
        var raw = new A.RawSecurityDescriptor(row.GetProperty("Arguments").GetProperty("Text").GetString()!);
        var expected = Convert.FromHexString(row.GetProperty("Outcome").GetProperty("Hex").GetString()!);
        Assert.Equal(expected, AccessFilterImage(raw));
        var copy = new A.RawSecurityDescriptor(expected, 0);
        if (caseId is 2402 or 2418) Assert.Throws<NotSupportedException>(() => copy.GetSddlForm(AccessControlSections.All));
        else Assert.Equal(expected, AccessFilterImage(new A.RawSecurityDescriptor(copy.GetSddlForm(AccessControlSections.All))));
        Assert.Equal(expected, AccessFilterImage(copy));
        Assert.Equal(expected, AccessFilterImage(raw));
    }
}
