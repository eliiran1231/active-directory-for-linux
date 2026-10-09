#pragma warning disable CA1416 // Framework enum values only; portable implementation is replayed.
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static object? ReplaySddlClosure(string operation, JsonElement arguments)
    {
        if (operation == "SddlErrorDetails")
        {
            try { _ = new A.RawSecurityDescriptor(arguments.GetProperty("Text").GetString()!); return null; }
            catch (Exception exception) { return new { Type = exception.GetType().FullName, ParamName = (exception as ArgumentException)?.ParamName,
                NativeErrorCode = (exception as System.ComponentModel.Win32Exception)?.NativeErrorCode }; }
        }
        if (operation == "SddlFormat")
        {
            var raw = new A.RawSecurityDescriptor(Convert.FromHexString(arguments.GetProperty("Hex").GetString()!), 0);
            var before = new byte[raw.BinaryLength]; raw.GetBinaryForm(before, 0);
            try { return raw.GetSddlForm((AccessControlSections)arguments.GetProperty("Sections").GetInt32()); }
            finally { var after = new byte[raw.BinaryLength]; raw.GetBinaryForm(after, 0); Assert.Equal(before, after); }
        }
        var descriptor = new A.RawSecurityDescriptor(arguments.GetProperty("Text").GetString()!);
        if (operation == "SddlRoundTrip")
            return descriptor.GetSddlForm((AccessControlSections)arguments.GetProperty("Sections").GetInt32());
        if (operation == "SddlParse")
        {
            var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
            return new { Hex = Convert.ToHexString(bytes), Control = (int)descriptor.ControlFlags };
        }
        throw new InvalidOperationException("Unknown SDDL recording operation: " + operation);
    }

    // Explicit incomplete-compatibility inventory. A matching native success must produce a
    // portable refusal; this does not substitute a canned native outcome or silently skip a row.
    private static string? SddlDeferredReason(JsonElement row)
    {
        var operation = row.GetProperty("Operation").GetString();
        var arguments = row.GetProperty("Arguments");
        if (operation is "SddlParse" or "SddlRoundTrip" or "SddlHostRelative")
        {
            var text = arguments.GetProperty("Text").GetString();
            if (text is "O:LA" or "G:LA" or "O:LG" or "G:LG") return "host-relative authority";
            if (operation == "SddlRoundTrip" && text == "D:(ZA;;RP;;;WD;(@User.Age == 1))") return "native collapsed callback tail omission";
            if (operation == "SddlRoundTrip" && text == "S:(RA;;;;;WD;(\"Department\",TS,0,\"Engineering\"))") return "native resource omission";
            if (operation == "SddlRoundTrip" && text is "S:(ML;;NW;;;LW)" or "S:(SP;;0;;;S-1-17-1)" or "S:(TL;;0;;;S-1-19-512-4096)")
                return "native label/policy omission";
        }
        if (operation == "SddlFormat" && arguments.GetProperty("Sections").GetInt32() == 15 &&
            SddlLossyFormatInputs.Contains(arguments.GetProperty("Hex").GetString()!))
            return "native opaque/flag omission";
        return null;
    }

    // Exact native transcript arguments for the 23 reviewed lossy exports. New shapes must
    // fail ordinary parity until independently reviewed; no broad unknown-ACE allowlist.
    private static readonly HashSet<string> SddlLossyFormatInputs = new(StringComparer.Ordinal)
    {
        "01000480000000000000000000000000140000000200200001000000000018001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000001C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000000118001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000011C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000000218001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000021C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000000418001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000041C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000000818001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000081C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000001018001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000101C00100000000101000000000001000000006172747800000000",
        "01000480000000000000000000000000140000000200200001000000002018001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000201C00100000000101000000000001000000006172747800000000",
        "010004800000000000000000000000001400000002001C00010000000040140010000000010100000000000100000000",
        "01000480000000000000000000000000140000000200200001000000004018001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000401C00100000000101000000000001000000006172747800000000",
        "010004800000000000000000000000001400000002001C00010000000080140010000000010100000000000100000000",
        "01000480000000000000000000000000140000000200200001000000008018001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000801C00100000000101000000000001000000006172747800000000",
        "010004800000000000000000000000001400000002001C000100000000FF140010000000010100000000000100000000",
        "0100048000000000000000000000000014000000020020000100000000FF18001000000001010000000000010000000001020304",
        "0100048000000000000000000000000014000000020024000100000000FF1C00100000000101000000000001000000006172747800000000",
    };

    // SHA-256 of each complete normalized native observation, including the successful
    // outcome. A fixture update cannot silently redefine what a reviewed refusal stands for.
    private static readonly Dictionary<int, string> SddlDeferredNativeHashes = new()
    {
        [2635] = "9D1B42B7424ED12FBA9A6339009CD74A5F051AB1623368DD1EAD84107C4678E2",
        [334] = "F8D5E24F8C0BAB1A63A502A56D4448A16EACAEF80933E9F9D1022098F0729389",
        [336] = "E88713056C66540FB1319764AACCF2354FB00A940C8C44D7AEBC7AC59362796A",
        [338] = "556BE310D624AA6BBF180DDADCCDA80CA0340C1161B64055EBBE1802E09BA3F6",
        [340] = "404FA3E9855B490D9C6A351C7C8B3342258179BD15903A5432169B975E9CC119",
        [655] = "083DAEC4D50EBA3ECDC9AC12D66797C7CE05131302F365BB8C92D1F06D7260D9",
        [656] = "F74B716D1B5BD488C802B4C1A603CF657C4E47D0FC560F8F837F79D6675BCB26",
        [657] = "59BAF0240063FE580B14955D19A8805E1AB6CD11348A137F13965DE6CAEC7485",
        [658] = "FF8F712B3DD603FBBCB14EECA8C76F8AAB8E9555AFC7D743FDF8CB7351AEE258",
        [659] = "254F42E08CCBA386C0EBB91BC86CB2F1113FB180E420DF564BA38962BC9C769E",
        [660] = "DCA49622DCC3BDE894D56D9D3AF3450DA6798D9E8A8605172E7B622570E88E83",
        [661] = "F2510D413EEF71F3D220575BD4FD30765406A955DC5D7F4D068F325251323ECF",
        [662] = "09BAA15A995B2E06237DBAE3B18B27B44FF7DFE1F30678F97F18B6DE6B44F1D7",
        [872] = "E8A320565D448D237D4447E6439A99F091E1E53DDEE7E72D9F0D0717889191C4",
        [873] = "3B71DF489EC00A0F41B17A93057690D5499542B6F26E64794B253C0B7A7DB7A8",
        [875] = "7E66CF8FB112AD8878C8B6918201707C333762BA541F9AFB9588EE5ECC3A5004",
        [876] = "40C2E6233F2CC8D674F4579DBD88710B72F5B73234F56C388F497315F9E6314B",
        [878] = "2241EE8F6F85E7ABAA20E8355D9960049AE68F9145AAF35D1B0499127BCF2DB8",
        [879] = "6B0AA9C0C7379403D169B6363EA65F678E48EC8EE36A8CCB67457884EDBB4703",
        [881] = "D798206185C1FF6E0F1F70058FDFC1397744C069D051E60F395DE619D5E0D420",
        [882] = "CFB520ACE716800505F380C7CD5ABBAF84CF6DA3BF4C84044F171B479B55B030",
        [884] = "8378CA399D061DDD6FA3C5C00F6CEA9885003C47DDF9E42D0054F2FBC6556A29",
        [885] = "C77E8BC674EB8B63BF3F80C87F00E8B261ABD95DFFBBCC9F4264EC0C4E7CE93F",
        [887] = "8ABA3A4D2B0EBA6AF3EDBB8159EA9F2C79187A4E9AFAB9CBC89B00A7185E663B",
        [888] = "B8AB32E3204737A61E51D34BDE045EE42CA1E33A3DCD8406FF366CA8F6B8FEB4",
        [890] = "7EF02EBCCFE516F93C3151547FD01FCED4D482A5A07786205AEAB02ADBADABAE",
        [891] = "EBFD2421F5CB11AB7345E302E3E902F82D0AD62278E702B5452257E0AE70EAB8",
        [892] = "9549993E673191231EFC680DC554AFCB54430B1D7F9CE004552CDC8939383F06",
        [893] = "CEEB8718E52C5E64979F4E8D1183937EC5CDD94A7D253FB981473CFD46F1EE9B",
        [894] = "4DFD2882C337DCCCB764F1E136B2C75CB60888EE89622DA9EBACC96709F4AC3E",
        [895] = "9F1EB3C8F83C16A322D448BA9C3BA3BA932549C47FD43FA91B9CE5CEBFC766A3",
        [896] = "3DC58AF93D79EDD48408E41EFD57315C68E88BCC39BD276EA563735CC237DD2D",
        [897] = "93A7CB804EDA81B8167D0B67BF542F306901893C2225A9D78A2B3BDD4018309D",
        [898] = "10D59A651F238172AA42C3E883F1449A0636F40D14A536FFDB0BCAFD859F7B28",
        [899] = "6B0C742E0AA787972F8EEC3189F0647A628EA807EBAD943481BE4A118FDCA43E",
        [900] = "64B96573F576A044D406F44F31E5A8E8D6B2D21D9BFEDCAA593C2BAF80749C73",
    };

    private static bool AssertSddlDeferred(JsonElement row, Exception? exception)
    {
        if (SddlDeferredReason(row) is null) return false;
        var caseId = row.GetProperty("Case").GetInt32();
        Assert.True(SddlDeferredNativeHashes.TryGetValue(caseId, out var expectedHash), "Unreviewed SDDL deferral " + caseId);
        Assert.Equal(expectedHash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(row)))));
        Assert.Equal(JsonValueKind.Null, row.GetProperty("ExceptionType").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, row.GetProperty("Outcome").ValueKind);
        Assert.IsType<NotSupportedException>(exception);
        return true;
    }

    [Fact]
    public void Recorded_Sddl_deferrals_remain_an_explicit_bounded_inventory()
    {
        var reasons = new List<string>();
        var caseIds = new List<int>();
        foreach (var data in ClosureRecordings())
        {
            using var document = JsonDocument.Parse((string)data[2]);
            var reason = SddlDeferredReason(document.RootElement);
            if (reason is not null) { reasons.Add(reason); caseIds.Add(document.RootElement.GetProperty("Case").GetInt32()); }
        }
        Assert.Equal(new[] { 334, 336, 338, 340, 655, 656, 657, 658, 659, 660, 661, 662,
            872, 873, 875, 876, 878, 879, 881, 882, 884, 885, 887, 888, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899, 900, 2635 }, caseIds.Order());
        Assert.Equal(36, reasons.Count);
        Assert.Equal(8, reasons.Count(r => r == "host-relative authority"));
        Assert.Equal(1, reasons.Count(r => r == "native resource omission"));
        Assert.Equal(1, reasons.Count(r => r == "native collapsed callback tail omission"));
        Assert.Equal(3, reasons.Count(r => r == "native label/policy omission"));
        Assert.Equal(23, reasons.Count(r => r == "native opaque/flag omission"));
    }

    [Fact]
    public void Sddl_export_refuses_opaque_payload_instead_of_silently_losing_it()
    {
        var sid = new AdForLinux.Security.Principal.SecurityIdentifier("S-1-1-0");
        var acl = new A.RawAcl(2, 1);
        acl.InsertAce(0, new A.CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 16, sid, false, new byte[] { 1, 2, 3, 4 }));
        var descriptor = new A.RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, sid, null, null, acl);
        var original = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(original, 0);
        Assert.Throws<NotSupportedException>(() => descriptor.GetSddlForm(AccessControlSections.Access));
        Assert.Equal("O:WD", descriptor.GetSddlForm(AccessControlSections.Owner));
        var after = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(after, 0);
        Assert.Equal(original, after);
    }

    [Fact]
    public void Sddl_conditional_payload_and_resource_input_preserve_binary_data()
    {
        var condition = new A.RawSecurityDescriptor("D:(XA;;RP;;;WD;(@User.Title == \"Engineer\"))");
        Assert.Equal("D:(XA;;RP;;;WD;(@USER.Title == \"Engineer\"))", condition.GetSddlForm(AccessControlSections.All));
        var resource = new A.RawSecurityDescriptor("S:(RA;;;;;WD;(\"Department\",TS,0,\"Engineering\"))");
        var before = new byte[resource.BinaryLength]; resource.GetBinaryForm(before, 0);
        Assert.Throws<NotSupportedException>(() => resource.GetSddlForm(AccessControlSections.All));
        var after = new byte[resource.BinaryLength]; resource.GetBinaryForm(after, 0);
        Assert.Equal(before, after);
    }
}
