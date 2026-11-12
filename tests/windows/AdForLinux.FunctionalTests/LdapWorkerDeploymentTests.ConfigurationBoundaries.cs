using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class LdapWorkerDeploymentTests
{
    // These invoke only the real in-memory policy/parser boundaries. They never
    // admit deployment files, construct a VerifiedDeployment authority, launch a
    // worker, read a cache or verify inherited/native descriptors.
    private static byte[] PadConfiguration(byte[] bytes, int length)
    {
        Assert.True(bytes.Length < length);
        var padded = new byte[length];
        Array.Fill(padded, (byte)' ');
        bytes.CopyTo(padded, 0);
        return padded;
    }

    [Fact]
    public void Manifest_byte_ceiling_rejects_before_parsing_and_does_not_poison_next_recipe()
    {
        var original = Encoding.UTF8.GetBytes(Recipe());
        var atLimit = PadConfiguration(original, 4 * 1024 * 1024);
        var accepted = LdapWorkerDeployment.Parse(atLimit);
        Assert.Equal("release-1", accepted.Version);
        Assert.Equal(4, accepted.Artifacts.Length);
        var oversized = PadConfiguration(original, atLimit.Length + 1);
        oversized[0] = (byte)'!'; // invalid JSON too; size policy must win
        var error = Assert.Throws<InvalidDataException>(() => LdapWorkerDeployment.Parse(oversized));
        Assert.Contains("manifest exceeds limit", error.Message, StringComparison.Ordinal);
        Assert.Equal(original, atLimit.AsSpan(0, original.Length).ToArray());

        var next = LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(Recipe().Replace("release-1", "release-2", StringComparison.Ordinal)));
        Assert.Equal("release-2", next.Version);
        Assert.Equal("host/host.dll", next.Roles.HostAssembly);
        Assert.Equal("release-1", accepted.Version);
        Assert.NotSame(accepted.Artifacts, next.Artifacts);
    }

    [Fact]
    public void Manifest_inventory_ceiling_is_independent_of_byte_ceiling_and_recovers_after_rejection()
    {
        var root = JsonNode.Parse(Recipe())!.AsObject();
        var artifacts = root["Artifacts"]!.AsArray();
        for (var index = 4; index < 32768; index++)
            artifacts.Add(new JsonObject { ["Path"] = "data/f" + index.ToString("D5", System.Globalization.CultureInfo.InvariantCulture), ["Sha256"] = new string('a', 64) });
        var atLimit = Encoding.UTF8.GetBytes(root.ToJsonString());
        Assert.True(atLimit.Length < 4 * 1024 * 1024);
        var accepted = LdapWorkerDeployment.Parse(atLimit);
        Assert.Equal(32768, accepted.Artifacts.Length);
        Assert.Equal("data/f32767", accepted.Artifacts[^1].Path);
        artifacts.Add(new JsonObject { ["Path"] = "data/overflow", ["Sha256"] = new string('b', 64) });
        var oversized = Encoding.UTF8.GetBytes(root.ToJsonString());
        Assert.True(oversized.Length < 4 * 1024 * 1024); // reach inventory guard, not byte guard
        var error = Assert.Throws<InvalidDataException>(() => LdapWorkerDeployment.Parse(oversized));
        Assert.Contains("inventory size", error.Message, StringComparison.Ordinal);
        Assert.Equal(32768, accepted.Artifacts.Length);
        var recovered = LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(Recipe()));
        Assert.Equal(4, recovered.Artifacts.Length);
        Assert.Equal("native/bridge.so", recovered.Roles.NativeBridge);
    }

    [Fact]
    public void Composition_byte_ceiling_and_bridge_binding_are_revalidated_for_distinct_receipts()
    {
        var first = Encoding.UTF8.GetBytes(Composition().ToJsonString());
        var atLimit = PadConfiguration(first, 65536);
        VerifiedDeployment.ValidateComposition(atLimit, ReceiptBridgeHash);
        var oversized = PadConfiguration(first, 65537);
        oversized[0] = (byte)'!';
        var error = Assert.Throws<InvalidDataException>(() => VerifiedDeployment.ValidateComposition(oversized, ReceiptBridgeHash));
        Assert.Contains("receipt exceeds limit", error.Message, StringComparison.Ordinal);
        Assert.Equal(first, atLimit.AsSpan(0, first.Length).ToArray());

        var second = Composition();
        var secondHash = new string('b', 64);
        second["NativeBridgeSha256"] = secondHash;
        var secondBytes = Encoding.UTF8.GetBytes(second.ToJsonString());
        VerifiedDeployment.ValidateComposition(secondBytes, secondHash);
        Assert.Throws<PlatformNotSupportedException>(() => VerifiedDeployment.ValidateComposition(secondBytes, ReceiptBridgeHash));
        VerifiedDeployment.ValidateComposition(atLimit, ReceiptBridgeHash);
    }

    [Theory]
    [InlineData("Sources")]
    [InlineData("Archives")]
    public void Composition_inventory_ceiling_is_per_collection_and_recovers_for_next_receipt(string inventory)
    {
        var root = Composition();
        var entries = new JsonArray();
        for (var index = 0; index < 128; index++)
            entries.Add(new JsonObject { ["Path"] = "input/f" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture), ["Sha256"] = ReceiptBridgeHash });
        root[inventory] = entries;
        VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(root.ToJsonString()), ReceiptBridgeHash);
        entries.Add(new JsonObject { ["Path"] = "input/overflow", ["Sha256"] = ReceiptBridgeHash });
        var error = Assert.Throws<InvalidDataException>(() => VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(root.ToJsonString()), ReceiptBridgeHash));
        Assert.Contains("provenance inventory", error.Message, StringComparison.Ordinal);
        VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(Composition().ToJsonString()), ReceiptBridgeHash);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Configuration_depth_and_missing_fields_refuse_without_poisoning_later_valid_input(bool composition)
    {
        // Supported schemas are shallow. This is rejection of excessive parser
        // nesting, not a claim that arbitrary depth8 input is schema-valid.
        var nested = Encoding.UTF8.GetBytes(new string('[', 9) + "0" + new string(']', 9));
        if (composition)
        {
            Assert.ThrowsAny<JsonException>(() => VerifiedDeployment.ValidateComposition(nested, ReceiptBridgeHash));
            Assert.Throws<InvalidDataException>(() => VerifiedDeployment.ValidateComposition("{}"u8.ToArray(), ReceiptBridgeHash));
            VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(Composition().ToJsonString()), ReceiptBridgeHash);
        }
        else
        {
            Assert.ThrowsAny<JsonException>(() => LdapWorkerDeployment.Parse(nested));
            Assert.Throws<InvalidDataException>(() => LdapWorkerDeployment.Parse("{}"u8));
            Assert.Equal("release-1", LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(Recipe())).Version);
        }
    }

    [Fact]
    public void Distinct_restricted_recipes_and_returned_byte_arrays_do_not_share_configuration_state()
    {
        var first = new LdapWorkerKerberosProfile("ONE.INVALID", "directory-one.invalid", "/recording/plugins-one", new("kdc-one.invalid", 88));
        var second = new LdapWorkerKerberosProfile("TWO.INVALID", "directory-two.invalid", "/recording/plugins-two", new("kdc-two.invalid", 10088));
        var firstBytes = first.Generate(first.ServiceHost);
        var snapshot = firstBytes.ToArray();
        var secondBytes = second.Generate(second.ServiceHost);
        var secondSnapshot = secondBytes.ToArray();
        var firstText = Encoding.ASCII.GetString(firstBytes);
        var secondText = Encoding.ASCII.GetString(secondBytes);
        Assert.Contains("default_realm = ONE.INVALID", firstText);
        Assert.Contains("directory-one.invalid = ONE.INVALID", firstText);
        Assert.Contains("plugin_base_dir = /recording/plugins-one", firstText);
        Assert.Contains("kdc = kdc-one.invalid:88", firstText);
        Assert.DoesNotContain("TWO.INVALID", firstText);
        Assert.DoesNotContain("plugins-two", firstText);
        Assert.Contains("default_realm = TWO.INVALID", secondText);
        Assert.Contains("directory-two.invalid = TWO.INVALID", secondText);
        Assert.Contains("plugin_base_dir = /recording/plugins-two", secondText);
        Assert.Contains("kdc = kdc-two.invalid:10088", secondText);
        Assert.DoesNotContain("ONE.INVALID", secondText);
        Assert.DoesNotContain("plugins-one", secondText);
        Array.Fill(firstBytes, (byte)'!');
        Assert.Equal(snapshot, first.Generate(first.ServiceHost));
        Assert.Equal(secondSnapshot, secondBytes);
        Assert.Equal(secondSnapshot, second.Generate(second.ServiceHost));
        Assert.Throws<ArgumentException>(() => first.Generate(second.ServiceHost));
        Assert.Equal(snapshot, first.Generate(first.ServiceHost));
        // These are recipes and memory buffers; no actual session, source file,
        // environment mutation or deployed plugin directory is consumed.
    }
}
