using System.Text.Json;

namespace AdForLinux.DirectoryServices.Ldap;

internal sealed partial class VerifiedDeployment
{
    internal const string RestrictedContract = "adfl-restricted-file-gssapi-v1";
    internal void RequireRestrictedComposition()
    {
        // Included in the already hashed immutable inventory. This is trusted
        // administrator adoption of the pinned build recipe, not a signature or
        // an attestation against that administrator. Never infer it from versions.
        var path = GetArtifact("composition.json");
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("Composition receipt exceeds limit.");
        ValidateComposition(File.ReadAllBytes(path), nativeBridgeSha256);
    }

    internal static void ValidateComposition(byte[] bytes, string bridgeHash)
    {
        if (bytes.Length > 65536) throw new InvalidDataException("Composition receipt exceeds limit.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        Exact(root, "FormatVersion", "Contract", "NativeAbi", "NativeBridgeSha256", "Inputs", "Sources", "Archives");
        if (root.GetProperty("FormatVersion").GetInt32() != 1 || root.GetProperty("NativeAbi").GetInt32() != 4 ||
            root.GetProperty("Contract").GetString() != RestrictedContract ||
            !string.Equals(root.GetProperty("NativeBridgeSha256").GetString(), bridgeHash, StringComparison.OrdinalIgnoreCase))
            throw new PlatformNotSupportedException("Deployment does not identify the restricted composition and exact bridge.");
        var pins = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["MitArchiveSha256"] = "b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35",
            ["CyrusArchiveSha256"] = "7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c",
            ["OpenLdapArchiveSha256"] = "1794dbb7225516ae5fb21f3f9a19c0181f0ce33e9d0218e0f623b0a386578181",
            ["MitPluginSourceSha256"] = "86f737e2ffe69a587c53bddb36df3b103dc632eccc978a3fe0f69118f6524898",
            ["CyrusGssapiSourceSha256"] = "a105e8462e893f6f17f594e6997df6a4a275ef34e468c017dcbcb8933a096e59"
        };
        var inputs = root.GetProperty("Inputs"); Exact(inputs, pins.Keys.ToArray());
        if (pins.Any(pin => inputs.GetProperty(pin.Key).GetString() != pin.Value))
            throw new PlatformNotSupportedException("Composition input pins do not match the reviewed recipe.");
        Inventory(root.GetProperty("Sources")); Inventory(root.GetProperty("Archives"));
    }
    private static void Inventory(JsonElement array)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 1 or > 128)
            throw new InvalidDataException("Invalid composition provenance inventory.");
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in array.EnumerateArray())
        {
            Exact(entry, "Path", "Sha256");
            var path = entry.GetProperty("Path").GetString(); var hash = entry.GetProperty("Sha256").GetString();
            if (string.IsNullOrEmpty(path) || path.Length > 1024 || path.Split('/').Any(part => part is "" or "." or ".." ||
                part.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-' and not '_')) || !paths.Add(path) ||
                hash is null || hash.Length != 64 || !hash.All(Uri.IsHexDigit))
                throw new InvalidDataException("Invalid composition provenance entry.");
        }
    }
    private static void Exact(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected composition object.");
        var remaining = names.ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!remaining.Remove(property.Name)) throw new InvalidDataException("Unknown or duplicate composition field.");
        if (remaining.Count != 0) throw new InvalidDataException("Missing composition field.");
    }
}
