using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

internal static partial class SddlAssemblyProbe
{
    // A single six-case experiment. Total decoded UTF-16 units and token count
    // stay fixed; no adaptive expansion or production threshold follows it.
    internal static void WritePartition(string path, int index)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if ((uint)index >= 6) throw new ArgumentOutOfRangeException(nameof(index));
        var attributeUnits = new[] { 1, 16351, 32702 }[index / 2];
        var literalUnits = 32703 - attributeUnits;
        var after = index % 2;
        var attribute = "A" + new string('x', attributeUnits - 1);
        var literal = new string('x', literalUnits);
        var condition = $"(@User.{attribute} == \"{literal}\")";
        var text = $"D:(XA;;RP;;;WD;{condition})" + (after == 1 ? Ordinary : "");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
        Emit(new { Kind="Attempt", Case=index, AttributeUnits=attributeUnits, LiteralUnits=literalUnits,
            After=after, Capacity=MaximumCapacity, InputUtf16Hex=SddlBoundaryInputs.Utf16Hex(text),
            Runtime=RuntimeInformation.FrameworkDescription, OS=RuntimeInformation.OSDescription });

        var ordinary = Convert("D:" + Ordinary);
        var ordinaryAce = ExtractDescriptorAce(ordinary, 0)
            ?? throw new InvalidOperationException("Native ordinary control unavailable; no replay bytes substituted.");
        // Compile into a fresh maximum-capacity empty ACL BEFORE whole conversion.
        // No successful sibling assumption: the independent control decides whether
        // token partitioning can be interpreted as a sizing experiment at all.
        var compiled = Assemble(true, new Witness(literalUnits,0,0), condition, null, ordinaryAce, ordinaryAce);
        var steps = JsonSerializer.SerializeToElement(compiled);
        var final = steps[steps.GetArrayLength() - 1].GetProperty("Post");
        var large = ExtractAclAce(System.Convert.FromHexString(final.GetProperty("Hex").GetString()!), 9);
        var shape = PartitionShape(large, attribute, literal);
        var established = compiled.Length == 2 && steps.EnumerateArray().All(step => step.GetProperty("Success").GetBoolean())
            && ordinaryAce.Length == 20 && shape.Matches;
        Emit(new { Kind="CompileControl", Case=index, Established=established, Shape=shape, Steps=compiled });

        var full = Convert(text);
        var convertedLarge = ExtractDescriptorAce(full, 9);
        Emit(new { Kind="Native", Case=index, Full=full, Ordinary=ordinary,
            MatchesCompiledLargeAce=convertedLarge is null || large is null ? (bool?)null : convertedLarge.AsSpan().SequenceEqual(large) });
        var replay = established ? Assemble(false, new Witness(literalUnits,0,after), condition, large, ordinaryAce, ordinaryAce) : [];
        Emit(new { Kind="Replay", Case=index, ControlEstablished=established, Steps=replay });
        // An unsuccessful control is recorded as inconclusive, never promoted to
        // a claim about allocation. Guard violations still fail the worker above.
    }

    private sealed record PartitionTokenShape(int? AceBytes, string? Signature, byte? AttributeToken,
        uint? AttributeBytes, byte? LiteralToken, uint? LiteralBytes, byte? Operator,
        int? PaddingBytes, bool Matches);

    private static PartitionTokenShape PartitionShape(byte[]? ace, string attribute, string literal)
    {
        if (ace is null || ace.Length < 34) return new(ace?.Length,null,null,null,null,null,null,null,false);
        var signature = Encoding.ASCII.GetString(ace,20,4);
        var attributeCode = ace[24];
        var attributeBytes = BinaryPrimitives.ReadUInt32LittleEndian(ace.AsSpan(25));
        var literalOffset = 29L + attributeBytes;
        if (literalOffset > ace.Length - 5) return new(ace.Length,signature,attributeCode,attributeBytes,null,null,null,null,false);
        var position = (int)literalOffset;
        var literalCode = ace[position];
        var literalBytes = BinaryPrimitives.ReadUInt32LittleEndian(ace.AsSpan(position+1));
        var operatorOffset = position + 5L + literalBytes;
        if (operatorOffset >= ace.Length) return new(ace.Length,signature,attributeCode,attributeBytes,literalCode,literalBytes,null,null,false);
        var op = ace[(int)operatorOffset];
        var padding = ace.Length - (int)operatorOffset - 1;
        var matches = ace.Length == 65444 && signature == "artx" && attributeCode == 0xf9 && literalCode == 0x10 && op == 0x80
            && attributeBytes == attribute.Length*2 && literalBytes == literal.Length*2 && padding is >= 0 and <= 3
            && !ace.AsSpan((int)operatorOffset+1).ContainsAnyExcept((byte)0)
            && ace.AsSpan(29,(int)attributeBytes).SequenceEqual(Encoding.Unicode.GetBytes(attribute))
            && ace.AsSpan(position+5,(int)literalBytes).SequenceEqual(Encoding.Unicode.GetBytes(literal));
        return new(ace.Length,signature,attributeCode,attributeBytes,literalCode,literalBytes,op,padding,matches);
    }
}
