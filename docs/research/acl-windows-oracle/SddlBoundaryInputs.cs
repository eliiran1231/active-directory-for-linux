using System.Buffers.Binary;

// Data-only proposed probes. No expected Windows outcomes and no production-code dependency.
internal static class SddlBoundaryInputs
{
    internal sealed record Input(string Label, string Family, string Text);

    internal static IEnumerable<Input> Create()
    {
        // Probe around, not assume, 16-bit ACE/ACL size boundaries. Include sizes
        // beyond those boundaries to observe native rejection and parameter identity.
        foreach (var length in new[] { 0, 1, 255, 4096, 32728, 32736, 32740, 32741, 32742, 32743, 32744, 32745, 32748, 32767, 32768, 65535, 65536 })
        {
            var value = new string('x', length);
            yield return new($"size/fl-string/{length}", "FL", $"S:(FL;;RP;;;WD;(@User.A == \"{value}\"))");
            yield return new($"size/xa-string/{length}", "XA", $"D:(XA;;RP;;;WD;(@User.A == \"{value}\"))");
            yield return new($"size/ra-string/{length}", "RA", $"S:(RA;;;;;WD;(\"Name\",TS,0,\"{value}\"))");
            yield return new($"size/ra-name/{length}", "RA", $"S:(RA;;;;;WD;(\"{value}\",TS,0,\"v\"))");
        }
        foreach (var count in new[] { 0, 1, 2, 255, 4095, 4096, 8191, 8192 })
        {
            var values = count == 0 ? "" : "," + string.Join(",", Enumerable.Repeat("1", count));
            yield return new($"size/ra-values/{count}", "RA", $"S:(RA;;;;;WD;(\"N\",TU,0{values}))");
        }
        var units = new (string Name, string Value)[]
        {
            ("composed", "\u00e9"), ("decomposed", "e\u0301"), ("cjk", "研发"),
            ("pair", "\ud83d\ude00"), ("high", "\ud800"), ("low", "\udc00"),
            ("reversed", "\udc00\ud800"), ("nul", "\0"), ("escaped-nul", "%0000"),
            ("noncharacter", "\uffff"), ("bom", "\ufeff")
        };
        foreach (var (name, unit) in units)
        {
            var value = "A" + unit + "B";
            foreach (var family in new[] { "FL", "XA" })
            {
                var section = family == "FL" ? "S" : "D";
                yield return new($"unicode/{family}-string/{name}", family, $"{section}:({family};;RP;;;WD;(@User.A == \"{value}\"))");
                yield return new($"unicode/{family}-attribute/{name}", family, $"{section}:({family};;RP;;;WD;(@User.{value} == 1))");
            }
            yield return new($"unicode/ra-value/{name}", "RA", $"S:(RA;;;;;WD;(\"Name\",TS,0,\"{value}\"))");
            yield return new($"unicode/ra-name/{name}", "RA", $"S:(RA;;;;;WD;(\"{value}\",TS,0,\"v\"))");
        }
        foreach (var (family, valid) in new[]
        {
            ("FL", "S:(FL;;RP;;;WD;(@User.A == 1))"),
            ("XA", "D:(XA;;RP;;;WD;(@User.A == 1))"),
            ("RA", "S:(RA;;;;;WD;(\"N\",TS,0,\"v\"))")
        })
        {
            yield return new($"nul/{family}/prefix", family, "\0" + valid);
            yield return new($"nul/{family}/suffix", family, valid + "\0garbage");
            yield return new($"nul/{family}/middle", family, valid.Insert(valid.IndexOf(';') + 1, "\0"));
        }
        // Single-fault controls, every pair and all faults together. The original
        // text (not a predicted validation order) is the authority for each probe.
        foreach (var family in new[] { "FL", "XA", "RA" })
        {
            var masks = new[] { 0 }.Concat(Enumerable.Range(0, 6).Select(i => 1 << i))
                .Concat(from a in Enumerable.Range(0, 6) from b in Enumerable.Range(a + 1, 5 - a) select (1 << a) | (1 << b))
                .Append(63);
            foreach (var faults in masks)
            {
                var section = family == "XA" ? "D" : "S";
                if ((faults & 1) != 0) section = section == "D" ? "S" : "D";
                var flags = (faults & 2) != 0 ? "SA" : "";
                var rights = (faults & 4) != 0 ? family == "FL" ? "GA" : family == "RA" ? "RP" : "ZZ" : family == "RA" ? "" : "RP";
                var guid = (faults & 8) != 0 ? "11111111-2222-3333-4444-555555555555" : "";
                var sid = (faults & 16) != 0 ? family == "XA" ? "garbage" : "SY" : "WD";
                var condition = family == "RA" ? "(\"N\",TB,0,1)" : "(@User.A == 1)";
                if ((faults & 32) != 0) condition = family == "RA" ? "(\"N\",TB,0,2)" : "(@User.A ==)";
                yield return new($"precedence/{family}/{faults:D2}", family, $"{section}:({family};{flags};{rights};{guid};;{sid};{condition})");
            }
        }
    }

    internal static IEnumerable<Input> CreateSizeFollowup()
    {
        // Narrow the transitions seen in the first 220 actual Windows rows.
        // These are questions, not predicted acceptance or exception thresholds.
        foreach (var length in Enumerable.Range(32690, 61))
        {
            var value = new string('x', length);
            yield return new($"transition/fl-string/{length}", "FL", $"S:(FL;;RP;;;WD;(@User.A == \"{value}\"))");
            yield return new($"transition/xa-string/{length}", "XA", $"D:(XA;;RP;;;WD;(@User.A == \"{value}\"))");
            yield return new($"transition/ra-string/{length}", "RA", $"S:(RA;;;;;WD;(\"Name\",TS,0,\"{value}\"))");
            yield return new($"transition/ra-name/{length}", "RA", $"S:(RA;;;;;WD;(\"{value}\",TS,0,\"v\"))");
        }
        foreach (var count in Enumerable.Range(5450, 16))
            yield return new($"transition/ra-values/{count}", "RA", $"S:(RA;;;;;WD;(\"N\",TU,0,{string.Join(",", Enumerable.Repeat("1", count))}))");
    }

    // Encoding.Unicode and JSON text encoding can replace lone surrogates. Preserve
    // every input/output UTF-16 code unit explicitly, including NUL and invalid pairs.
    internal static string Utf16Hex(string value)
    {
        var bytes = new byte[value.Length * 2];
        for (var i = 0; i < value.Length; i++) BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(i * 2), value[i]);
        return Convert.ToHexString(bytes);
    }
}
