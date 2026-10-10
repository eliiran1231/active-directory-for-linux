// Syntax and binary token codec only. No condition or access-check evaluation.
// MS-DTYP 2.4.4.17.4-.8 and 2.5.1.1; exact formatting is pinned by Windows recordings.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/dbd1d783-9d1e-4e1a-ab56-144e394b5c36
using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

internal static class SddlConditionCodec
{
    private sealed record Node(byte Code, byte[] Data, Node[] Children);
    private static readonly Dictionary<string, byte> Operators = new(StringComparer.OrdinalIgnoreCase)
    {
        ["=="] = 0x80, ["!="] = 0x81, ["<"] = 0x82, ["<="] = 0x83, [">"] = 0x84, [">="] = 0x85,
        ["Contains"] = 0x86, ["Exists"] = 0x87, ["Any_of"] = 0x88, ["Member_of"] = 0x89,
        ["Device_Member_of"] = 0x8a, ["Member_of_any"] = 0x8b, ["Device_Member_of_any"] = 0x8c,
        ["Not_Exists"] = 0x8d, ["Not_Contains"] = 0x8e, ["Not_Any_of"] = 0x8f,
        ["Not_Member_of"] = 0x90, ["Not_Device_Member_of"] = 0x91,
        ["Not_Member_of_any"] = 0x92, ["Not_Device_Member_of_any"] = 0x93,
        ["&&"] = 0xa0, ["||"] = 0xa1, ["!"] = 0xa2
    };
    private static bool Unary(byte code) => code is 0x87 or 0x8d or >= 0x89 and <= 0x8c or >= 0x90 and <= 0x93 or 0xa2;
    private static string Op(byte code) => Operators.First(pair => pair.Value == code).Key;
    internal static byte[] Parse(string text)
    {
        var parser = new Parser(text);
        var node = parser.Parse();
        using var stream = new MemoryStream(); stream.Write("artx"u8);
        Write(stream, node);
        while (stream.Length % 4 != 0) stream.WriteByte(0);
        if (stream.Length > ushort.MaxValue) throw Invalid();
        return stream.ToArray();
    }
    private static void Write(Stream stream, Node node)
    {
        var pending = new Stack<(Node Node, bool Visited)>(); pending.Push((node, false));
        while (pending.TryPop(out var item))
        {
            var current = item.Node;
            if (!item.Visited && current.Code != 0x50)
            {
                pending.Push((current, true));
                for (var i = current.Children.Length - 1; i >= 0; i--) pending.Push((current.Children[i], false));
                continue;
            }
            stream.WriteByte(current.Code);
            if (current.Code == 4) stream.Write(current.Data);
            else if (current.Code is 0x10 or 0x18 or 0x50 or 0x51 or >= 0xf8 and <= 0xfb)
            {
                var data = current.Data;
                if (current.Code == 0x50) { using var nested = new MemoryStream(); foreach (var child in current.Children) Write(nested, child); data = nested.ToArray(); }
                var length = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(length, data.Length); stream.Write(length); stream.Write(data);
            }
        }
    }
    internal static string Format(byte[] data)
    {
        // An arbitrary callback payload is not evidence of a condition. Never export it
        // as a conditionless ACE, or discard trailing/unknown bytes of a known signature.
        if (data.Length < 4 || !data.AsSpan(0, 4).SequenceEqual("artx"u8)) throw Malformed();
        try
        {
            var stack = new Stack<Node>(); var position = 4;
            while (position < data.Length && data[position] != 0)
            {
                var code = data[position++];
                if (Operators.ContainsValue(code))
                {
                    var count = Unary(code) ? 1 : 2;
                    if (stack.Count < count) throw Malformed();
                    var children = new Node[count]; for (var i = count - 1; i >= 0; i--) children[i] = stack.Pop();
                    stack.Push(new Node(code, [], children));
                }
                else stack.Push(ReadLiteral(data, ref position, code, 0));
            }
            if (stack.Count != 1) throw Malformed();
            if (data.Length - position > 3 || data.AsSpan(position).ContainsAnyExcept((byte)0)) throw Unsupported();
            var node = stack.Pop(); var text = Render(node);
            if (node.Code >= 0xf8) text = "(" + text + ")";
            // Text export must reproduce the entire condition payload, not just an
            // equivalent expression. Noncanonical/unknown encodings remain binary-only.
            if (!Parse(text).AsSpan().SequenceEqual(data)) throw Unsupported();
            return text;
        }
        catch (Exception e) when (e is ArgumentException or OverflowException) { throw Unsupported(); }
    }
    private static Node ReadLiteral(byte[] bytes, ref int position, byte code, int depth)
    {
        if (depth > 128) throw Unsupported();
        if (code == 4)
        {
            if (bytes.Length - position < 10) throw Malformed();
            var data = bytes.AsSpan(position, 10).ToArray(); position += 10;
            if (data[8] is < 1 or > 3 || data[9] is < 1 or > 3) throw Unsupported();
            return new Node(code, data, []);
        }
        // Int8/16/32 encodings are known token families outside this codec's
        // lossless subset. Do not confuse those with malformed/reserved opcodes.
        if (code is >= 1 and <= 3) throw Unsupported();
        if (code is not (0x10 or 0x18 or 0x50 or 0x51 or >= 0xf8 and <= 0xfb)) throw Malformed();
        if (bytes.Length - position < 4) throw Malformed();
        var length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(position)); position += 4;
        if (length < 0 || length > bytes.Length - position) throw Malformed();
        var payload = bytes.AsSpan(position, length).ToArray(); position += length;
        if (code != 0x50) return new Node(code, payload, []);
        var children = new List<Node>(); var offset = 0;
        while (offset < payload.Length) { var childCode = payload[offset++]; if (childCode == 0x50) throw Unsupported(); children.Add(ReadLiteral(payload, ref offset, childCode, depth + 1)); }
        return new Node(code, [], children.ToArray());
    }
    private static string Render(Node root)
    {
        // Emit each node directly into one buffer. Materializing every subtree would
        // repeatedly copy its descendants and allocate quadratically for skewed trees.
        var output = new StringBuilder();
        var pending = new Stack<(Node? Node, string? Text)>();
        pending.Push((root, null));
        while (pending.TryPop(out var item))
        {
            if (item.Node is not { } node) { output.Append(item.Text); continue; }
            if (node.Children.Length == 0) { output.Append(RenderLiteral(node)); continue; }
            if (node.Code == 0x50)
            {
                output.Append('{'); pending.Push((null, "}"));
                for (var i = node.Children.Length - 1; i >= 0; i--)
                {
                    pending.Push((node.Children[i], null));
                    if (i != 0) pending.Push((null, ", "));
                }
                continue;
            }
            output.Append('('); pending.Push((null, ")"));
            var logical = node.Code is 0xa0 or 0xa1 or 0xa2;
            if (Unary(node.Code))
            {
                output.Append(Op(node.Code));
                if (node.Code != 0xa2) output.Append(' ');
                PushChild(node.Children[0], logical);
            }
            else
            {
                PushChild(node.Children[1], logical);
                pending.Push((null, " " + Op(node.Code) + " "));
                PushChild(node.Children[0], logical);
            }
        }
        return output.ToString();

        void PushChild(Node child, bool logical)
        {
            var wrap = logical && child.Code >= 0xf8;
            if (wrap) pending.Push((null, ")"));
            pending.Push((child, null));
            if (wrap) pending.Push((null, "("));
        }
    }
    private static string RenderLiteral(Node node)
    {
        if (node.Code is >= 0xf8 and <= 0xfb)
        {
            var prefix = node.Code switch { 0xf9 => "@USER.", 0xfa => "@RESOURCE.", 0xfb => "@DEVICE.", _ => "" };
            return prefix + (node.Code == 0xf8 ? Unicode(node.Data) : EscapeName(Unicode(node.Data)));
        }
        if (node.Code == 0x10) { var value = Unicode(node.Data); if (value.Contains('"') || value.Contains('\0')) throw Unsupported(); return "\"" + value + "\""; }
        if (node.Code == 0x18) return "#" + Convert.ToHexString(node.Data).ToLowerInvariant();
        if (node.Code == 0x51)
        {
            var sid = new SecurityIdentifier(node.Data, 0);
            if (sid.BinaryLength != node.Data.Length) throw Unsupported();
            return "SID(" + (SecurityIdentifier.GetSddlAlias(sid) ?? sid.Value) + ")";
        }
        if (node.Code == 0x50) return "{}";
        if (node.Code == 4)
        {
            var bits = BinaryPrimitives.ReadUInt64LittleEndian(node.Data);
            var sign = node.Data[8]; var radix = node.Data[9];
            var magnitude = sign == 2 ? unchecked(0UL - bits) : bits;
            var digits = radix switch { 1 => Octal(magnitude), 3 => "0x" + magnitude.ToString("x", CultureInfo.InvariantCulture), _ => magnitude.ToString(CultureInfo.InvariantCulture) };
            return (sign == 1 ? "+" : sign == 2 ? "-" : "") + digits;
        }
        throw Unsupported();
    }
    private static string Octal(ulong value)
    {
        if (value == 0) return "0";
        var digits = ""; while (value != 0) { digits = (char)('0' + (value & 7)) + digits; value >>= 3; } return "0" + digits;
    }
    private static string Unicode(byte[] bytes)
    {
        if (bytes.Length % 2 != 0) throw Unsupported();
        return SddlUtf16.Decode(bytes);
    }
    internal static string UnescapeName(string text, bool conditional = false)
    {
        var result = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '%')
            {
                if (text.Length - i < 5 || !ushort.TryParse(text.AsSpan(i + 1, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code) ) throw Invalid();
                c = (char)code; i += 4;
                if (conditional && !NeedsNameEscape(c)) throw Invalid();
                if (c == '\0') break; // Native text conversion terminates an escaped attribute name here.
            }
            if (c == '\0') throw Invalid(); result.Append(c);
        }
        return result.ToString();
    }
    private static bool NeedsNameEscape(char c) => c < 0x21 || c >= 0x7f || "!&()><=|%,\"".Contains(c);
    private static string EscapeName(string text) => string.Concat(text.Select(c => NeedsNameEscape(c) ? "%" + ((int)c).ToString("x4", CultureInfo.InvariantCulture) : c.ToString()));

    // The recorded native simple-name class is the legacy Latin-1 alphanumeric
    // class, not all Unicode letters/digits. All 128 high-byte characters are probed.
    private static bool SimpleNameCharacter(char c) => char.IsAsciiLetterOrDigit(c) || ":./_".Contains(c)
        || c is '\u00b2' or '\u00b3' or '\u00b9' or >= '\u00c0' and <= '\u00d6'
            or >= '\u00d8' and <= '\u00f6' or >= '\u00f8' and <= '\u00ff';

    private sealed class Parser(string text)
    {
        private int position;
        internal Node Parse()
        {
            Space(); if (!Take("(")) throw Invalid();
            var operators = new Stack<byte>(); operators.Push(0);
            var values = new Stack<Node>();
            var expectTerm = true;
            while (operators.Count != 0)
            {
                if (expectTerm)
                {
                    if (Take("(")) { operators.Push(0); continue; }
                    if (Take("!")) { if (operators.Peek() == 0xa2) throw Invalid(); operators.Push(0xa2); continue; }
                    var saved = position; var word = Word();
                    if (Operators.TryGetValue(word, out var unary) && Unary(unary))
                    {
                        var operand = Operand(unary is not (0x87 or 0x8d));
                        if (unary is 0x87 or 0x8d && operand.Code is not (0xf8 or 0xfa)) throw Invalid();
                        values.Push(new Node(unary, [], [operand]));
                    }
                    else { position = saved; values.Push(Attribute()); }
                    expectTerm = false;
                    continue;
                }
                if (Take(")"))
                {
                    while (operators.Count != 0 && operators.Peek() != 0) Reduce();
                    if (operators.Count == 0) throw Invalid();
                    operators.Pop(); continue;
                }
                var token = Operator();
                if (!Operators.TryGetValue(token, out var code) || Unary(code)) throw Invalid();
                var precedence = Precedence(code);
                while (operators.Peek() != 0 && Precedence(operators.Peek()) >= precedence) Reduce();
                if (precedence == 4)
                {
                    if (values.Count == 0 || values.Peek().Code < 0xf8) throw Invalid();
                    var left = values.Pop(); values.Push(new Node(code, [], [left, Operand(true)]));
                }
                else { operators.Push(code); expectTerm = true; }
            }
            Space(); if (expectTerm || position != text.Length || values.Count != 1) throw Invalid();
            return values.Pop();

            void Reduce()
            {
                var code = operators.Pop(); var count = Unary(code) ? 1 : 2;
                if (values.Count < count) throw Invalid();
                var children = new Node[count]; for (var i = count - 1; i >= 0; i--) children[i] = values.Pop();
                values.Push(new Node(code, [], children));
            }
        }
        // MS-DTYP 2.5.1.3: relations bind before NOT, then AND, then OR.
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d1a8392f-3f54-4fea-8233-44ede9eb198c
        private static int Precedence(byte code) => code == 0xa1 ? 1 : code == 0xa0 ? 2 : code == 0xa2 ? 3 : 4;
        private Node Operand(bool literal, bool inComposite = false)
        {
            Space();
            if (!literal || Peek() == '@') return Attribute();
            if (Take("{"))
            {
                if (inComposite) throw Invalid();
                var children = new List<Node>();
                do { children.Add(Operand(true, true)); } while (Take(","));
                if (!Take("}") || children.Any(n => n.Code >= 0xf8 || n.Code == 0x50)) throw Invalid();
                return new Node(0x50, [], children.ToArray());
            }
            if (Take("\""))
            {
                var end = text.IndexOf('"', position); if (end < 0) throw Invalid();
                var value = text[position..end]; position = end + 1;
                if (value.Contains('\0')) throw Invalid(); return new Node(0x10, SddlUtf16.Encode(value), []);
            }
            if (Take("SID("))
            {
                var end = text.IndexOf(')', position); if (end < 0) throw Invalid();
                var value = text[position..end]; position = end + 1;
                if (value is "LA" or "LG") throw new NotSupportedException("Condition SID requires explicit host authority.");
                SecurityIdentifier sid; try { sid = new SecurityIdentifier(value); } catch (ArgumentException) { throw Invalid(); }
                var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return new Node(0x51, bytes, []);
            }
            if (Take("#"))
            {
                var hex = Word().Replace('#', '0'); if (hex.Length == 0) throw Invalid(); try { return new Node(0x18, Convert.FromHexString((hex.Length % 2 == 0 ? "" : "0") + hex), []); } catch (FormatException) { throw Invalid(); }
            }
            var number = Word(); var bits = SddlResourceCodec.Number(number);
            var sign = number.StartsWith('+') ? (byte)1 : number.StartsWith('-') ? (byte)2 : (byte)3;
            if (sign == 2 && unchecked(0UL - bits) > long.MaxValue) throw Invalid();
            var digits = sign == 3 ? number : number[1..];
            var radix = digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? (byte)3 : digits.StartsWith('0') ? (byte)1 : (byte)2;
            var data = new byte[10]; BinaryPrimitives.WriteUInt64LittleEndian(data, bits); data[8] = sign; data[9] = radix; return new Node(4, data, []);
        }
        private Node Attribute()
        {
            Space(); byte code = 0xf8;
            if (Peek() == '@')
            {
                if (Take("@USER.")) code = 0xf9;
                else if (Take("@RESOURCE.")) code = 0xfa;
                else if (Take("@DEVICE.")) code = 0xfb;
                else throw Invalid();
            }
            var start = position;
            while (position < text.Length)
            {
                var c = text[position];
                var simple = SimpleNameCharacter(c);
                if (code == 0xf8)
                {
                    if (!simple && !(c == '@' && position > start)) break;
                }
                else if (!simple && !(c >= 0x80 || "#$'*+-;,?@[\\]^`{}~%".Contains(c))) break;
                position++;
            }
            var value = text[start..position];
            if (value.Length == 0) throw Invalid();
            return new Node(code, SddlUtf16.Encode(code == 0xf8 ? value : UnescapeName(value, conditional: true)), []);
        }
        private string Operator()
        {
            foreach (var token in new[] { "==", "!=", "<=", ">=", "&&", "||", "<", ">" }) if (Take(token)) return token;
            return Word();
        }
        private string Word()
        {
            Space(); var start = position;
            while (position < text.Length && !char.IsWhiteSpace(text[position]) && !"(){}\",!&|<>=;".Contains(text[position])) position++;
            return text[start..position];
        }
        private char Peek() => position < text.Length ? text[position] : '\0';
        private void Space() { while (position < text.Length && char.IsWhiteSpace(text[position])) position++; }
        private bool Take(string value) { Space(); if (!text.AsSpan(position).StartsWith(value, StringComparison.OrdinalIgnoreCase)) return false; position += value.Length; return true; }
    }
    private static ArgumentException Invalid() => new("The SDDL condition is invalid.", "sddlForm");
    private static InvalidOperationException Malformed() => new("The conditional ACE payload is not a valid native condition encoding.");
    private static NotSupportedException Unsupported() => new("The conditional ACE encoding cannot be exported losslessly by this codec.");
}
