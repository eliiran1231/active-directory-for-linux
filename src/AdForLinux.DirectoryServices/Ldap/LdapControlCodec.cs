using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Text;

namespace AdForLinux.DirectoryServices.Ldap;

internal static class LdapControlCodec
{
    internal static LdapTransportControl FromProtocol(DirectoryControl control)
    {
        byte[] bytes;
        // Use public properties for exact framework types. Custom subclasses
        // retain their virtual GetValue semantics; no private native handle.
        var type = control.GetType();
        if (type == typeof(SecurityDescriptorFlagControl) || type == typeof(ExtendedDNControl) ||
            type == typeof(DirSyncRequestControl) || type == typeof(VlvRequestControl) || type == typeof(SortRequestControl))
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            writer.PushSequence();
            switch (control)
            {
                case SecurityDescriptorFlagControl mask: writer.WriteInteger((int)mask.SecurityMasks); break;
                case ExtendedDNControl extended: writer.WriteInteger((int)extended.Flag); break;
                case DirSyncRequestControl sync:
                    writer.WriteInteger(unchecked((int)sync.Option)); writer.WriteInteger(sync.AttributeCount);
                    writer.WriteOctetString(sync.Cookie); break;
                case VlvRequestControl vlv:
                    writer.WriteInteger(vlv.BeforeCount); writer.WriteInteger(vlv.AfterCount);
                    if (vlv.Target.Length != 0) writer.WriteOctetString(vlv.Target, new(TagClass.ContextSpecific, 1));
                    else
                    {
                        var tag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
                        writer.PushSequence(tag); writer.WriteInteger(vlv.Offset); writer.WriteInteger(vlv.EstimateCount); writer.PopSequence(tag);
                    }
                    if (vlv.ContextId.Length != 0) writer.WriteOctetString(vlv.ContextId);
                    break;
                case SortRequestControl sort:
                    foreach (var key in sort.SortKeys)
                    {
                        writer.PushSequence(); writer.WriteOctetString(Encoding.UTF8.GetBytes(key.AttributeName));
                        if (key.MatchingRule is not null) writer.WriteOctetString(Encoding.UTF8.GetBytes(key.MatchingRule), new(TagClass.ContextSpecific, 0));
                        if (key.ReverseOrder) writer.WriteBoolean(true, new(TagClass.ContextSpecific, 1));
                        writer.PopSequence();
                    }
                    break;
            }
            writer.PopSequence(); bytes = writer.Encode();
        }
        else bytes = control.GetValue();
        // Protocols' native marshaler treats an empty GetValue as absent.
        return new(control.Type, bytes, control.IsCritical, bytes.Length != 0);
    }

    internal sealed record ResponseState(byte[]? SyncCookie, (int Position, int Count, byte[] Context)? Vlv);

    // Structurally validate all recognized payloads before publishing state. Unknown
    // controls remain opaque. Control-specific results are not LDAP result codes.
    internal static ResponseState DecodeResponse(LdapTransportControl[] controls)
    {
        try { return DecodeResponseCore(controls); }
        catch (AsnContentException) { throw new BerConversionException(); }
    }

    private static ResponseState DecodeResponseCore(LdapTransportControl[] controls)
    {
        byte[]? cookie = null;
        (int, int, byte[])? vlv = null;
        foreach (var control in controls)
        {
            if (control.Oid is not ("1.2.840.113556.1.4.841" or "2.16.840.1.113730.3.4.10" or
                "1.2.840.113556.1.4.474" or "1.2.840.113556.1.4.319" or "1.2.840.113556.1.4.1504")) continue;
            if (!control.HasValue) throw new BerConversionException();
            var reader = new AsnReader(control.Value, AsnEncodingRules.BER);
            var sequence = reader.ReadSequence();
            int Integer()
            {
                if (!sequence.TryReadInt32(out var value)) throw new BerConversionException();
                return value;
            }
            switch (control.Oid)
            {
                case "1.2.840.113556.1.4.841":
                    _ = Integer(); _ = Integer(); var returnedCookie = sequence.ReadOctetString();
                    cookie ??= returnedCookie; break;
                case "2.16.840.1.113730.3.4.10":
                    var position = Integer(); var count = Integer(); _ = sequence.ReadEnumeratedValue<ResultCode>();
                    var context = sequence.HasData ? sequence.ReadOctetString() : [];
                    vlv ??= (position, count, context); break;
                case "1.2.840.113556.1.4.474":
                    _ = sequence.ReadEnumeratedValue<ResultCode>();
                    if (sequence.HasData) _ = sequence.ReadOctetString(new(TagClass.ContextSpecific, 0));
                    break;
                case "1.2.840.113556.1.4.319":
                    _ = Integer(); _ = sequence.ReadOctetString(); break;
                case "1.2.840.113556.1.4.1504":
                    _ = sequence.ReadEnumeratedValue<ResultCode>(); break;
            }
            sequence.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        }
        return new(cookie, vlv);
    }

    internal static LdapTransportControl Snapshot(LdapTransportControl control)
    {
        ArgumentNullException.ThrowIfNull(control);
        ArgumentNullException.ThrowIfNull(control.Value);
        if (!control.HasValue && control.Value.Length != 0)
            throw new ArgumentException("An absent LDAP control value cannot contain bytes.");
        return control with { Value = control.Value.ToArray() };
    }
}
