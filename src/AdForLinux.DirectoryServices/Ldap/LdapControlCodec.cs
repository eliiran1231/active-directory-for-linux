using System.DirectoryServices.Protocols;
using System.Formats.Asn1;

namespace AdForLinux.DirectoryServices.Ldap;

internal static class LdapControlCodec
{
    internal static LdapTransportControl FromProtocol(DirectoryControl control)
    {
        byte[] bytes;
        // Protocols 9 encodes this public mask as BER SEQUENCE { INTEGER }.
        // Exact type preserves custom subclasses' virtual GetValue behavior.
        if (control.GetType() == typeof(SecurityDescriptorFlagControl))
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            writer.PushSequence();
            writer.WriteInteger((int)((SecurityDescriptorFlagControl)control).SecurityMasks);
            writer.PopSequence();
            bytes = writer.Encode();
        }
        else bytes = control.GetValue();
        // Protocols' native marshaler treats an empty GetValue as absent.
        return new(control.Type, bytes, control.IsCritical, bytes.Length != 0);
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
