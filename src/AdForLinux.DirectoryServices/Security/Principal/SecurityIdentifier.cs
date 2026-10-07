// Managed equality/hash/comparison contracts adapted from dotnet/runtime v9.0.0 SID.cs.
// Copyright (c) .NET Foundation and Contributors. MIT license: ../AccessControl/RULES-LICENSE.txt.
// Native text conversion and domain behavior are implemented from the detached recordings.
using AdForLinux.DirectoryServices.Security.Core;
using System.Buffers.Binary;

namespace AdForLinux.Security.Principal;

/// <summary>A portable immutable numeric SID. No operating-system or directory lookup is performed.</summary>
public sealed class SecurityIdentifier : IdentityReference, IComparable<SecurityIdentifier>
{
    private readonly Sid _sid;
    public static readonly int MinBinaryLength = Sid.MinBinaryLength;
    public static readonly int MaxBinaryLength = Sid.MaxBinaryLength;

    public SecurityIdentifier(string sddlForm)
    {
        ArgumentNullException.ThrowIfNull(sddlForm);
        // Keep the strict lossless core parser separate from the measured public SDDL contract.
        // These two aliases are covered by detached recordings; the remaining alias family
        // is an explicit pending dependency of the complete SDDL implementation.
        var text = sddlForm switch { "BA" => "S-1-5-32-544", "WD" => "S-1-1-0", _ => sddlForm };
        var parts = text.Split('-');
        if (parts.Length < 4 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)
            || !TryUnsigned(parts[1], byte.MaxValue, out var revision)
            || !TryUnsigned(parts[2], 0xFFFFFFFFFFFF, out var authority))
            throw new ArgumentException("The value is not a valid numeric SID.", nameof(sddlForm));
        var values = new uint[parts.Length - 3];
        for (var i = 0; i < values.Length; i++)
        {
            // Windows saturates oversized sub-authorities to UINT_MAX during text conversion.
            if (!TryUnsigned(parts[i + 3], uint.MaxValue, out var value, saturate: true))
                throw new ArgumentException("The value is not a valid numeric SID.", nameof(sddlForm));
            values[i] = (uint)value;
        }
        if (revision != 1 || values.Length > Sid.MaxSubAuthorities)
            throw new ArgumentException("The converted binary SID is invalid.", "binaryForm");
        var bytes = new byte[8 + values.Length * 4];
        bytes[0] = 1; bytes[1] = (byte)values.Length;
        for (var i = 0; i < 6; i++) bytes[2 + i] = (byte)(authority >> (8 * (5 - i)));
        for (var i = 0; i < values.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8 + 4 * i), values[i]);
        Sid.TryRead(bytes, out var parsed, out _);
        _sid = parsed!;
    }

    private static bool TryUnsigned(string text, ulong maximum, out ulong value, bool saturate = false)
    {
        value = 0;
        var radix = 10u;
        var start = 0;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { radix = 16; start = 2; }
        if (start == text.Length) return false;
        for (var i = start; i < text.Length; i++)
        {
            var c = text[i];
            var digit = c is >= '0' and <= '9' ? c - '0'
                : c is >= 'a' and <= 'f' ? c - 'a' + 10
                : c is >= 'A' and <= 'F' ? c - 'A' + 10 : -1;
            if (digit < 0 || digit >= radix) return false;
            if (value > (maximum - (uint)digit) / radix)
            {
                if (!saturate) return false;
                value = maximum;
            }
            else value = value * radix + (uint)digit;
        }
        return true;
    }

    public SecurityIdentifier(byte[] binaryForm, int offset)
    {
        ArgumentNullException.ThrowIfNull(binaryForm);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (binaryForm.Length - (long)offset < MinBinaryLength)
            throw new ArgumentOutOfRangeException(nameof(binaryForm), "The array is too small for a SID header.");
        if (!Sid.TryRead(binaryForm.AsSpan(offset), out var sid, out _))
            throw new ArgumentException("The binary SID is invalid or incomplete.", nameof(binaryForm));
        _sid = sid!;
    }

    public int BinaryLength => _sid.BinaryLength;
    public SecurityIdentifier? AccountDomainSid
    {
        get
        {
            if (!IsAccountSid()) return null;
            var bytes = _sid.AsSpan()[..24].ToArray();
            bytes[1] = 4;
            return new SecurityIdentifier(bytes, 0);
        }
    }
    public bool IsAccountSid() => _sid.IdentifierAuthority == 5 && _sid.SubAuthorityCount >= 4
        && _sid.GetSubAuthority(0) == 21;
    public bool IsEqualDomainSid(SecurityIdentifier sid)
    {
#if NET10_0_OR_GREATER
        if (sid is null) return false;
#else
        ArgumentNullException.ThrowIfNull(sid);
#endif
        if (_sid.IdentifierAuthority != 5 || sid._sid.IdentifierAuthority != 5) return false;
        if (IsAccountSid() && sid.IsAccountSid())
            return _sid.AsSpan().Slice(8, 16).SequenceEqual(sid._sid.AsSpan().Slice(8, 16));
        return _sid.SubAuthorityCount >= 1 && sid._sid.SubAuthorityCount >= 1
            && _sid.GetSubAuthority(0) == 32 && sid._sid.GetSubAuthority(0) == 32;
    }
    public override string Value => _sid.ToString();
    public override string ToString() => Value;
    public void GetBinaryForm(byte[] binaryForm, int offset) => _sid.ToArray().CopyTo(binaryForm, offset);
    public override bool Equals(object? o) => o is SecurityIdentifier sid && _sid.Equals(sid._sid);
    public bool Equals(SecurityIdentifier? sid) => sid is not null && _sid.Equals(sid._sid);
    public override int GetHashCode()
    {
        // Match the managed Microsoft value hash; no randomized process state participates.
        var hash = ((long)_sid.IdentifierAuthority).GetHashCode();
        for (var i = 0; i < _sid.SubAuthorityCount; i++) hash ^= unchecked((int)_sid.GetSubAuthority(i));
        return hash;
    }
    public int CompareTo(SecurityIdentifier? sid)
    {
        if (sid is null) return 1;
        var comparison = _sid.IdentifierAuthority.CompareTo(sid._sid.IdentifierAuthority);
        if (comparison != 0) return comparison;
        comparison = _sid.SubAuthorityCount.CompareTo(sid._sid.SubAuthorityCount);
        if (comparison != 0) return comparison;
        for (var i = 0; i < _sid.SubAuthorityCount; i++)
        {
            // The native managed contract uses unchecked signed subtraction, not uint ordering.
            comparison = unchecked((int)_sid.GetSubAuthority(i) - (int)sid._sid.GetSubAuthority(i));
            if (comparison != 0) return comparison;
        }
        return 0;
    }
    public override bool IsValidTargetType(Type targetType) => targetType == typeof(SecurityIdentifier) || targetType == typeof(NTAccount);
    public override IdentityReference Translate(Type targetType) => TranslateDetached(targetType);
    public static bool operator ==(SecurityIdentifier? left, SecurityIdentifier? right) => ReferenceEquals(left, right) || left is not null && left.Equals(right);
    public static bool operator !=(SecurityIdentifier? left, SecurityIdentifier? right) => !(left == right);
}
