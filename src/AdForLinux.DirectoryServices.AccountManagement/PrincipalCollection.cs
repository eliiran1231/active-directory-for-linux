using System.Collections;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The members of a <see cref="GroupPrincipal"/>, like Microsoft's
/// <c>PrincipalCollection</c>. <see cref="Add"/> and <see cref="Remove"/> stage
/// a change; call <c>group.Save()</c> to write it.
/// </summary>
public sealed class PrincipalCollection : IEnumerable<Principal>
{
    private readonly GroupPrincipal _group;

    // DNs staged since the last save.
    private readonly List<string> _toAdd = new();
    private readonly List<string> _toRemove = new();

    internal PrincipalCollection(GroupPrincipal group)
    {
        _group = group;
    }

    /// <summary>True if there are staged changes not yet saved.</summary>
    internal bool HasPendingChanges => _toAdd.Count > 0 || _toRemove.Count > 0;

    /// <summary>Adds a principal to the group. Save the group to apply it.</summary>
    public void Add(Principal principal)
    {
        var dn = RequireDn(principal);
        _toRemove.Remove(dn);
        if (!_toAdd.Contains(dn, StringComparer.OrdinalIgnoreCase))
        {
            _toAdd.Add(dn);
        }
    }

    /// <summary>Removes a principal from the group. Save the group to apply it.</summary>
    public bool Remove(Principal principal)
    {
        var dn = RequireDn(principal);
        _toAdd.Remove(dn);
        if (!_toRemove.Contains(dn, StringComparer.OrdinalIgnoreCase))
        {
            _toRemove.Add(dn);
        }

        return true;
    }

    /// <summary>
    /// True if the principal is a direct member, counting staged changes.
    /// Only direct members — nested groups are not searched.
    /// </summary>
    public bool Contains(Principal principal)
    {
        var dn = RequireDn(principal);

        if (_toAdd.Contains(dn, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        if (_toRemove.Contains(dn, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        return CurrentMemberDns().Contains(dn, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Removes every member. Save the group to apply it.</summary>
    public void Clear()
    {
        _toAdd.Clear();
        _toRemove.Clear();
        _toRemove.AddRange(CurrentMemberDns());
    }

    /// <summary>Number of members, counting staged changes.</summary>
    public int Count => EffectiveMemberDns().Count;

    /// <summary>Writes the staged changes and forgets them.</summary>
    internal void ApplyChanges()
    {
        if (!HasPendingChanges)
        {
            return;
        }

        _group.RequireEntry().ApplyValueChanges("member", _toAdd, _toRemove);
        _toAdd.Clear();
        _toRemove.Clear();
        _group.RequireEntry().RefreshCache();
    }

    public IEnumerator<Principal> GetEnumerator()
    {
        var context = _group.Context;
        foreach (var dn in EffectiveMemberDns())
        {
            var entry = context.CreateDirectoryEntry(dn);
            var principal = PrincipalFactory.FromEntry(context, entry);
            if (principal is null)
            {
                entry.Dispose();
                continue;
            }

            yield return principal;
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Member DNs as stored on the server right now.</summary>
    private List<string> CurrentMemberDns() =>
        RangedAttributeReader.Read(_group.RequireEntry(), "member")
            .Select(value => value.ToString()!)
            .ToList();

    /// <summary>Member DNs with the staged changes applied.</summary>
    private List<string> EffectiveMemberDns()
    {
        var dns = CurrentMemberDns();
        dns.RemoveAll(dn => _toRemove.Contains(dn, StringComparer.OrdinalIgnoreCase));
        foreach (var dn in _toAdd)
        {
            if (!dns.Contains(dn, StringComparer.OrdinalIgnoreCase))
            {
                dns.Add(dn);
            }
        }

        return dns;
    }

    private static string RequireDn(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.DistinguishedName
            ?? throw new InvalidOperationException(
                "The principal must be saved before it can be used as a group member.");
    }
}
