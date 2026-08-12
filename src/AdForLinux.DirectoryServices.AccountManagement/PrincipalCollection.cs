using System.Collections;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The members of a <see cref="GroupPrincipal"/>, like Microsoft's
/// <c>PrincipalCollection</c>. Changes are staged until the owning group is saved.
/// </summary>
public class PrincipalCollection : ICollection<Principal>, ICollection
{
    private readonly GroupPrincipal _group;
    private readonly List<string> _insertedValuesCompleted = new();
    private readonly List<string> _insertedValuesPending = new();
    private readonly List<string> _removedValuesCompleted = new();
    private readonly List<string> _removedValuesPending = new();
    private bool _clearCompleted;
    private bool _clearPending;
    private List<string>? _primaryGroupMemberDns;

    internal PrincipalCollection(GroupPrincipal group)
    {
        _group = group;
    }

    internal bool HasPendingChanges =>
        _insertedValuesPending.Count > 0
        || _removedValuesPending.Count > 0
        || _clearPending;

    public bool IsReadOnly => false;

    public bool IsSynchronized => false;

    public object SyncRoot => this;

    public int Count
    {
        get
        {
            _group.EnsureMembersUsable();
            return EffectiveMemberDns().Count;
        }
    }

    public void Add(UserPrincipal user) => Add((Principal)user);

    public void Add(GroupPrincipal group) => Add((Principal)group);

    public void Add(ComputerPrincipal computer) => Add((Principal)computer);

    public void Add(Principal principal)
    {
        _group.EnsureMembersUsable();
        var dn = RequireDn(principal);
        if (principal.IsPrimaryGroup(_group) || ContainsDn(dn))
        {
            throw new PrincipalExistsException(
                "The principal already exists in the collection.");
        }

        if (RemoveDn(_removedValuesPending, dn))
        {
            AddDn(_insertedValuesCompleted, dn);
        }
        else
        {
            AddDn(_insertedValuesPending, dn);
            RemoveDn(_removedValuesCompleted, dn);
        }
    }

    public void Add(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        _group.EnsureMembersUsable();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identityValue);

        using var principal = Principal.FindByIdentity(context, identityType, identityValue)
            ?? throw new NoMatchingPrincipalException(
                "No principal matched the supplied identity.");
        Add(principal);
    }

    public bool Remove(UserPrincipal user) => Remove((Principal)user);

    public bool Remove(GroupPrincipal group) => Remove((Principal)group);

    public bool Remove(ComputerPrincipal computer) => Remove((Principal)computer);

    public bool Remove(Principal principal)
    {
        _group.EnsureMembersUsable();
        var dn = RequireDn(principal);
        if (principal.IsPrimaryGroup(_group))
        {
            throw new InvalidOperationException(
                "The principal cannot be removed because this is its primary group.");
        }

        if (RemoveDn(_insertedValuesPending, dn))
        {
            AddDn(_removedValuesCompleted, dn);
            return true;
        }

        if (!ContainsDn(dn))
        {
            return false;
        }

        AddDn(_removedValuesPending, dn);
        RemoveDn(_insertedValuesCompleted, dn);
        return true;
    }

    public bool Remove(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        _group.EnsureMembersUsable();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identityValue);

        using var principal = Principal.FindByIdentity(context, identityType, identityValue)
            ?? throw new NoMatchingPrincipalException(
                "No principal matched the supplied identity.");
        return Remove(principal);
    }

    public bool Contains(UserPrincipal user) => Contains((Principal)user);

    public bool Contains(GroupPrincipal group) => Contains((Principal)group);

    public bool Contains(ComputerPrincipal computer) => Contains((Principal)computer);

    public bool Contains(Principal principal)
    {
        _group.EnsureMembersUsable();
        var dn = RequireDn(principal);
        return principal.IsPrimaryGroup(_group) || ContainsDn(dn);
    }

    public bool Contains(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        _group.EnsureMembersUsable();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identityValue);

        using var principal = Principal.FindByIdentity(context, identityType, identityValue);
        return principal is not null && Contains(principal);
    }

    public void Clear()
    {
        _group.EnsureMembersUsable();
        if (_group.HasPrimaryGroupMembers())
        {
            throw new InvalidOperationException(
                "The group cannot be cleared because one or more principals use it as their primary group.");
        }

        _insertedValuesPending.Clear();
        _removedValuesPending.Clear();
        _insertedValuesCompleted.Clear();
        _removedValuesCompleted.Clear();
        _clearPending = true;
    }

    public void CopyTo(Principal[] array, int index) =>
        ((ICollection)this).CopyTo(array, index);

    void ICollection.CopyTo(Array array, int index)
    {
        _group.EnsureMembersUsable();
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        ArgumentNullException.ThrowIfNull(array);
        if (array.Rank != 1)
        {
            throw new ArgumentException("The array must be one-dimensional.", nameof(array));
        }

        if (index >= array.GetLength(0))
        {
            throw new ArgumentException("The index is outside the array.", nameof(index));
        }

        var values = new List<Principal>();
        foreach (var value in this)
        {
            values.Add(value);
        }

        if (array.GetLength(0) - index < values.Count)
        {
            throw new ArgumentException("The destination array is too small.", nameof(array));
        }

        foreach (var value in values)
        {
            array.SetValue(value, index++);
        }
    }

    internal void ApplyChanges()
    {
        if (!HasPendingChanges)
        {
            return;
        }

        var toRemove = _clearPending
            ? CurrentDirectMemberDns()
            : _removedValuesPending.ToList();
        _group.RequireEntry().ApplyValueChanges(
            "member", _insertedValuesPending, toRemove);

        foreach (var dn in _removedValuesPending)
        {
            AddDn(_removedValuesCompleted, dn);
        }

        _removedValuesPending.Clear();
        foreach (var dn in _insertedValuesPending)
        {
            AddDn(_insertedValuesCompleted, dn);
        }

        _insertedValuesPending.Clear();
        if (_clearPending)
        {
            _clearCompleted = true;
            _clearPending = false;
        }

        _group.RequireEntry().RefreshCache();
    }

    public IEnumerator<Principal> GetEnumerator()
    {
        _group.EnsureMembersUsable();
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

    private bool ContainsDn(string dn)
    {
        if (ContainsDn(_insertedValuesCompleted, dn)
            || ContainsDn(_insertedValuesPending, dn))
        {
            return true;
        }

        if (ContainsDn(_removedValuesCompleted, dn)
            || ContainsDn(_removedValuesPending, dn)
            || _clearPending
            || _clearCompleted)
        {
            return false;
        }

        return CurrentDirectMemberDns().Contains(dn, StringComparer.OrdinalIgnoreCase);
    }

    private List<string> CurrentDirectMemberDns() =>
        !_group.IsPersisted
            ? new List<string>()
            : RangedAttributeReader.Read(_group.RequireEntry(), "member")
                .Select(value => value.ToString()!)
                .ToList();

    private List<string> CurrentMemberDns()
    {
        var dns = CurrentDirectMemberDns();
        _primaryGroupMemberDns ??= _group.PrimaryGroupMemberDns().ToList();
        foreach (var dn in _primaryGroupMemberDns)
        {
            AddDn(dns, dn);
        }

        return dns;
    }

    /// <summary>Member DNs with the staged changes applied.</summary>
    private List<string> EffectiveMemberDns()
    {
        var dns = _clearPending || _clearCompleted
            ? new List<string>()
            : CurrentMemberDns();
        dns.RemoveAll(dn =>
            ContainsDn(_removedValuesCompleted, dn)
            || ContainsDn(_removedValuesPending, dn));
        foreach (var dn in _insertedValuesCompleted)
        {
            AddDn(dns, dn);
        }

        foreach (var dn in _insertedValuesPending)
        {
            AddDn(dns, dn);
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

    private static bool ContainsDn(IEnumerable<string> values, string dn) =>
        values.Contains(dn, StringComparer.OrdinalIgnoreCase);

    private static void AddDn(ICollection<string> values, string dn)
    {
        if (!ContainsDn(values, dn))
        {
            values.Add(dn);
        }
    }

    private static bool RemoveDn(ICollection<string> values, string dn)
    {
        var match = values.FirstOrDefault(value =>
            value.Equals(dn, StringComparison.OrdinalIgnoreCase));
        return match is not null && values.Remove(match);
    }
}
