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
    private bool _disposed;
    private List<string>? _primaryGroupMemberDns;
    private readonly Dictionary<string, MemberReference> _memberSources =
        new(StringComparer.OrdinalIgnoreCase);

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
            CheckDisposed();
            _group.EnsureMembersUsable();
            return EffectiveMembers().Count;
        }
    }

    public void Add(UserPrincipal user) => Add((Principal)user);

    public void Add(GroupPrincipal group) => Add((Principal)group);

    public void Add(ComputerPrincipal computer) => Add((Principal)computer);

    public void Add(Principal principal)
    {
        CheckDisposed();
        _group.EnsureMembersUsable();
        var value = RequireMembershipValue(principal);
        if ((_group.IsPersisted && principal.IsPrimaryGroup(_group)) || ContainsValue(value))
        {
            throw new PrincipalExistsException(
                "The principal already exists in the collection.");
        }

        _memberSources[value] = new MemberReference(
            value, principal.DistinguishedName!, principal.Context);
        if (RemoveValue(_removedValuesPending, value))
        {
            AddValue(_insertedValuesCompleted, value);
        }
        else
        {
            AddValue(_insertedValuesPending, value);
            RemoveValue(_removedValuesCompleted, value);
        }
    }

    public void Add(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        CheckDisposed();
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
        CheckDisposed();
        _group.EnsureMembersUsable();
        var value = RequireMembershipValue(principal);
        if (_group.IsPersisted && principal.IsPrimaryGroup(_group))
        {
            throw new InvalidOperationException(
                "The principal cannot be removed because this is its primary group.");
        }

        if (RemoveValue(_insertedValuesPending, value))
        {
            AddValue(_removedValuesCompleted, value);
            return true;
        }

        if (!ContainsValue(value))
        {
            return false;
        }

        AddValue(_removedValuesPending, value);
        RemoveValue(_insertedValuesCompleted, value);
        return true;
    }

    public bool Remove(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        CheckDisposed();
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
        CheckDisposed();
        _group.EnsureMembersUsable();
        return ContainsValue(RequireMembershipValue(principal));
    }

    public bool Contains(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        CheckDisposed();
        _group.EnsureMembersUsable();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identityValue);

        using var principal = Principal.FindByIdentity(context, identityType, identityValue);
        return principal is not null && Contains(principal);
    }

    public void Clear()
    {
        CheckDisposed();
        _group.EnsureMembersUsable();
        if (_group.IsPersisted && _group.HasPrimaryGroupMembers())
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
        CheckDisposed();
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
            AddValue(_removedValuesCompleted, dn);
        }

        _removedValuesPending.Clear();
        foreach (var dn in _insertedValuesPending)
        {
            AddValue(_insertedValuesCompleted, dn);
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
        CheckDisposed();
        _group.EnsureMembersUsable();
        return new PrincipalCollectionEnumerator(EnumerateMembers().GetEnumerator(), CheckDisposed);
    }

    private IEnumerable<Principal> EnumerateMembers()
    {
        foreach (var member in EffectiveMembers())
        {
            var entry = member.Context.CreateDirectoryEntry(member.DistinguishedName);
            var principal = PrincipalFactory.FromEntry(member.Context, entry);
            if (principal is null)
            {
                entry.Dispose();
                continue;
            }

            yield return principal;
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    internal void Dispose()
    {
        _disposed = true;
    }

    private void CheckDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(PrincipalCollection));
        }
    }

    private sealed class PrincipalCollectionEnumerator : IEnumerator<Principal>
    {
        private readonly IEnumerator<Principal> _inner;
        private readonly Action _checkCollection;
        private bool _disposed;

        internal PrincipalCollectionEnumerator(
            IEnumerator<Principal> inner,
            Action checkCollection)
        {
            _inner = inner;
            _checkCollection = checkCollection;
        }

        public Principal Current
        {
            get
            {
                CheckDisposed();
                _checkCollection();
                return _inner.Current;
            }
        }

        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            CheckDisposed();
            _checkCollection();
            return _inner.MoveNext();
        }

        public void Reset()
        {
            CheckDisposed();
            _checkCollection();
            _inner.Reset();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _inner.Dispose();
            _disposed = true;
        }

        private void CheckDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(PrincipalCollectionEnumerator));
            }
        }
    }

    private bool ContainsValue(string value)
    {
        if (ContainsValue(_insertedValuesCompleted, value)
            || ContainsValue(_insertedValuesPending, value))
        {
            return true;
        }

        if (ContainsValue(_removedValuesCompleted, value)
            || ContainsValue(_removedValuesPending, value)
            || _clearPending
            || _clearCompleted)
        {
            return false;
        }

        return CurrentDirectMembers().Any(member =>
            member.Value.Equals(value, StringComparison.OrdinalIgnoreCase));
    }

    private List<string> CurrentDirectMemberDns() =>
        AccountManagementExceptionTranslator.Execute(() =>
            !_group.IsPersisted
                ? new List<string>()
                : RangedAttributeReader.Read(_group.RequireEntry(), "member")
                    .Select(value => value.ToString()!)
                    .ToList());

    private List<MemberReference> CurrentDirectMembers()
    {
        var members = new List<MemberReference>();
        foreach (var dn in CurrentDirectMemberDns())
        {
            using var entry = _group.Context.CreateDirectoryEntry(dn);
            var principal = PrincipalFactory.FromEntry(_group.Context, entry);
            if (principal is null)
            {
                AddMember(members, new MemberReference(dn, dn, _group.Context));
                continue;
            }

            using (principal)
            {
                var value = principal is ForeignSecurityPrincipal
                    ? GroupMembershipConverter.SelectValue(
                        isForeignSecurityPrincipal: true,
                        sameForest: true,
                        dn,
                        principal.GetSidBytes())
                    : dn;
                AddMember(members, new MemberReference(value, dn, _group.Context));
            }
        }

        return members;
    }

    private List<MemberReference> CurrentMembers()
    {
        var members = CurrentDirectMembers();
        _primaryGroupMemberDns ??= AccountManagementExceptionTranslator.Execute(
            () => _group.PrimaryGroupMemberDns().ToList());
        foreach (var dn in _primaryGroupMemberDns)
        {
            AddMember(members, new MemberReference(dn, dn, _group.Context));
        }

        return members;
    }

    /// <summary>Member references with the staged changes applied.</summary>
    private List<MemberReference> EffectiveMembers()
    {
        var members = _clearPending || _clearCompleted
            ? new List<MemberReference>()
            : CurrentMembers();
        members.RemoveAll(member =>
            ContainsValue(_removedValuesCompleted, member.Value)
            || ContainsValue(_removedValuesPending, member.Value));
        foreach (var value in _insertedValuesCompleted)
        {
            AddMember(members, SourceFor(value));
        }

        foreach (var value in _insertedValuesPending)
        {
            AddMember(members, SourceFor(value));
        }

        return members;
    }

    private string RequireMembershipValue(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return GroupMembershipConverter.ForPrincipal(_group, principal);
    }

    private MemberReference SourceFor(string value) =>
        _memberSources.TryGetValue(value, out var source)
            ? source
            : throw new InvalidOperationException("The staged group member source is unavailable.");

    private static bool ContainsValue(IEnumerable<string> values, string value) =>
        values.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static void AddValue(ICollection<string> values, string value)
    {
        if (!ContainsValue(values, value))
        {
            values.Add(value);
        }
    }

    private static bool RemoveValue(ICollection<string> values, string value)
    {
        var match = values.FirstOrDefault(candidate =>
            candidate.Equals(value, StringComparison.OrdinalIgnoreCase));
        return match is not null && values.Remove(match);
    }

    private static void AddMember(
        ICollection<MemberReference> members,
        MemberReference member)
    {
        if (!members.Any(candidate =>
                candidate.Value.Equals(member.Value, StringComparison.OrdinalIgnoreCase)))
        {
            members.Add(member);
        }
    }

    private sealed record MemberReference(
        string Value,
        string DistinguishedName,
        PrincipalContext Context);
}
