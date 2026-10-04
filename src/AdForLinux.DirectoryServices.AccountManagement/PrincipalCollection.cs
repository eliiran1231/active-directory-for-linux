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
    private DirectoryEntry? _retainedEntry;
    private readonly List<string> _insertedValuesCompleted = new();
    private readonly List<string> _insertedValuesPending = new();
    private readonly List<string> _removedValuesCompleted = new();
    private readonly List<string> _removedValuesPending = new();
    private bool _clearCompleted;
    private bool _clearPending;
    private bool _disposed;
    private int _version;
    private List<string>? _primaryGroupMemberDns;
    private List<string>? _smallGroupMemberDns;
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

    bool ICollection.IsSynchronized => IsSynchronized;

    object ICollection.SyncRoot => SyncRoot;

    public int Count
    {
        get
        {
            CheckDisposed();
            EnsureReadableMembers();
            return EffectiveMembers().Count;
        }
    }

    public void Add(UserPrincipal user) => Add((Principal)user);

    public void Add(GroupPrincipal group) => Add((Principal)group);

    public void Add(ComputerPrincipal computer) => Add((Principal)computer);

    public void Add(Principal principal)
    {
        CheckDisposed();
        ArgumentNullException.ThrowIfNull(principal);
        _group.EnsureMembersUsable();
        var value = RequireMembershipValue(principal);
        if ((_group.IsPersisted && principal.IsPersisted && principal.IsPrimaryGroup(_group)) || ContainsValue(value))
        {
            throw new PrincipalExistsException(
                "The principal already exists in the collection.");
        }

        _memberSources[value] = new MemberReference(
            value, principal.DistinguishedName, principal.Context, principal);
        if (RemoveValue(_removedValuesPending, value))
        {
            AddValue(_insertedValuesCompleted, value);
        }
        else
        {
            AddValue(_insertedValuesPending, value);
            RemoveValue(_removedValuesCompleted, value);
        }
        _version++;
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

        var principal = Principal.FindByIdentity(context, identityType, identityValue)
            ?? throw new NoMatchingPrincipalException(
                "No principal matched the supplied identity.");
        try
        {
            Add(principal);
        }
        catch
        {
            principal.Dispose();
            throw;
        }
    }

    public bool Remove(UserPrincipal user) => Remove((Principal)user);

    public bool Remove(GroupPrincipal group) => Remove((Principal)group);

    public bool Remove(ComputerPrincipal computer) => Remove((Principal)computer);

    public bool Remove(Principal principal)
    {
        CheckDisposed();
        ArgumentNullException.ThrowIfNull(principal);
        _group.EnsureMembersUsable();
        var value = RequireMembershipValue(principal);
        if (_group.IsPersisted && principal.IsPersisted && principal.IsPrimaryGroup(_group))
        {
            throw new InvalidOperationException(
                "The principal cannot be removed because this is its primary group.");
        }

        if (RemoveValue(_insertedValuesPending, value))
        {
            AddValue(_removedValuesCompleted, value);
            _version++;
            return true;
        }

        if (!ContainsValue(value))
        {
            return false;
        }

        AddValue(_removedValuesPending, value);
        RemoveValue(_insertedValuesCompleted, value);
        _version++;
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
        ArgumentNullException.ThrowIfNull(principal);
        if (_insertedValuesPending.Any(value => SourceFor(value).Principal?.Equals(principal) == true))
            return true;
        if (!_group.IsPersisted)
        {
            _ = principal.DistinguishedName;
            return false;
        }
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
        _version++;
    }

    public void CopyTo(Principal[] array, int index) =>
        ((ICollection)this).CopyTo(array, index);

    void ICollection.CopyTo(Array array, int index)
    {
        CheckDisposed();
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        ArgumentNullException.ThrowIfNull(array);
        if (array.Rank != 1)
        {
            throw new ArgumentException("The array must be one-dimensional.");
        }

        if (index >= array.GetLength(0))
        {
            throw new ArgumentException("The index is outside the array.");
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

        // Resolve pending objects only at Save. Unsaved members can be staged,
        // but every member must have a directory identity before any LDAP write.
        var inserted = _insertedValuesPending.Select(value =>
        {
            var source = SourceFor(value);
            return source.Principal is null
                ? value
                : GroupMembershipConverter.ForPrincipal(_group, source.Principal);
        }).ToList();
        var toRemove = _clearPending
            ? CurrentDirectMemberDns()
            : _removedValuesPending.ToList();
        _group.RequireEntry().ApplyValueChanges(
            "member", inserted, toRemove);

        foreach (var dn in _removedValuesPending)
        {
            AddValue(_removedValuesCompleted, dn);
        }

        _removedValuesPending.Clear();
        for (var index = 0; index < _insertedValuesPending.Count; index++)
        {
            var oldValue = _insertedValuesPending[index];
            var value = inserted[index];
            var source = SourceFor(oldValue);
            _memberSources.Remove(oldValue);
            _memberSources[value] = source with
            {
                Value = value,
                DistinguishedName = source.Principal?.DistinguishedName ?? source.DistinguishedName,
            };
            AddValue(_insertedValuesCompleted, value);
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
        return new PrincipalCollectionEnumerator(this);
    }

    private IEnumerable<Principal> EnumerateMembers()
    {
        EnsureReadableMembers();
        foreach (var member in EffectiveMembers())
        {
            if (member.Principal is not null)
            {
                yield return member.Principal;
                continue;
            }
            var entry = member.Context.CreateDirectoryEntry(member.DistinguishedName!);
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
        _retainedEntry?.Dispose();
        // Inserted principals can escape through enumeration, including those
        // resolved by identity-based Add. Their lifetime belongs to the caller.
        _disposed = true;
    }

    private void EnsureReadableMembers()
    {
        if (_group.IsDeleted && _retainedEntry is not null)
        {
            // A retained collection reaches its old directory binding when
            // enumerated, whereas argument checks and cursor creation stay local.
            _retainedEntry.RefreshCache(new[] { "member" });
        }
        _group.EnsureMembersUsable();
        if (_retainedEntry is null && _group.IsPersisted)
        {
            var entry = _group.RequireEntry();
            _retainedEntry = entry.CreateEntryForDn(entry.DistinguishedName);
        }
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
        private IEnumerator<Principal> _inner;
        private readonly PrincipalCollection _collection;
        private readonly int _version;
        private bool _hasCurrent;
        private bool _disposed;

        internal PrincipalCollectionEnumerator(PrincipalCollection collection)
        {
            _collection = collection;
            _version = collection._version;
            _inner = collection.EnumerateMembers().GetEnumerator();
        }

        public Principal Current
        {
            get
            {
                CheckDisposed();
                if (!_hasCurrent)
                {
                    _collection.CheckDisposed();
                    throw new InvalidOperationException("The enumerator is not positioned on a member.");
                }
                return _inner.Current;
            }
        }

        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            CheckDisposed();
            _collection.CheckDisposed();
            CheckChanged();
            _hasCurrent = _inner.MoveNext();
            return _hasCurrent;
        }

        public void Reset()
        {
            CheckDisposed();
            CheckChanged();
            // Compiler-generated iterators do not support Reset. Start a new
            // traversal without taking ownership of previously yielded principals.
            _inner.Dispose();
            _inner = _collection.EnumerateMembers().GetEnumerator();
            _hasCurrent = false;
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

        private void CheckChanged()
        {
            if (_version != _collection._version)
            {
                throw new InvalidOperationException("The collection changed during enumeration.");
            }
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

        var storedDns = _smallGroupMemberDns ?? CurrentDirectMemberDns();
        if (_group.IsPersisted && storedDns.Count < 1500) _smallGroupMemberDns = storedDns;
        return storedDns.Any(dn => GroupMembershipConverter.ForStoredDistinguishedName(dn)
            .Equals(value, StringComparison.OrdinalIgnoreCase));
    }

    private List<string> CurrentDirectMemberDns()
    {
        // Enumeration and writes use the current membership. Only the optimized
        // small-group Contains path retains the original lookup snapshot.
        return AccountManagementExceptionTranslator.Execute(() =>
            !_group.IsPersisted ? new List<string>()
                : RangedAttributeReader.Read(_group.RequireEntry(), "member")
                    .Select(value => value.ToString()!).ToList());
    }

    private List<MemberReference> CurrentDirectMembers()
    {
        var members = new List<MemberReference>();
        foreach (var dn in CurrentDirectMemberDns())
        {
            var value = GroupMembershipConverter.ForStoredDistinguishedName(dn);
            AddMember(members, new MemberReference(value, dn, _group.Context));
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
            // Completed inserts are directory-backed members. Enumeration must
            // not borrow the caller's original (possibly disposed) principal.
            AddMember(members, SourceFor(value) with { Principal = null });
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
        // Read the identity to retain disposed/deleted principal validation.
        var dn = principal.DistinguishedName;
        // A retained unsaved member can acquire a stored identity before the
        // group is saved. Match equivalent wrappers against that live principal,
        // keeping all pending/completed operations on its original staging key.
        var retained = _memberSources.Values.FirstOrDefault(source =>
            source.Principal is not null && source.Principal.Equals(principal));
        if (retained is not null) return retained.Value;
        if (dn is not null) return GroupMembershipConverter.ForPrincipal(_group, principal);

        var value = "pending:" + Guid.NewGuid().ToString("N");
        _memberSources[value] = new MemberReference(value, null, principal.Context, principal);
        return value;
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
        string? DistinguishedName,
        PrincipalContext Context,
        Principal? Principal = null);
}
