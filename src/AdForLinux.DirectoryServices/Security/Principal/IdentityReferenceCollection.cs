// Collection and enumerator contracts adapted from dotnet/runtime v9.0.0 IRCollection.cs.
// Copyright (c) .NET Foundation and Contributors. MIT license: ../AccessControl/RULES-LICENSE.txt.
using System.Collections;

namespace AdForLinux.Security.Principal;

/// <summary>A mutable collection of identity values. Collection operations do not resolve names.</summary>
public class IdentityReferenceCollection : ICollection<IdentityReference>
{
    private readonly List<IdentityReference> _identities;

    public IdentityReferenceCollection() : this(0) { }
    public IdentityReferenceCollection(int capacity) => _identities = new List<IdentityReference>(capacity);

    public int Count => _identities.Count;
    bool ICollection<IdentityReference>.IsReadOnly => false;

    public IdentityReference this[int index]
    {
        get => _identities[index];
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _identities[index] = value;
        }
    }

    public void Add(IdentityReference identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _identities.Add(identity);
    }

    public bool Contains(IdentityReference identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return _identities.Contains(identity);
    }

    public bool Remove(IdentityReference identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return Contains(identity) && _identities.Remove(identity);
    }

    public void Clear() => _identities.Clear();
    public void CopyTo(IdentityReference[] array, int offset) => _identities.CopyTo(0, array, offset, Count);
    public IEnumerator<IdentityReference> GetEnumerator() => new IdentityReferenceEnumerator(this);
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public IdentityReferenceCollection Translate(Type targetType) => Translate(targetType, false);

    public IdentityReferenceCollection Translate(Type targetType, bool forceSuccess)
    {
        ArgumentNullException.ThrowIfNull(targetType);
        if (!targetType.IsSubclassOf(typeof(IdentityReference)))
            throw new ArgumentException("The targetType parameter must be of IdentityReference type.", nameof(targetType));

        // Empty/same-kind translation creates a new collection retaining element identity.
        // Cross-kind translation has the same explicit staging boundary as the values:
        // no resolver authority is inferred, no lookup is attempted, and forceSuccess
        // does not turn the absence of a resolver into a native mapping-failure claim.
        if (_identities.Any(identity => identity.GetType() != targetType))
            throw new NotSupportedException("Cross-kind translation requires the pending context-bound identity resolver.");

        var result = new IdentityReferenceCollection(Count);
        foreach (var identity in _identities) result.Add(identity);
        return result;
    }

    // The native enumerator reads the live list by index, including Current. It neither
    // caches the current element nor invalidates itself when the collection changes.
    private sealed class IdentityReferenceEnumerator(IdentityReferenceCollection collection) : IEnumerator<IdentityReference>
    {
        private int _current = -1;
        public IdentityReference Current => collection._identities[_current];
        object IEnumerator.Current => Current;
        public bool MoveNext() => ++_current < collection.Count;
        public void Reset() => _current = -1;
        public void Dispose() { }
    }
}
