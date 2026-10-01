using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The values of one attribute in a <see cref="SearchResult"/>. Read-only,
/// like Microsoft's type. Typical use: <c>result.Properties["cn"][0]</c>.
/// </summary>
public class ResultPropertyValueCollection : ReadOnlyCollectionBase, IEnumerable<object?>
{
    internal ResultPropertyValueCollection(IReadOnlyList<object> values)
    {
        foreach (var value in values)
        {
            InnerList.Add(value);
        }
    }

    /// <summary>Gets the value at an index.</summary>
    public object this[int index]
    {
        get
        {
            var value = InnerList[index];
            if (value is Exception exception)
            {
                throw exception;
            }

            return value!;
        }
    }

    /// <summary>True if the value is present.</summary>
    public bool Contains(object? value) => InnerList.Contains(value);

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object?[] values, int index) => InnerList.CopyTo(values, index);

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object? value) => InnerList.IndexOf(value);

    public new IEnumerator<object?> GetEnumerator() => new ValueEnumerator(InnerList.GetEnumerator());

    // Preserve ArrayList's position validation and Reset support for generic callers.
    private sealed class ValueEnumerator(IEnumerator enumerator) : IEnumerator<object?>
    {
        public object? Current => enumerator.Current;

        public bool MoveNext() => enumerator.MoveNext();

        public void Reset() => enumerator.Reset();

        public void Dispose() { }
    }
}
