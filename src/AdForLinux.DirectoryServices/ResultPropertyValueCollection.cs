using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The values of one attribute in a <see cref="SearchResult"/>. Read-only,
/// like Microsoft's type. Typical use: <c>result.Properties["cn"][0]</c>.
/// </summary>
public sealed class ResultPropertyValueCollection : ReadOnlyCollectionBase, IEnumerable<object>
{
    internal ResultPropertyValueCollection(IReadOnlyList<object> values)
    {
        foreach (var value in values)
        {
            InnerList.Add(value);
        }
    }

    /// <summary>Gets the value at an index.</summary>
    public object this[int index] => InnerList[index]!;

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => InnerList.Contains(value);

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object[] array, int index) => InnerList.CopyTo(array, index);

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object value) => InnerList.IndexOf(value);

    public new IEnumerator<object> GetEnumerator() => InnerList.Cast<object>().GetEnumerator();
}
