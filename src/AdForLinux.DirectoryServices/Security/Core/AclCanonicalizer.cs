namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>Recorded ordering/compaction of already validated known ACEs only.</summary>
internal static class AclCanonicalizer
{
    internal static void Sort(List<Ace> aces, bool isDacl)
        => Sort(aces, ace => ace, isDacl);

    internal static void Sort<T>(List<T> values, Func<T, Ace> getAce, bool isDacl)
    {
        var entries = values.Select((value, index) => (Value: value, Ace: getAce(value), OriginalIndex: index)).ToArray();
        var pending = new Stack<(int Left, int Right)>();
        pending.Push((0, entries.Length - 1));
        // Preserve Microsoft's pivot/tie behavior without recursive stack growth.
        while (pending.TryPop(out var range))
        {
            var (left, right) = range;
            if (left >= right) continue;
            var pivot = entries[left];
            while (left < right)
            {
                while (left < right && Compare(entries[right], pivot) >= 0) right--;
                if (left != right) entries[left++] = entries[right];
                while (left < right && Compare(entries[left], pivot) <= 0) left++;
                if (left != right) entries[right--] = entries[left];
            }
            entries[left] = pivot;
            pending.Push((left + 1, range.Right));
            pending.Push((range.Left, left - 1));
        }
        for (var i = 0; i < entries.Length; i++) values[i] = entries[i].Value;

        int Priority((T Value, Ace Ace, int OriginalIndex) entry) => (entry.Ace.AceFlags & 0x10) != 0
            ? 2 * ushort.MaxValue + entry.OriginalIndex
            : (isDacl && entry.Ace.AceType is not (1 or 6) ? 2 : 0)
                + (entry.Ace.Kind is AceKind.ObjectAccess or AceKind.ObjectAudit ? 1 : 0);
        int Compare((T Value, Ace Ace, int OriginalIndex) a, (T Value, Ace Ace, int OriginalIndex) b)
        {
            var priority = Priority(a).CompareTo(Priority(b));
            if (priority != 0) return priority;
            var x = a.Ace.Sid!;
            var y = b.Ace.Sid!;
            var value = x.IdentifierAuthority.CompareTo(y.IdentifierAuthority);
            if (value != 0) return value;
            value = x.SubAuthorityCount.CompareTo(y.SubAuthorityCount);
            if (value != 0) return value;
            for (var i = 0; i < x.SubAuthorityCount; i++)
            {
                value = x.GetSubAuthority(i).CompareTo(y.GetSubAuthority(i));
                if (value != 0) return value;
            }
            return 0;
        }
    }

    // Import performs one adjacent pass, not fixed-point minimization. Live edits do not
    // invoke this. Return identities whose raw entries lost one-to-one correspondence.
    internal static IReadOnlyList<Sid> Compact(List<Ace> aces)
    {
        var identities = new List<Sid>();
        for (var i = 0; i < aces.Count - 1; i++)
        {
            if (!AclMutationEngine.TryMerge(aces[i], aces[i + 1], out var merged)) continue;
            identities.Add(aces[i].Sid!);
            aces[i] = merged;
            aces.RemoveAt(i + 1);
        }
        return identities;
    }
}
