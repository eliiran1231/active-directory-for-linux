using Xunit;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Collects differences between the real Microsoft library and our clone, then
/// reports them all at once. Comparing everything in one go is much easier to
/// read than failing on the first difference.
/// </summary>
public sealed class Comparison
{
    private readonly List<string> _differences = new();
    private readonly string _subject;

    public Comparison(string subject)
    {
        _subject = subject;
    }

    /// <summary>Compares one property from both libraries.</summary>
    public Comparison Check(string propertyName, object? microsoft, object? adForLinux)
    {
        if (!ValuesMatch(microsoft, adForLinux))
        {
            _differences.Add(
                $"  {propertyName}: Microsoft = {Show(microsoft)} | AdForLinux = {Show(adForLinux)}");
        }

        return this;
    }

    /// <summary>Compares two sets of strings, ignoring order and case.</summary>
    public Comparison CheckSet(string propertyName, IEnumerable<string?> microsoft, IEnumerable<string?> adForLinux)
    {
        var left = microsoft.Where(v => v is not null).Select(v => v!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var right = adForLinux.Where(v => v is not null).Select(v => v!).ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!left.SetEquals(right))
        {
            var onlyMicrosoft = left.Except(right, StringComparer.OrdinalIgnoreCase).ToList();
            var onlyOurs = right.Except(left, StringComparer.OrdinalIgnoreCase).ToList();
            _differences.Add(
                $"  {propertyName}: only in Microsoft = [{string.Join(", ", onlyMicrosoft)}] | " +
                $"only in AdForLinux = [{string.Join(", ", onlyOurs)}]");
        }

        return this;
    }

    /// <summary>Fails the test if anything differed.</summary>
    public void Assert()
    {
        Xunit.Assert.True(
            _differences.Count == 0,
            $"{_differences.Count} difference(s) for {_subject}:{Environment.NewLine}" +
            string.Join(Environment.NewLine, _differences));
    }

    private static bool ValuesMatch(object? left, object? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        if (left is byte[] leftBytes && right is byte[] rightBytes)
        {
            return leftBytes.AsSpan().SequenceEqual(rightBytes);
        }

        if (left is string leftText && right is string rightText)
        {
            return string.Equals(leftText, rightText, StringComparison.Ordinal);
        }

        if (left is DateTime leftTime && right is DateTime rightTime)
        {
            // Compare the instant, not the Kind, so UTC and local both work.
            return leftTime.ToUniversalTime() == rightTime.ToUniversalTime();
        }

        return Equals(left, right);
    }

    private static string Show(object? value) => value switch
    {
        null => "(null)",
        byte[] bytes => $"byte[{bytes.Length}]",
        DateTime time => time.ToUniversalTime().ToString("O"),
        _ => $"\"{value}\"",
    };
}
