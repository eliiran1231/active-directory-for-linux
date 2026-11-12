using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Every entry is disposed before an operation that could bind. Microsoft's
// Bind rejects disposed entries before ADSI/DNS/default-domain discovery.
// Null-parent overloads dereference the parent before any provider operation.
[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilityDisposedEntryValidationComparisonTests
{
    [Theory]
    [InlineData("refresh-null")]
    [InlineData("refresh-null-element")]
    [InlineData("refresh-empty")]
    [InlineData("refresh-valid")]
    [InlineData("move-null-parent")]
    [InlineData("move-empty-name")]
    [InlineData("move-whitespace-name")]
    [InlineData("move-valid-name")]
    [InlineData("copy-null-parent")]
    public void Disposed_entry_and_invalid_argument_precedence_match_microsoft(string operation)
    {
        const string path = "LDAP://unused.example.test/CN=source,DC=example,DC=test";
        const string parentPath = "LDAP://unused.example.test/DC=example,DC=test";
        using var microsoft = new Ms.DirectoryEntry(path);
        using var ours = new Ours.DirectoryEntry(path);
        using var microsoftParent = new Ms.DirectoryEntry(parentPath);
        using var ourParent = new Ours.DirectoryEntry(parentPath);
        microsoft.Dispose();
        ours.Dispose();
        microsoftParent.Dispose();
        ourParent.Dispose();

        var comparison = new Comparison($"Disposed DirectoryEntry validation: {operation}");
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var expected = Record.Exception(() => Invoke(microsoft, microsoftParent, operation));
            var actual = Record.Exception(() => Invoke(ours, ourParent, operation));
            // The oracle must reject the operation; an accidental no-op is not
            // evidence for this validation-order contract.
            Assert.NotNull(expected);
            comparison.Check($"attempt {attempt}: exception", expected.GetType().Name, actual?.GetType().Name)
                .Check($"attempt {attempt}: parameter", (expected as ArgumentException)?.ParamName,
                    (actual as ArgumentException)?.ParamName)
                .Check($"attempt {attempt}: HRESULT", expected.HResult, actual?.HResult)
                .Check($"attempt {attempt}: disposed object", (expected as ObjectDisposedException)?.ObjectName,
                    (actual as ObjectDisposedException)?.ObjectName);
        }
        comparison.Check("source path", microsoft.Path, ours.Path)
            .Check("parent path", microsoftParent.Path, ourParent.Path).Assert();
    }

    // Source: dotnet/runtime v9.0.0 DirectoryEntry.cs, RefreshCache(string[]),
    // MoveTo, CopyTo and Bind. No fabricated provider or private state is used.
    private static void Invoke(Ms.DirectoryEntry entry, Ms.DirectoryEntry parent, string operation)
    {
        switch (operation)
        {
            case "refresh-null": entry.RefreshCache(null!); break;
            case "refresh-null-element": entry.RefreshCache(new string[] { null! }); break;
            case "refresh-empty": entry.RefreshCache(Array.Empty<string>()); break;
            case "refresh-valid": entry.RefreshCache(new[] { "description" }); break;
            case "move-null-parent": entry.MoveTo(null!); break;
            case "move-empty-name": entry.MoveTo(parent, ""); break;
            case "move-whitespace-name": entry.MoveTo(parent, " \t "); break;
            case "move-valid-name": entry.MoveTo(parent, "CN=renamed"); break;
            case "copy-null-parent": using (entry.CopyTo(null!)) { } break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static void Invoke(Ours.DirectoryEntry entry, Ours.DirectoryEntry parent, string operation)
    {
        switch (operation)
        {
            case "refresh-null": entry.RefreshCache(null!); break;
            case "refresh-null-element": entry.RefreshCache(new string[] { null! }); break;
            case "refresh-empty": entry.RefreshCache(Array.Empty<string>()); break;
            case "refresh-valid": entry.RefreshCache(new[] { "description" }); break;
            case "move-null-parent": entry.MoveTo(null!); break;
            case "move-empty-name": entry.MoveTo(parent, ""); break;
            case "move-whitespace-name": entry.MoveTo(parent, " \t "); break;
            case "move-valid-name": entry.MoveTo(parent, "CN=renamed"); break;
            case "copy-null-parent": using (entry.CopyTo(null!)) { } break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }
}
