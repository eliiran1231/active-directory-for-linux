using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class DirectoryEntryRenameComparisonTests
{
    [Fact]
    public void Rename_parameter_nullability_matches_microsoft()
    {
        var microsoft = RenameParameter(typeof(Ms.DirectoryEntry));
        var ours = RenameParameter(typeof(Ours.DirectoryEntry));
        var nullability = new NullabilityInfoContext();

        Assert.Equal(
            nullability.Create(microsoft).ReadState,
            nullability.Create(ours).ReadState);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-an-rdn")]
    [InlineData("OU=renamed")]
    public void Rename_inputs_match_microsoft(string? newName)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var rootName = $"adfl-rn-{suffix}";
        var rootDn = $"OU={rootName},{DifferentialSettings.BaseDn}";
        var microsoftParentDn = $"OU=microsoft,{rootDn}";
        var ourParentDn = $"OU=adforlinux,{rootDn}";
        var microsoftSourceDn = $"OU=source,{microsoftParentDn}";
        var ourSourceDn = $"OU=source,{ourParentDn}";

        try
        {
            using (var domain = MicrosoftEntry(DifferentialSettings.BaseDn))
            using (var root = domain.Children.Add($"OU={rootName}", "organizationalUnit"))
            {
                root.CommitChanges();
            }

            using (var root = MicrosoftEntry(rootDn))
            {
                CreateOu(root, "OU=microsoft");
                CreateOu(root, "OU=adforlinux");
            }

            using (var microsoftParent = MicrosoftEntry(microsoftParentDn))
            using (var ourParent = MicrosoftEntry(ourParentDn))
            {
                CreateOu(microsoftParent, "OU=source");
                CreateOu(ourParent, "OU=source");
            }

            using var microsoft = MicrosoftEntry(microsoftSourceDn);
            using var ours = OurEntry(ourSourceDn);

            var microsoftResult = Observe(() => microsoft.Rename(newName));
            var ourResult = Observe(() => ours.Rename(newName));

            Assert.Equal(microsoftResult, ourResult);

            if (microsoftResult.ExceptionType is null)
            {
                Assert.Equal(microsoft.Name, ours.Name);
                Assert.Equal(
                    newName ?? "OU=source",
                    microsoft.Name,
                    ignoreCase: true);
            }
        }
        finally
        {
            SafeDeleteMicrosoft(rootDn);
        }
    }

    [Fact]
    public void Rename_on_disposed_entries_matches_microsoft()
    {
        var microsoft = MicrosoftEntry($"OU=missing,{DifferentialSettings.BaseDn}");
        var ours = OurEntry($"OU=missing,{DifferentialSettings.BaseDn}");
        microsoft.Dispose();
        ours.Dispose();

        Assert.Equal(
            Observe(() => microsoft.Rename(null)),
            Observe(() => ours.Rename(null)));
    }

    [Fact]
    public void Rename_on_missing_entries_matches_microsoft()
    {
        var name = $"adfl-missing-{Guid.NewGuid():N}";
        using var microsoft = MicrosoftEntry($"OU={name},{DifferentialSettings.BaseDn}");
        using var ours = OurEntry($"OU={name},{DifferentialSettings.BaseDn}");

        Assert.Equal(
            Observe(() => microsoft.Rename(null)),
            Observe(() => ours.Rename(null)));
    }

    private static ParameterInfo RenameParameter(Type type) =>
        type.GetMethod(nameof(Ms.DirectoryEntry.Rename), new[] { typeof(string) })!
            .GetParameters()[0];

    private static ExceptionResult Observe(Action action)
    {
        var exception = Record.Exception(action);
        return exception is null
            ? new ExceptionResult(null, 0, null, null)
            : new ExceptionResult(
                exception.GetType().Name,
                exception.HResult,
                (exception as ArgumentException)?.ParamName,
                (exception as ObjectDisposedException)?.ObjectName);
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

    private static void CreateOu(Ms.DirectoryEntry parent, string relativeName)
    {
        using var child = parent.Children.Add(relativeName, "organizationalUnit");
        child.CommitChanges();
    }

    private static void SafeDeleteMicrosoft(string dn)
    {
        try
        {
            using var entry = MicrosoftEntry(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best-effort cleanup if setup or either implementation failed.
        }
    }

    private sealed record ExceptionResult(
        string? ExceptionType,
        int HResult,
        string? ParamName,
        string? ObjectName);
}
