using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Detached real Microsoft collection tracking; no PrincipalContext or LDAP use.
public sealed class V1ServiceNameTrackingComparisonTests
{
    [Theory]
    [InlineData("add")]
    [InlineData("remove")]
    [InlineData("clear")]
    [InlineData("replace")]
    [InlineData("duplicates")]
    [InlineData("cancel-add")]
    [InlineData("cancel-remove")]
    [InlineData("change-remove")]
    [InlineData("insert-change")]
    [InlineData("clear-reinsert")]
    public void Collection_change_tracking_matches_microsoft(string scenario)
    {
        var microsoft = (Ms.PrincipalValueCollection<string>)Activator.CreateInstance(
            typeof(Ms.PrincipalValueCollection<string>), nonPublic: true)!;
        Invoke(microsoft, "Load", new List<string> { "old", "keep" });
        var ours = new Ours.PrincipalValueCollection<string>(new[] { "old", "keep" }, null, trackChanges: true);
        Edit(microsoft, scenario); Edit(ours, scenario);
        Compare(microsoft, ours);
        Invoke(microsoft, "ResetTracking"); ours.Acknowledge(ours.CaptureChanges());
        microsoft.Add("next"); ours.Add("next");
        microsoft.RemoveAt(0); ours.RemoveAt(0);
        Compare(microsoft, ours);
    }

    private static void Edit(IList<string> values, string scenario)
    {
        switch (scenario)
        {
            case "add": values.Add("new"); break;
            case "remove": values.Remove("old"); break;
            case "clear": values.Clear(); break;
            case "replace": values[0] = "new"; break;
            case "duplicates": values.Add("old"); values.Add("new"); values.Add("new"); break;
            case "cancel-add": values.Add("new"); values.Remove("new"); break;
            case "cancel-remove": values.Remove("old"); values.Add("old"); break;
            case "change-remove": values[0] = "new"; values.RemoveAt(0); break;
            case "insert-change": values.Insert(1, "new"); values[1] = "changed"; break;
            case "clear-reinsert": values.Clear(); values.Add("old"); break;
        }
    }

    private static void Compare(Ms.PrincipalValueCollection<string> expected, Ours.PrincipalValueCollection<string> actual)
    {
        var changes = actual.CaptureChanges();
        Assert.Equal(expected.ToArray(), actual.ToArray());
        Assert.Equal(((IEnumerable)Read(expected, "Inserted")).Cast<string>(), changes.Inserted);
        Assert.Equal(((IEnumerable)Read(expected, "Removed")).Cast<string>(), changes.Removed);
        Assert.Equal(((IEnumerable)Read(expected, "ChangedValues")).Cast<object>()
            .Select(pair => ((string)Read(pair, "Left"), (string)Read(pair, "Right"))), changes.Changed);
    }

    private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static object Read(object instance, string name) =>
        instance.GetType().GetProperty(name, Flags)?.GetValue(instance)
        ?? instance.GetType().GetField(name, Flags)!.GetValue(instance)!;
    private static void Invoke(object instance, string method, params object[] args) =>
        instance.GetType().GetMethod(method, Flags)!.Invoke(instance, args);
}
