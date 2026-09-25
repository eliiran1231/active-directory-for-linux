using System.Collections;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class PrincipalValueCollectionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Mutations_notify_owner_once_with_the_complete_updated_values(bool useNonGenericList)
    {
        var notifications = new List<string[]>();
        var values = new PrincipalValueCollection<string>(
            new[] { "HOST/first", "HOST/last" },
            updated => notifications.Add(updated.ToArray()));
        Assert.Empty(notifications);

        if (useNonGenericList)
        {
            IList list = values;
            Assert.Equal(3, list.Add("HOST/tail"));
            list.Insert(1, "HOST/middle");
            list[0] = "HOST/replaced";
            list.Remove("HOST/last");
            list.RemoveAt(1);
            list.Clear();
        }
        else
        {
            values.Add("HOST/tail");
            values.Insert(1, "HOST/middle");
            values[0] = "HOST/replaced";
            Assert.True(values.Remove("HOST/last"));
            values.RemoveAt(1);
            values.Clear();
        }

        Assert.Collection(notifications,
            actual => Assert.Equal(new[] { "HOST/first", "HOST/last", "HOST/tail" }, actual),
            actual => Assert.Equal(new[] { "HOST/first", "HOST/middle", "HOST/last", "HOST/tail" }, actual),
            actual => Assert.Equal(new[] { "HOST/replaced", "HOST/middle", "HOST/last", "HOST/tail" }, actual),
            actual => Assert.Equal(new[] { "HOST/replaced", "HOST/middle", "HOST/tail" }, actual),
            actual => Assert.Equal(new[] { "HOST/replaced", "HOST/tail" }, actual),
            actual => Assert.Empty(actual));
        Assert.Empty(values);
    }

    [Fact]
    public void Reads_and_missing_removals_do_not_mark_owner_changed()
    {
        var input = new[] { "DESK01", "DESK02" };
        var notifications = 0;
        var values = new PrincipalValueCollection<string>(input, _ => notifications++);
        input[0] = "changed outside collection";
        IList list = values;

        Assert.Equal("DESK01", values[0]);
        Assert.True(list.Contains("DESK02"));
        Assert.Equal(1, list.IndexOf("DESK02"));
        Assert.False(values.Remove("missing"));
        list.Remove("missing");
        var copy = new string[3];
        ((ICollection)values).CopyTo(copy, 1);
        Assert.Equal(new[] { null, "DESK01", "DESK02" }, copy);
        Assert.Equal(new[] { "DESK01", "DESK02" }, values.ToArray());
        Assert.Equal(0, notifications);
    }

    [Theory]
    [InlineData("add-null")]
    [InlineData("insert-null")]
    [InlineData("set-null")]
    [InlineData("add-wrong-type")]
    [InlineData("insert-wrong-type")]
    [InlineData("set-wrong-type")]
    [InlineData("insert-invalid-index")]
    [InlineData("set-invalid-index")]
    [InlineData("remove-invalid-index")]
    public void Rejected_mutations_preserve_values_and_do_not_notify_owner(string operation)
    {
        var notifications = 0;
        var values = new PrincipalValueCollection<string>(new[] { "DESK01" }, _ => notifications++);
        IList list = values;

        switch (operation)
        {
            case "add-null": Assert.Throws<ArgumentNullException>(() => list.Add(null)); break;
            case "insert-null": Assert.Throws<ArgumentNullException>(() => list.Insert(0, null)); break;
            case "set-null": Assert.Throws<ArgumentNullException>(() => list[0] = null); break;
            case "add-wrong-type": Assert.Throws<InvalidCastException>(() => list.Add(42)); break;
            case "insert-wrong-type": Assert.Throws<InvalidCastException>(() => list.Insert(0, 42)); break;
            case "set-wrong-type": Assert.Throws<InvalidCastException>(() => list[0] = 42); break;
            case "insert-invalid-index": Assert.Throws<ArgumentOutOfRangeException>(() => list.Insert(2, "DESK02")); break;
            case "set-invalid-index": Assert.Throws<ArgumentOutOfRangeException>(() => list[1] = "DESK02"); break;
            case "remove-invalid-index": Assert.Throws<ArgumentOutOfRangeException>(() => list.RemoveAt(-1)); break;
            default: throw new ArgumentException("Unknown test operation", nameof(operation));
        }

        Assert.Equal("DESK01", Assert.Single(values));
        Assert.Equal(0, notifications);
    }
}
