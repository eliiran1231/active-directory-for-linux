using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// All edits remain in fresh entry caches. No test commits, saves, or deletes.
// The existing fixture alone creates and cleans up its owned seed objects.
[Collection("differential")]
[Trait("Category", "CacheBoundaryLive")]
public sealed class CacheBoundaryLiveComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;
    public CacheBoundaryLiveComparisonTests(TestDataFixture data) => _data = data;

    [Theory]
    [InlineData("DESCRIPTION")]
    [InlineData("dEsCrIpTiOn")]
    [InlineData("description")]
    public void First_lookup_preserves_requested_property_name(string spelling)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        expected.RefreshCache();
        actual.RefreshCache();
        var left = expected.Properties[spelling];
        var right = actual.Properties[spelling];
        Assert.NotNull(left.Value);
        new Comparison("First requested property spelling")
            .Check("PropertyName", left.PropertyName, right.PropertyName)
            .Check("value", left.Value, right.Value)
            .Check("case aliases reuse wrapper", ReferenceEquals(left, expected.Properties["description"]),
                ReferenceEquals(right, actual.Properties["description"]))
            .Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Contains_after_clearing_a_present_attribute(bool clear)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        Assert.True(expected.Properties.Contains("description"));
        Assert.True(actual.Properties.Contains("description"));
        if (clear)
        {
            expected.Properties["description"].Clear();
            actual.Properties["description"].Clear();
        }
        new Comparison("Contains after Clear")
            .Check("value count", expected.Properties["description"].Count, actual.Properties["description"].Count)
            .Check("Contains", expected.Properties.Contains("description"), actual.Properties.Contains("description"))
            .Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Dictionary_enumeration_created_after_staging_uses_matching_name_source(bool stage)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        Assert.False(expected.Properties.Contains("info"));
        Assert.False(actual.Properties.Contains("info"));
        if (stage)
        {
            expected.Properties["info"].Value = "pending-only";
            actual.Properties["info"].Value = "pending-only";
        }
        new Comparison("Dictionary names: enumerator created AFTER pending addition")
            .CheckSet("names", DictionaryNames(expected.Properties), DictionaryNames(actual.Properties))
            .Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Positioned_dictionary_value_observes_later_cache_edits(bool stage)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        var left = expected.Properties.GetEnumerator();
        var right = actual.Properties.GetEnumerator();
        try
        {
            MoveToDescription(left);
            MoveToDescription(right);
            var beforeLeft = Assert.IsType<Ms.PropertyValueCollection>(left.Value).Value;
            var beforeRight = Assert.IsType<Ours.PropertyValueCollection>(right.Value).Value;
            Assert.Equal(beforeLeft, beforeRight);
            if (stage)
            {
                expected.Properties["description"].Value = "edited-after-positioning";
                actual.Properties["description"].Value = "edited-after-positioning";
            }
            new Comparison("Dictionary Value reads parent cache at access time")
                .Check("value", ((Ms.PropertyValueCollection)left.Value).Value,
                    ((Ours.PropertyValueCollection)right.Value).Value)
                .Assert();
        }
        finally { Dispose(left); Dispose(right); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void View_cursor_can_advance_again_after_end(bool names)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        var left = View(expected.Properties, names).GetEnumerator();
        var right = View(actual.Properties, names).GetEnumerator();
        try
        {
            Assert.True(left.MoveNext());
            Assert.True(right.MoveNext());
            while (left.MoveNext()) { }
            while (right.MoveNext()) { }
            new Comparison($"View cursor restart: names={names}")
                .Check("MoveNext after false", left.MoveNext(), right.MoveNext())
                .Assert();
        }
        finally { Dispose(left); Dispose(right); }
    }

    [Fact]
    public void Dictionary_CopyTo_allocates_wrappers_independent_of_indexer_cache()
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        var leftCached = expected.Properties["description"];
        var rightCached = actual.Properties["description"];
        var left = new Ms.PropertyValueCollection[expected.Properties.Count];
        var right = new Ours.PropertyValueCollection[actual.Properties.Count];
        expected.Properties.CopyTo(left, 0);
        actual.Properties.CopyTo(right, 0);
        var leftCopied = left.Single(p => p.PropertyName.Equals("description", StringComparison.OrdinalIgnoreCase));
        var rightCopied = right.Single(p => p.PropertyName.Equals("description", StringComparison.OrdinalIgnoreCase));
        var comparison = new Comparison("CopyTo wrapper independence")
            .Check("copied wrapper is indexer wrapper", ReferenceEquals(leftCached, leftCopied),
                ReferenceEquals(rightCached, rightCopied));
        leftCopied.Value = "edit-through-copy";
        rightCopied.Value = "edit-through-copy";
        comparison.Check("retained indexer wrapper value", leftCached.Value, rightCached.Value).Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void View_CopyTo_short_array_preserves_matching_partial_progress(bool names)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        var leftView = View(expected.Properties, names);
        var rightView = View(actual.Properties, names);
        Assert.True(leftView.Count > 1);
        Assert.True(rightView.Count > 1);
        object sentinel = new();
        var left = new[] { sentinel };
        var right = new[] { sentinel };
        var comparison = new Comparison($"View CopyTo short destination: names={names}");
        Errors(comparison, () => leftView.CopyTo(left, 0), () => rightView.CopyTo(right, 0));
        // Attribute order is unspecified; compare whether a slot was written.
        comparison.Check("first slot written before error", !ReferenceEquals(sentinel, left[0]),
            !ReferenceEquals(sentinel, right[0])).Assert();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(int.MaxValue)]
    public void Dictionary_CopyTo_capacity_error_has_matching_parameter(int index)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        Assert.True(expected.Properties.Count > 0);
        Assert.True(actual.Properties.Count > 0);
        var comparison = new Comparison("PropertyCollection CopyTo capacity validation");
        Errors(comparison, () => ((ICollection)expected.Properties).CopyTo(Array.Empty<object>(), index),
            () => ((ICollection)actual.Properties).CopyTo(Array.Empty<object>(), index));
        comparison.Assert();
    }

    [Theory]
    [InlineData(false, "add")]
    [InlineData(false, "find")]
    [InlineData(true, "add")]
    [InlineData(true, "find")]
    public void Child_wrappers_inherit_parent_cache_mode(bool cache, string operation)
    {
        using var expected = MicrosoftEntry(DifferentialSettings.UsersContainer);
        using var actual = OurEntry(DifferentialSettings.UsersContainer);
        expected.UsePropertyCache = cache;
        actual.UsePropertyCache = cache;
        var name = "CN=cache-boundary-" + Guid.NewGuid().ToString("N");
        // Add only constructs an uncommitted child, including when caching is off.
        using var left = operation == "add" ? expected.Children.Add(name, "user")
            : expected.Children.Find("CN=" + _data.UserName);
        using var right = operation == "add" ? actual.Children.Add(name, "user")
            : actual.Children.Find("CN=" + _data.UserName);
        Assert.Equal(cache, left.UsePropertyCache);
        Assert.Equal(left.UsePropertyCache, right.UsePropertyCache);
    }

    [Fact]
    public void SchemaEntry_returns_the_same_provider_schema_object()
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        using var left = expected.SchemaEntry;
        using var right = actual.SchemaEntry;
        Assert.False(string.IsNullOrEmpty(left.Path));
        // This compares the returned provider path, without attempting an
        // unrelated bind of the returned schema wrapper.
        new Comparison("SchemaEntry provider path")
            .Check("Path", left.Path, right.Path)
            .Check("UsePropertyCache", left.UsePropertyCache, right.UsePropertyCache)
            .Assert();
    }

    [Theory]
    [InlineData("info")]
    [InlineData("description")]
    public void Refresh_of_absent_server_attribute_preserves_matching_staged_state(string refreshName)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        Assert.False(expected.Properties.Contains("info"));
        Assert.False(actual.Properties.Contains("info"));
        expected.Properties["info"].Value = "staged-but-absent-on-server";
        actual.Properties["info"].Value = "staged-but-absent-on-server";
        expected.RefreshCache(new[] { refreshName });
        actual.RefreshCache(new[] { refreshName });
        new Comparison($"RefreshCache({refreshName}) with absent server value")
            .Check("info value", expected.Properties["info"].Value, actual.Properties["info"].Value)
            .Check("info present", expected.Properties.Contains("info"), actual.Properties.Contains("info"))
            .Assert();
    }

    [Theory]
    [InlineData("description")]
    [InlineData("mail")]
    public void First_partial_refresh_does_not_hide_other_existing_attributes(string requested)
    {
        using var expected = MicrosoftEntry();
        using var actual = OurEntry();
        expected.RefreshCache(new[] { requested });
        actual.RefreshCache(new[] { requested });
        var comparison = new Comparison("First partial refresh followed by another attribute lookup");
        comparison.Check("requested attribute", expected.Properties[requested].Value, actual.Properties[requested].Value);
        comparison.Check("unrequested sAMAccountName", expected.Properties["sAMAccountName"].Value,
            actual.Properties["sAMAccountName"].Value).Assert();
    }

    [Theory]
    [InlineData("member;range=0-0")]
    [InlineData("description")]
    public void Ranged_refresh_invalidates_base_attribute_wrapper(string requested)
    {
        using var expected = MicrosoftEntry(_data.GroupDn);
        using var actual = OurEntry(_data.GroupDn);
        var left = expected.Properties["member"];
        var right = actual.Properties["member"];
        Assert.NotEmpty(left);
        Assert.NotEmpty(right);
        expected.RefreshCache(new[] { requested });
        actual.RefreshCache(new[] { requested });
        new Comparison($"Base member wrapper after RefreshCache({requested})")
            .Check("base wrapper retained", ReferenceEquals(left, expected.Properties["member"]),
                ReferenceEquals(right, actual.Properties["member"]))
            .CheckSet("retained wrapper contents", left.Cast<string>(), right.Cast<string>())
            .Assert();
    }

    private Ms.DirectoryEntry MicrosoftEntry(string? dn = null) => new(
        DifferentialSettings.PathFor(dn ?? _data.UserDn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
    private Ours.DirectoryEntry OurEntry(string? dn = null) => new(
        DifferentialSettings.PathFor(dn ?? _data.UserDn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
    private static ICollection View(Ms.PropertyCollection properties, bool names) => names ? properties.PropertyNames : properties.Values;
    private static ICollection View(Ours.PropertyCollection properties, bool names) => names ? properties.PropertyNames : properties.Values;
    private static void Dispose(IEnumerator cursor) => (cursor as IDisposable)?.Dispose();
    private static string[] DictionaryNames(IDictionary properties)
    {
        var cursor = properties.GetEnumerator();
        try
        {
            var names = new List<string>();
            while (cursor.MoveNext()) names.Add((string)cursor.Key);
            return names.ToArray();
        }
        finally { Dispose(cursor); }
    }
    private static void MoveToDescription(IDictionaryEnumerator cursor)
    {
        while (cursor.MoveNext())
            if (string.Equals((string)cursor.Key, "description", StringComparison.OrdinalIgnoreCase)) return;
        Assert.Fail("Seeded description missing from property enumeration.");
    }
    private static void Errors(Comparison comparison, Action expected, Action actual)
    {
        var left = Record.Exception(expected);
        var right = Record.Exception(actual);
        comparison.Check("exception", left?.GetType().Name, right?.GetType().Name)
            .Check("parameter", (left as ArgumentException)?.ParamName, (right as ArgumentException)?.ParamName);
    }
}
