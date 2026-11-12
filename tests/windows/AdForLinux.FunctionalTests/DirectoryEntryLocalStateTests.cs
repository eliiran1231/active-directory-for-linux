using System.Collections;
using System.Globalization;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryLocalStateTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Disposed_entry_allows_wrappers_but_rejects_directory_reads(bool primeWrapper)
    {
        using var entry = new DirectoryEntry("LDAP://127.0.0.1:1/DC=example,DC=test",
            null, null, AuthenticationTypes.Anonymous);
        var retained = primeWrapper ? entry.Properties : null;
        entry.Dispose();

        var properties = entry.Properties;
        Assert.Same(properties, entry.Properties);
        Assert.NotNull(properties.PropertyNames);
        Assert.NotNull(properties.Values);
        Assert.True(((IDictionary)properties).IsReadOnly);
        Assert.Equal("propertyName",
            Assert.Throws<ArgumentNullException>(() => properties[null!]).ParamName);

        Assert.Throws<ObjectDisposedException>(() => properties["cn"]);
        Assert.Throws<ObjectDisposedException>(() => properties.Count);
        Assert.Throws<ObjectDisposedException>(() => properties.PropertyNames.Count);
        Assert.Throws<ObjectDisposedException>(() => properties.Values.Count);
        Assert.Throws<ObjectDisposedException>(() => properties.Contains("cn"));
        Assert.Throws<ObjectDisposedException>(() => properties.GetEnumerator());
        if (retained is not null)
            Assert.Throws<ObjectDisposedException>(() => retained["cn"]);

        entry.Close();
        entry.Path = "LDAP://127.0.0.1:1/DC=other,DC=test";
        Assert.Throws<ObjectDisposedException>(() => entry.Properties["cn"]);
        Assert.Throws<ObjectDisposedException>(() => entry.RefreshCache());
    }

    [Theory]
    [InlineData("Alice", "ALICE", true)]
    [InlineData("Alice", "Al\u00adice", true)]
    [InlineData("Jos\u00e9", "Jose\u0301", true)]
    [InlineData("Jose", "Jos\u00e9", true)]
    [InlineData("Alice", "\uff21lice", true)]
    [InlineData("\u3042", "\u30a2", true)]
    [InlineData("Alice", "Bob", false)]
    [InlineData("Alice", "Al-ice", false)]
    public void Path_equality_preserves_state_independently_of_current_culture(
        string initialName, string replacementName, bool equivalent)
    {
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            // ADSI uses en-US, even when the caller uses Turkish casing rules.
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            const string prefix = "LDAP://unused.example.test/CN=";
            const string suffix = ",DC=example,DC=test";
            var initial = prefix + initialName + suffix;
            var replacement = prefix + replacementName + suffix;
            using var entry = new DirectoryEntry(initial);
            var properties = entry.Properties;

            entry.Path = replacement;

            Assert.Equal(equivalent ? initial : replacement, entry.Path);
            Assert.Equal(equivalent, ReferenceEquals(properties, entry.Properties));
            Assert.Equal(equivalent ? "CN=" + initialName + suffix : "CN=" + replacementName + suffix,
                entry.DistinguishedName);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }
}
