#pragma warning disable SYSLIB0050, SYSLIB0051 // Metadata serialization only, never a formatter.
using System.Collections;
using System.Runtime.Serialization;
using P = AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Identity_collection_retains_duplicates_and_removes_first_equal_value()
    {
        var first = new P.SecurityIdentifier("S-1-1-0");
        var duplicate = new P.SecurityIdentifier("S-1-1-0");
        var name = new P.NTAccount("EXAMPLE", "Alice");
        var collection = new P.IdentityReferenceCollection { first, duplicate, name, first };
        Assert.False(((ICollection<P.IdentityReference>)collection).IsReadOnly);
        var containsName = collection.Contains(new P.NTAccount("example", "ALICE"));
        Assert.True(containsName);
        Assert.True(collection.Remove(new P.SecurityIdentifier("S-1-1-0")));
        Assert.Same(duplicate, collection[0]);
        var copy = new P.IdentityReference[4];
        collection.CopyTo(copy, 1);
        Assert.Null(copy[0]);
        Assert.Same(duplicate, copy[1]);
        Assert.Same(name, copy[2]);
        Assert.Same(first, copy[3]);
        Assert.False(collection.Remove(new P.SecurityIdentifier("S-1-5-18")));
        collection.Clear();
        Assert.Empty(collection);
        Assert.Same(duplicate, copy[1]);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void Identity_collection_null_setter_validation_precedes_index_validation(int index)
    {
        var collection = new P.IdentityReferenceCollection { new P.SecurityIdentifier("S-1-1-0") };
        var original = collection[0];
        Assert.Equal("value", Assert.Throws<ArgumentNullException>(() => collection[index] = null!).ParamName);
        Assert.Same(original, Assert.Single(collection));
    }

    [Fact]
    public void Identity_collection_null_and_copy_validation_matches_list_contract()
    {
        Assert.Equal("capacity", Assert.Throws<ArgumentOutOfRangeException>(() => new P.IdentityReferenceCollection(-1)).ParamName);
        var collection = new P.IdentityReferenceCollection { new P.SecurityIdentifier("S-1-1-0") };
        Assert.Equal("identity", Assert.Throws<ArgumentNullException>(() => collection.Add(null!)).ParamName);
        Assert.Equal("identity", Assert.Throws<ArgumentNullException>(() => collection.Contains(null!)).ParamName);
        Assert.Equal("identity", Assert.Throws<ArgumentNullException>(() => collection.Remove(null!)).ParamName);
        Assert.Equal("destinationArray", Assert.Throws<ArgumentNullException>(() => collection.CopyTo(null!, -1)).ParamName);
        Assert.Equal("destinationIndex", Assert.Throws<ArgumentOutOfRangeException>(() => collection.CopyTo(new P.IdentityReference[1], -1)).ParamName);
        Assert.Throws<ArgumentException>(() => collection.CopyTo(Array.Empty<P.IdentityReference>(), 0));
        Assert.Equal("index", Assert.Throws<ArgumentOutOfRangeException>(() => collection[-1]).ParamName);
    }

    [Fact]
    public void Identity_enumerator_observes_live_replacements_removal_and_growth()
    {
        var a = new P.NTAccount("a"); var b = new P.NTAccount("b"); var c = new P.NTAccount("c");
        var collection = new P.IdentityReferenceCollection { a, b };
        using var iterator = collection.GetEnumerator();
        Assert.Equal("index", Assert.Throws<ArgumentOutOfRangeException>(() => iterator.Current).ParamName);
        Assert.True(iterator.MoveNext());
        collection[0] = c;
        Assert.Same(c, iterator.Current);
        collection.Remove(c);
        Assert.Same(b, iterator.Current);
        collection.Add(c);
        iterator.Dispose(); // Native Dispose is a no-op.
        Assert.True(iterator.MoveNext());
        Assert.Same(c, iterator.Current);
        Assert.False(iterator.MoveNext());
        Assert.Throws<ArgumentOutOfRangeException>(() => ((IEnumerator)iterator).Current);
        collection.Add(a);
        Assert.False(iterator.MoveNext()); // The failed MoveNext already advanced the index.
        iterator.Reset();
        Assert.True(iterator.MoveNext());
        Assert.Same(b, iterator.Current);
        collection.Clear();
        Assert.Throws<ArgumentOutOfRangeException>(() => iterator.Current);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Same_kind_identity_translation_copies_collection_but_retains_identity(bool account, bool force)
    {
        P.IdentityReference identity = account ? new P.NTAccount("unresolved") : new P.SecurityIdentifier("S-1-1-0");
        var collection = new P.IdentityReferenceCollection { identity, identity };
        foreach (var translated in new[] { collection.Translate(identity.GetType()), collection.Translate(identity.GetType(), force) })
        {
            Assert.NotSame(collection, translated);
            Assert.Equal(2, translated.Count);
            Assert.Same(identity, translated[0]);
            Assert.Same(identity, translated[1]);
            translated.Clear();
            Assert.Equal(2, collection.Count);
        }
        var empty = new P.IdentityReferenceCollection();
        var copy = empty.Translate(identity.GetType(), force);
        Assert.NotSame(empty, copy);
        Assert.Empty(copy);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Identity_translation_validates_target_before_resolution_and_keeps_staged_refusal_atomic(bool force)
    {
        var identity = new P.NTAccount("unresolved");
        var collection = new P.IdentityReferenceCollection { identity };
        Assert.Equal("targetType", Assert.Throws<ArgumentNullException>(() => collection.Translate(null!, force)).ParamName);
        foreach (var target in new[] { typeof(object), typeof(P.IdentityReference), typeof(string) })
        {
            Assert.Equal("targetType", Assert.Throws<ArgumentException>(() => collection.Translate(target, force)).ParamName);
            Assert.Equal("targetType", Assert.Throws<ArgumentException>(() => new P.IdentityReferenceCollection().Translate(target, force)).ParamName);
        }
        // This is the explicit existing resolver staging guard, not native mapping parity.
        Assert.Throws<NotSupportedException>(() => collection.Translate(typeof(P.SecurityIdentifier), force));
        Assert.Same(identity, Assert.Single(collection));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Mapping_exception_null_message_preserves_target_runtime_contract(bool withInner)
    {
        var inner = new InvalidOperationException("inner");
        var exception = withInner ? new P.IdentityNotMappedException(null, inner) : new P.IdentityNotMappedException((string?)null);
#if NET10_0_OR_GREATER
        Assert.Equal("Some or all identity references could not be translated.", exception.Message);
#else
        Assert.Equal("Exception of type 'AdForLinux.Security.Principal.IdentityNotMappedException' was thrown.", exception.Message);
#endif
        Assert.Equal(withInner ? inner : null, exception.InnerException);
        Assert.Equal(unchecked((int)0x80131501), exception.HResult);
    }

    [Theory]
    [InlineData("")]
    [InlineData("custom")]
    public void Mapping_exception_keeps_explicit_message_inner_and_live_unmapped_collection(string message)
    {
        var inner = new InvalidOperationException("inner");
        var exception = new P.IdentityNotMappedException(message, inner);
        Assert.Equal(message, exception.Message);
        Assert.Same(inner, exception.InnerException);
        var identities = exception.UnmappedIdentities;
        identities.Add(new P.SecurityIdentifier("S-1-1-0"));
        Assert.Same(identities, exception.UnmappedIdentities);
        Assert.Single(exception.UnmappedIdentities);
        var other = new P.IdentityNotMappedException();
        Assert.Empty(other.UnmappedIdentities);
        Assert.Equal("Some or all identity references could not be translated.", other.Message);
    }

    [Fact]
    public void Mapping_exception_serialization_exports_base_metadata_only()
    {
        var exception = new P.IdentityNotMappedException("custom");
        exception.UnmappedIdentities.Add(new P.SecurityIdentifier("S-1-1-0"));
        Assert.Equal("info", Assert.Throws<ArgumentNullException>(() => exception.GetObjectData(null!, default)).ParamName);
        var info = new SerializationInfo(typeof(P.IdentityNotMappedException), new FormatterConverter());
        exception.GetObjectData(info, default);
        Assert.Equal("custom", info.GetString("Message"));
        Assert.Equal(exception.HResult, info.GetInt32("HResult"));
        Assert.Null(info.GetValue("InnerException", typeof(Exception)));
        var keys = new List<string>(); var entries = info.GetEnumerator();
        while (entries.MoveNext()) keys.Add(entries.Name);
        Assert.DoesNotContain("UnmappedIdentities", keys);
        Assert.DoesNotContain("_unmappedIdentities", keys);
    }
}
