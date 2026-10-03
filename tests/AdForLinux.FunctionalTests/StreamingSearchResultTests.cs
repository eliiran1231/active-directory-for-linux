using System.Collections;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class StreamingSearchResultTests
{
    [Fact]
    public void Cached_enumerators_replay_results_without_advancing_each_others_position()
    {
        var items = CreateResults();
        var source = new TrackedResults(items);
        using var results = new SearchResultCollection(source, cacheResults: true);
        using var first = ((IEnumerable<SearchResult>)results).GetEnumerator();
        using var second = ((IEnumerable<SearchResult>)results).GetEnumerator();

        Assert.Equal(0, source.ValuesRead);
        Assert.True(first.MoveNext());
        Assert.Equal(items[0].Path, first.Current.Path);
        Assert.Same(first.Current, first.Current);
        Assert.True(first.MoveNext());
        Assert.Equal(items[1].Path, first.Current.Path);
        Assert.True(second.MoveNext());
        Assert.Equal(items[0].Path, second.Current.Path);
        Assert.Equal(2, source.ValuesRead);

        Assert.Equal(items.Length, results.Count);
        Assert.True(second.MoveNext());
        Assert.Equal(items[1].Path, second.Current.Path);
        Assert.NotSame(first.Current, second.Current);
        Assert.NotSame(results[1], second.Current);
        Assert.Same(results[1], results[1]);
        Assert.Equal(items.Select(row => row.Path), results.Select(row => row.Path));
        Assert.Equal(items.Select(row => row.Path), results.Select(row => row.Path));
        Assert.Equal(1, source.Enumerations);
        Assert.Equal(items.Length, source.ValuesRead);
        Assert.Equal(1, source.Disposals);
    }

    [Theory]
    [InlineData("Count")]
    [InlineData("Indexer")]
    [InlineData("Contains")]
    [InlineData("IndexOf")]
    [InlineData("CopyTo")]
    [InlineData("ICollection.CopyTo")]
    public void Uncached_collection_operations_preserve_only_the_unconsumed_results(string operation)
    {
        var items = CreateResults();
        var source = new TrackedResults(items);
        using var results = new SearchResultCollection(source, cacheResults: false);
        using (var cursor = ((IEnumerable<SearchResult>)results).GetEnumerator())
        {
            Assert.True(cursor.MoveNext());
            Assert.Same(items[0], cursor.Current);
        }

        // Disposing the cursor must leave the rest available to the collection.
        Assert.Equal(0, source.Disposals);
        var copy = new SearchResult[4];
        switch (operation)
        {
            case "Count": Assert.Equal(2, results.Count); break;
            case "Indexer": Assert.Same(items[1], results[0]); break;
            case "Contains": Assert.True(results.Contains(items[2])); break;
            case "IndexOf": Assert.Equal(1, results.IndexOf(items[2])); break;
            case "CopyTo": results.CopyTo(copy, 1); break;
            case "ICollection.CopyTo": ((ICollection)results).CopyTo(copy, 1); break;
        }

        if (operation.EndsWith("CopyTo", StringComparison.Ordinal))
        {
            Assert.Equal(new[] { null, items[1], items[2], null }, copy);
        }

        Assert.Equal(items[1..], results.ToArray());
        Assert.Equal(items[1..], results.ToArray());
        Assert.False(results.Contains(items[0]));
        Assert.Equal(-1, results.IndexOf(items[0]));
        Assert.Equal(1, source.Enumerations);
        Assert.Equal(1, source.Disposals);
    }

    [Fact]
    public void Uncached_enumeration_cannot_be_claimed_twice()
    {
        var items = CreateResults();
        var source = new TrackedResults(items);
        using var results = new SearchResultCollection(source, cacheResults: false);
        using var cursor = ((IEnumerable<SearchResult>)results).GetEnumerator();
        Assert.True(cursor.MoveNext());

        Assert.Empty(results.ToArray());
        Assert.Equal(1, source.ValuesRead);
        Assert.True(cursor.MoveNext());
        Assert.Same(items[1], cursor.Current);
        Assert.True(cursor.MoveNext());
        Assert.Same(items[2], cursor.Current);
        Assert.False(cursor.MoveNext());
        Assert.Empty(results.ToArray());
        Assert.Equal(1, source.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Producer_failure_is_reported_after_already_produced_results(bool cacheResults)
    {
        var item = CreateResults()[0];
        var failure = new InvalidOperationException("LDAP search failed after a partial response");
        using var source = new StreamingSearchResultSource((publish, _) =>
        {
            publish(item);
            throw failure;
        });
        using var results = new SearchResultCollection(source, cacheResults);

        // Bound the wait so a missing completion signal cannot hang the suite.
        await Task.Run(() =>
        {
            using var cursor = ((IEnumerable<SearchResult>)results).GetEnumerator();
            Assert.True(cursor.MoveNext());
            Assert.Equal(item.Path, cursor.Current.Path);
            Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => cursor.MoveNext()));
        }).WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void Disposing_an_uncached_collection_releases_its_partially_read_cursor_once()
    {
        var source = new TrackedResults(CreateResults());
        var results = new SearchResultCollection(source, cacheResults: false);
        using var cursor = ((IEnumerable<SearchResult>)results).GetEnumerator();
        Assert.True(cursor.MoveNext());

        results.Dispose();
        results.Dispose();

        Assert.Equal(1, source.Disposals);
        Assert.False(cursor.MoveNext());
        Assert.Throws<ObjectDisposedException>(() => results.Count);
        Assert.Throws<ObjectDisposedException>(() => results[0]);
        Assert.Throws<ObjectDisposedException>(() => results.GetEnumerator());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Short_copy_destination_is_unchanged_after_validation_failure(bool nonGeneric)
    {
        var items = CreateResults();
        using var results = new SearchResultCollection(items);
        var destination = new[] { items[2] };
        var error = Assert.Throws<ArgumentException>(() =>
        {
            if (nonGeneric) ((ICollection)results).CopyTo(destination, 0);
            else results.CopyTo(destination, 0);
        });
        Assert.Equal("destinationArray", error.ParamName);
        Assert.Same(items[2], destination[0]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Materialized_results_remain_accessible_after_disposal(bool streaming)
    {
        var items = CreateResults();
        var results = streaming
            ? new SearchResultCollection(new TrackedResults(items), cacheResults: true)
            : new SearchResultCollection(items);
        var cached = results[0];
        results.Dispose();
        Assert.Equal(3, results.Count);
        Assert.Same(cached, results[0]);
        Assert.True(results.Contains(cached));
        Assert.False(results.Contains(null!));
        Assert.Equal(-1, results.IndexOf(null!));
        var copy = new SearchResult[3];
        results.CopyTo(copy, 0);
        Assert.Same(cached, copy[0]);
        Assert.Throws<ObjectDisposedException>(() => results.GetEnumerator());
    }

    private static SearchResult[] CreateResults() => Enumerable.Range(0, 3)
        .Select(index =>
        {
            var root = new DirectoryEntry($"LDAP://offline.invalid/CN={index}");
            var properties = new ResultPropertyCollection();
            properties.Set("adspath", new object[] { root.Path });
            return new SearchResult(root, properties);
        })
        .ToArray();

    private sealed class TrackedResults(SearchResult[] items) : IEnumerable<SearchResult>
    {
        public int Enumerations { get; private set; }
        public int ValuesRead { get; private set; }
        public int Disposals { get; private set; }

        public IEnumerator<SearchResult> GetEnumerator()
        {
            Enumerations++;
            try
            {
                foreach (var item in items)
                {
                    ValuesRead++;
                    yield return item;
                }
            }
            finally
            {
                Disposals++;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
