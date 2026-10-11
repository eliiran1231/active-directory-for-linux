using System.Collections;
using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private static void SetEntryField(DirectoryEntry entry, string name, object? value)
        => typeof(DirectoryEntry).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(entry, value);

    private static void InstallSearchTransport(DirectoryEntry entry, Action<DirectoryRequest>? requestSent = null, Action? schemaRead = null)
    {
        var dn = entry.DistinguishedName;
        SetEntryField(entry, "_connection", SaveReadConnection.Create(request =>
        {
            requestSent?.Invoke(request);
            if (request is DeleteRequest) return SaveResponse("", [], 0, ResultCode.Success, false, false);
            var search = Assert.IsType<SearchRequest>(request);
            var resultDn = search.Attributes.Contains("1.1") ? dn : "CN=returned," + CrossContextFixture.DomainDn;
            return SaveResponse(resultDn, new() { ["description"] = ["copied result"] }, 1, ResultCode.Success, false, false);
        }, () => { }));
        SetEntryField(entry, "_schemaConnection", SaveReadConnection.Create(_ =>
        {
            schemaRead?.Invoke();
            return SaveResponse("", [], 0, ResultCode.Success, false, false);
        }, () => { }));
    }

    private static DirectorySearcher ControlledSearcher(DirectoryEntry entry)
        => new(entry) { ConfigureConnectionOverride = _ => { } };

    private static PropertyCollection ChildValues()
    {
        var values = new PropertyCollection(); values.ReplaceLoaded("objectClass", ["user"]); return values;
    }

    [Fact]
    public void Published_authority_revokes_retained_children_filters_searchers_and_delayed_enumerators()
    {
        var f = new ExecutorFixture();
        try
        {
            var children = f.Proof.Entry.Children;
            var filter = children.SchemaFilter; filter.Add("user");
            var copiedNames = filter.GetEnumerator();
            var delayed = children.GetEnumerator();
            var genericDelayed = ((IEnumerable<DirectoryEntry>)children).GetEnumerator();
            using var searcher = ControlledSearcher(f.Proof.Entry);
            using var operation = f.Create(); operation.Execute();
            var destinationIo = 0;
            InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            using var target = new DirectoryEntry("LDAP://unused.invalid/CN=target");
            target.PropertyReadOverride = (_, _) => throw new Exception("Stale Remove read its target");
            Assert.Throws<InvalidOperationException>(() => children.Add("CN=late", "user"));
            Assert.Throws<InvalidOperationException>(() => children.Find("CN=late"));
            Assert.Throws<InvalidOperationException>(() => children.Remove(target));
            Assert.Throws<InvalidOperationException>(() => children.GetEnumerator());
            Assert.Throws<InvalidOperationException>(() => delayed.MoveNext());
            Assert.Throws<InvalidOperationException>(() => genericDelayed.MoveNext());
            Assert.Throws<InvalidOperationException>(() => _ = children.SchemaFilter);
            Assert.Throws<InvalidOperationException>(() => filter.Add("late"));
            Assert.Throws<InvalidOperationException>(() => filter.Clear());
            Assert.Throws<InvalidOperationException>(() => filter[0] = "late");
            Assert.Throws<InvalidOperationException>(() => searcher.FindOne());
            Assert.Throws<InvalidOperationException>(() => searcher.FindAll());
            Assert.Equal(0, destinationIo);
            // The captured schema array is data; revocation does not erase it.
            Assert.True(copiedNames.MoveNext()); Assert.Equal("user", copiedNames.Current);

            var fresh = f.Proof.Entry.Children;
            fresh.SchemaFilter.Add("fresh");
            using var added = fresh.Add("CN=new", "user");
            Assert.Equal("destination-reader", added.Username);
            fresh.BeforeChildLookup = child =>
            {
                Assert.Equal("destination-reader", child.Username);
                child.PropertyReadOverride = (_, _) => ChildValues();
                SetEntryField(child, "_boundDistinguishedName", child.DistinguishedName);
            };
            using var found = fresh.Find("CN=found", "user"); fresh.Remove(found);
            fresh.SearcherCreated = created => created.ConfigureConnectionOverride = _ => { };
            using var enumeration = ((IEnumerable<DirectoryEntry>)fresh).GetEnumerator();
            Assert.True(enumeration.MoveNext());
            using var enumerated = enumeration.Current;
            Assert.Equal("destination-reader", enumerated.Username);
            using var freshSearcher = ControlledSearcher(f.Proof.Entry);
            var result = Assert.IsType<SearchResult>(freshSearcher.FindOne());
            using var resultEntry = result.GetDirectoryEntry(); Assert.Equal("destination-reader", resultEntry.Username);
            // Explicit SearchRoot assignment reacquires a fresh handle token.
            searcher.SearchRoot = f.Proof.Entry;
            Assert.NotNull(searcher.FindOne());
            Assert.True(destinationIo > 0); Assert.Equal(new[] { "fresh" }, fresh.SchemaFilter.Cast<string>());
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Children_lookup_or_remove_blocked_across_publication_cannot_borrow_destination(bool remove)
    {
        var f = new ExecutorFixture();
        using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? active = null;
        using var target = new DirectoryEntry("LDAP://source.invalid/CN=child," + CrossContextFixture.ItemDn);
        try
        {
            var children = f.Proof.Entry.Children;
            PropertyCollection Read(string[] _, bool __)
            { entered.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); return ChildValues(); }
            target.PropertyReadOverride = Read; SetEntryField(target, "_boundDistinguishedName", target.DistinguishedName);
            children.BeforeChildLookup = child =>
            { Assert.Equal("source-reader", child.Username); child.PropertyReadOverride = Read; };
            active = Task.Run(() => Assert.Throws<InvalidOperationException>(() =>
            { if (remove) children.Remove(target); else children.Find("CN=child"); }));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            var destinationIo = 0; InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            resume.Set(); await active;
            Assert.Equal(0, destinationIo);
        }
        finally { resume.Set(); if (active is not null) await active; f.Cleanup(); }
    }

    [Fact]
    public async Task Retained_schema_filter_write_rechecks_authority_before_publishing_array()
    {
        var f = new ExecutorFixture();
        using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? active = null;
        try
        {
            var filter = f.Proof.Entry.Children.SchemaFilter; filter.Add("old");
            filter.BeforeWrite = () => { entered.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); };
            active = Task.Run(() => Assert.Throws<InvalidOperationException>(() => filter.Add("late")));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            var fresh = f.Proof.Entry.Children.SchemaFilter; fresh.Add("destination");
            resume.Set(); await active;
            Assert.Equal(new[] { "destination" }, fresh.Cast<string>());
        }
        finally { resume.Set(); if (active is not null) await active; f.Cleanup(); }
    }

    [Theory]
    [InlineData(false, 1)] [InlineData(true, 1)]
    [InlineData(false, 2)] [InlineData(true, 2)]
    public async Task Search_response_arriving_after_publication_cannot_create_destination_results(bool all, int blockRequest)
    {
        var f = new ExecutorFixture();
        using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? active = null;
        try
        {
            var requests = 0;
            InstallSearchTransport(f.Proof.Entry, _ =>
            { if (++requests == blockRequest) { entered.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); } });
            using var searcher = ControlledSearcher(f.Proof.Entry);
            active = Task.Run(() => Assert.Throws<InvalidOperationException>(() =>
            { if (all) searcher.FindAll(); else searcher.FindOne(); }));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            var destinationIo = 0; InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            resume.Set(); await active;
            Assert.Equal(blockRequest, requests); Assert.Equal(0, destinationIo);
        }
        finally { resume.Set(); if (active is not null) await active; f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Search_result_schema_read_blocked_across_publication_cannot_publish_new_authority(bool all)
    {
        var f = new ExecutorFixture();
        using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? active = null;
        try
        {
            InstallSearchTransport(f.Proof.Entry, schemaRead: () =>
            { entered.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); });
            using var searcher = ControlledSearcher(f.Proof.Entry);
            active = Task.Run(() => Assert.Throws<InvalidOperationException>(() =>
            { if (all) searcher.FindAll(); else searcher.FindOne(); }));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            var destinationIo = 0; InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            resume.Set(); await active; Assert.Equal(0, destinationIo);
        }
        finally { resume.Set(); if (active is not null) await active; f.Cleanup(); }
    }

    [Fact]
    public void Close_and_refresh_preserve_handles_but_authority_publication_preserves_only_copied_result_data()
    {
        var f = new ExecutorFixture();
        try
        {
            InstallSearchTransport(f.Proof.Entry);
            var children = f.Proof.Entry.Children; var filter = children.SchemaFilter; filter.Add("old");
            using var searcher = ControlledSearcher(f.Proof.Entry);
            using var results = searcher.FindAll(); var copied = results[0]; var snapshot = copied.Snapshot();
            f.Proof.Entry.Close(); f.Proof.Entry.RefreshCache(); InstallSearchTransport(f.Proof.Entry);
            filter.Add("after-close"); Assert.Equal(new[] { "after-close" }, filter.Cast<string>());
            using var child = children.Add("CN=still-source", "user"); Assert.Equal("source-reader", child.Username);
            Assert.NotNull(searcher.FindOne());
            using var sourceResult = copied.GetDirectoryEntry(); Assert.Equal("source-reader", sourceResult.Username);
            using var operation = f.Create(); operation.Execute();
            Assert.Equal("copied result", copied.Properties["description"][0]);
            Assert.Equal("copied result", snapshot.Properties["description"][0]);
            Assert.Single(results); Assert.Equal("copied result", results[0].Properties["description"][0]);
            Assert.Throws<InvalidOperationException>(() => copied.GetDirectoryEntry());
            Assert.Throws<InvalidOperationException>(() => snapshot.GetDirectoryEntry());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Delayed_result_construction_retains_the_original_search_authority()
    {
        var f = new ExecutorFixture();
        try
        {
            var origin = new SearchResultOrigin(f.Proof.Entry, f.Proof.Entry.CaptureBindingAuthority());
            var raw = SaveResponse(CrossContextFixture.ItemDn, new() { ["description"] = ["copied"] }, 1, ResultCode.Success, false, false);
            IEnumerable<SearchResult> Deferred()
            { yield return new SearchResult(raw.Entries[0], origin, f.Proof.Entry); }
            using var results = new SearchResultCollection(Deferred(), cacheResults: false);
            var enumerator = results.GetEnumerator();
            using var operation = f.Create(); operation.Execute();
            var destinationIo = 0; InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            Assert.Throws<InvalidOperationException>(() => enumerator.MoveNext()); Assert.Equal(0, destinationIo);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Inflight_search_result_uses_its_captured_root_when_searcher_root_is_reassigned()
    {
        var f = new ExecutorFixture();
        using var other = new DirectoryEntry("LDAP://other.invalid/DC=elsewhere", "other-user", "other-test-value");
        try
        {
            using var searcher = ControlledSearcher(f.Proof.Entry);
            var requests = 0;
            InstallSearchTransport(f.Proof.Entry, _ => { if (++requests == 2) searcher.SearchRoot = other; });
            var result = Assert.IsType<SearchResult>(searcher.FindOne());
            using var materialized = result.GetDirectoryEntry();
            Assert.Same(other, searcher.SearchRoot);
            Assert.Equal("source-reader", materialized.Username); Assert.Contains("source.invalid", materialized.Path);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Streaming_dispatch_rechecks_original_authority_before_native_async_request(bool asynchronous)
    {
        var f = new ExecutorFixture();
        try
        {
            InstallSearchTransport(f.Proof.Entry);
            using var searcher = ControlledSearcher(f.Proof.Entry);
            searcher.Asynchronous = asynchronous; searcher.CacheResults = asynchronous;
            searcher.StreamingRootCreated = clone =>
            { Assert.Equal("source-reader", clone.Username); InstallSearchTransport(clone); };
            var destinationIo = 0;
            searcher.ConfigureConnectionOverride = _ =>
            {
                using var operation = f.Create(); operation.Execute();
                InstallSearchTransport(f.Proof.Entry, _ => destinationIo++, () => destinationIo++);
            };
            using var results = searcher.FindAll();
            // The fake connection has no native handle: reaching BeginSendRequest
            // would fail differently. Revocation must win before native dispatch.
            var failure = Assert.Throws<InvalidOperationException>(() => results.GetEnumerator().MoveNext());
            Assert.Contains("revoked entry authority", failure.Message);
            Assert.Equal(0, destinationIo);
        }
        finally { f.Cleanup(); }
    }
}
