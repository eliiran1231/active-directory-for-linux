using System.Collections;
using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Seeded finite read store; actual DirectoryEntries enumerators own query replay.
internal static class ChildEnumerationMirrors
{
    private const string RootDn="CN=owned-enumeration,DC=example,DC=test";
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var count in new[] { 0,3 })
        foreach (var position in count==0 ? new[] { "before","exhausted" } : new[] { "before","partial","exhausted" })
        foreach (var operation in new[] { "Current","Reset" })
        {
            var state=new State(count);
            var resources=new List<Transport>();
            using (var root=new DS.DirectoryEntry("LDAP://unused.example.test/"+RootDn))
            {
                root.OperationSessionFactory=(options,size,referrals,fresh,minimum) =>
                {
                    if (!OfflineTestGuard.Enabled || size is <1 or >2) throw new InvalidOperationException("Invalid child fixture admission");
                    return Enumerable.Range(0,size).Select(_ =>
                    {
                        var transport=new Transport(state);resources.Add(transport);
                        var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                        return new LdapConnectionProvider.Session(session,() => { },() => { });
                    }).ToArray();
                };
                var entries=new HashSet<IDisposable>(ReferenceEqualityComparer.Instance);
                var iterator=root.Children.GetEnumerator();
                try
                {
                    if (position=="partial")
                    {
                        if (!iterator.MoveNext()) throw new InvalidOperationException("Seeded child partial positioning failed");
                        TrackCurrent();
                    }
                    else if (position=="exhausted")
                    {
                        var initial=ReadRemaining();
                        if (initial.Error is not null || initial.Count!=count) throw new InvalidOperationException("Seeded child exhaustion precondition failed",initial.Error);
                    }
                    TrackCurrent();
                    var row=new Sequence();
                    if (operation=="Reset")
                    {
                        iterator.Reset();TrackCurrent();
                        var first=ReadRemaining();row.Observe(70,first.Count);row.Observe(71,first.Error?.GetType().FullName,exceptionType:true);
                        iterator.Reset();
                        var second=ReadRemaining();row.Observe(78,second.Count);row.Observe(79,second.Error?.GetType().FullName,exceptionType:true);
                    }
                    else
                    {
                        TrackCurrent();
                        var rest=ReadRemaining();row.Observe(90,rest.Count);row.Observe(91,rest.Error?.GetType().FullName,exceptionType:true);
                    }
                    TrackCurrent();
                    if (iterator.MoveNext()) throw new InvalidOperationException("Exhausted child iterator advanced again");
                    rows.Add(row);

                    void TrackCurrent()
                    {
                        var error=OfflineTheoryMirrors.Capture(() =>
                        {
                            if (iterator.Current is not DS.DirectoryEntry entry) throw new InvalidDataException("Child iterator materialized an unexpected type");
                            entries.Add(entry);
                        });
                        if (error is not null && error is not InvalidOperationException) throw error;
                    }
                    (int Count,Exception? Error) ReadRemaining()
                    {
                        var names=new HashSet<string>(StringComparer.Ordinal);
                        var seen=0;
                        var error=OfflineTheoryMirrors.Capture(() =>
                        {
                            while (iterator.MoveNext())
                            {
                                var entry=iterator.Current as DS.DirectoryEntry ?? throw new InvalidDataException("Child iterator did not materialize an entry");
                                entries.Add(entry);
                                var name=entry.Name;
                                if (!Enumerable.Range(0,count).Any(i => name=="CN=child-"+i) || !names.Add(name))
                                    throw new InvalidDataException("Seeded child name/uniqueness control failed");
                                seen++;
                            }
                        });
                        return (seen,error);
                    }
                }
                finally
                {
                    (iterator as IDisposable)?.Dispose();
                    foreach (var entry in entries) entry.Dispose();
                }
            }
            if (state.Opens==0 || !SpinWait.SpinUntil(() => Volatile.Read(ref state.Closes)==state.Opens
                && resources.All(r => Volatile.Read(ref r.Disposals)==1),TimeSpan.FromSeconds(5)))
                throw new InvalidOperationException("Child replay cursor/session ownership failed");
        }
        verify("CompatibilityChildEnumeratorComparisonTests.Child_enumerator_position_and_reset_match_microsoft",rows);
    }
    private sealed class State(int count)
    {
        internal readonly int Count=count;
        internal int Opens,Closes;
    }
    private sealed class Transport(State state) : ILdapConversationTransport,IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        private static LdapTransportEntry Item(string dn) => new(dn,new(StringComparer.OrdinalIgnoreCase)
        {
            ["objectClass"]=[Encoding.UTF8.GetBytes("container")],
            ["cn"]=[Encoding.UTF8.GetBytes(dn[..dn.IndexOf(',')][3..])],
            ["distinguishedName"]=[Encoding.UTF8.GetBytes(dn)],
        },[]);
        private static void Controls(LdapSearchCommand command)
        {
            if (command.TypesOnly || (command.Controls ?? []).Any(c => c.Oid!="1.2.840.113556.1.4.801"))
                throw new InvalidDataException("Unreviewed child read control");
        }
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.BaseDn=="" && command.Attributes.SequenceEqual(new[] { "schemaNamingContext" }))
                return new(ResultCode.Success,"",null,[],[],[],[]);
            Controls(command);
            if (command.Scope!=System.DirectoryServices.Protocols.SearchScope.Base || command.Filter!="(objectClass=*)"
                || (command.BaseDn!=RootDn && !Enumerable.Range(0,state.Count).Any(i => command.BaseDn=="CN=child-"+i+","+RootDn)))
                throw new InvalidDataException("Unreviewed child metadata target");
            var item=Item(command.BaseDn);
            return new(ResultCode.Success,"",null,[item],[],[],[]);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Controls(command);
            if (command.BaseDn!=RootDn || command.Scope!=System.DirectoryServices.Protocols.SearchScope.OneLevel
                || command.Filter!="(objectClass=*)" || pageSize!=0 || command.SizeLimit!=0)
                throw new InvalidDataException("Unreviewed child enumeration request");
            Interlocked.Increment(ref state.Opens);
            return ValueTask.FromResult<ILdapSearchCursor>(new Cursor(state));
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
            => throw new InvalidDataException("Child enumeration fixture cannot mutate");
        public void Dispose() => Interlocked.Increment(ref Disposals);
        private sealed class Cursor(State state) : ILdapSearchCursor
        {
            private int index,closed;
            public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining,CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if (index<state.Count) return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(Item("CN=child-"+(index++)+","+RootDn)));
                if (index++!=state.Count) throw new InvalidDataException("Child cursor advanced past terminal event");
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success,"",null,[],[]),false));
            }
            public ValueTask NextPageAsync(TimeSpan remaining,CancellationToken token,TimeSpan? serverTimeLimit=null)
                => throw new InvalidDataException("Unreviewed child paging request");
            public ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref closed,1)==0) Interlocked.Increment(ref state.Closes);
                return ValueTask.CompletedTask;
            }
        }
    }
}
