using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Scripted managed search events isolate response ownership from server sorting,
// binding and window selection. No native handles or private field edits.
internal static class NeutralVlvMirrors
{
    private const string RootDn="DC=example,DC=test";
    private const string UserDn="CN=window-user,"+RootDn;

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var exhaust in new[] { false,true })
        {
            var resources=new List<Transport>();
            using var root=new DS.DirectoryEntry("LDAP://unused.example.test/"+RootDn);
            root.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
            {
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid controlled VLV admission");
                return Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport(); resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            };
            var view=new DS.DirectoryVirtualListView(0,0,1);
            using var searcher=new DS.DirectorySearcher(root,"(objectClass=*)",new[] { "distinguishedName" },DS.SearchScope.OneLevel)
            {
                Sort=new DS.SortOption("cn",DS.SortDirection.Ascending),VirtualListView=view,
            };
            using var results=searcher.FindAll();
            var cursor=results.GetEnumerator();
            try
            {
                if (!cursor.MoveNext()) throw new InvalidOperationException("Controlled VLV window was empty");
                var item=(DS.SearchResult)cursor.Current;
                if ((string)item.Properties["distinguishedName"][0]!=UserDn || view.ApproximateTotal!=3)
                    throw new InvalidOperationException("Controlled VLV row/control precondition failed");
                if (exhaust && cursor.MoveNext()) throw new InvalidOperationException("Controlled VLV window returned extra rows");
            }
            finally { (cursor as IDisposable)?.Dispose(); }
            results.Dispose();
            DS.DirectoryVirtualListView? read=null;
            var error=OfflineTheoryMirrors.Capture(() => read=searcher.VirtualListView);
            searcher.VirtualListView=null;
            if (searcher.VirtualListView is not null) throw new InvalidOperationException("Cleared VLV getter did not recover");
            var row=new Sequence();
            row.Observe(138,error?.GetType().Name,exceptionType:true);
            row.Observe(139,(error as ObjectDisposedException)?.ObjectName);
            row.Observe(141,ReferenceEquals(view,read));
            rows.Add(row);
            // The streaming producer owns asynchronous lease cleanup after
            // collection cancellation. Bound this wait and verify every owner.
            if (!SpinWait.SpinUntil(() => resources.Count>=2 && resources.All(resource => Volatile.Read(ref resource.Disposals)==1),TimeSpan.FromSeconds(5)))
                throw new InvalidOperationException("Controlled VLV session cleanup did not finish");
            if (resources.Sum(resource => resource.Opens)!=1 || resources.Sum(resource => resource.Closes)!=1)
                throw new InvalidOperationException("Controlled VLV search cursor ownership failed");
        }
        verify("CompatibilityVlvResultDisposalComparisonTests.View_getter_after_result_disposal_matches_exhaustion_state",rows);
    }

    private sealed class Transport : ILdapConversationTransport,ILdapSearchCursor,IDisposable
    {
        internal int Disposals,Opens,Closes;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.BaseDn=="" && command.Attributes.SequenceEqual(new[] { "schemaNamingContext" }))
                return new(ResultCode.Success,"",null,[],[],[],[]);
            if (command.BaseDn==RootDn && command.Scope==System.DirectoryServices.Protocols.SearchScope.Base)
                return new(ResultCode.Success,"",null,[new(RootDn,new(StringComparer.OrdinalIgnoreCase),[])],[],[],[]);
            throw new InvalidDataException("Unexpected controlled VLV schema/root request");
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var controls=command.Controls ?? [];
            if (command.BaseDn!=RootDn || command.Scope!=System.DirectoryServices.Protocols.SearchScope.OneLevel || pageSize!=0
                || !controls.Any(control => control.Oid=="2.16.840.1.113730.3.4.9")
                || !controls.Any(control => control.Oid=="1.2.840.113556.1.4.473"))
                throw new InvalidDataException("Controlled VLV request shape changed");
            Opens++;
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (position++==0)
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(new(UserDn,
                    new(StringComparer.OrdinalIgnoreCase) { ["distinguishedName"]=[Encoding.UTF8.GetBytes(UserDn)] },[])));
            if (position!=2) throw new InvalidDataException("Controlled VLV cursor read past terminal result");
            var writer=new AsnWriter(AsnEncodingRules.BER);
            writer.PushSequence();writer.WriteInteger(1);writer.WriteInteger(3);writer.WriteEnumeratedValue(ResultCode.Success);writer.PopSequence();
            LdapTransportControl[] controls=[new("2.16.840.1.113730.3.4.10",writer.Encode(),false)];
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success,"",null,[],controls),false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining,CancellationToken token,TimeSpan? serverTimeLimit=null)
            => throw new InvalidDataException("Controlled VLV window attempted paging");
        public ValueTask DisposeAsync() { Interlocked.Increment(ref Closes);return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
            => throw new InvalidDataException("Controlled VLV fixture attempted a mutation");
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }
}
