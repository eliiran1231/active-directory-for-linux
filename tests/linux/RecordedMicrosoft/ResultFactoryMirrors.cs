using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Real DirectorySearcher dispatch/materialization against one managed row.
// The captured TLS flag is configuration evidence; no TLS/network is opened.
internal static class ResultFactoryMirrors
{
    private const string Dn="CN=snapshot-user,DC=example,DC=test";
    private const string Path="LDAP://unused.example.test:636/"+Dn;

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var query in new[] { "FindOne","FindAll" })
        foreach (var change in new[] { "path","authentication" })
        {
            var resources=new List<Transport>();
            using var root=new DS.DirectoryEntry(Path,null,null,DS.AuthenticationTypes.SecureSocketsLayer);
            root.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
            {
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid result-factory admission");
                return Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport();resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            };
            using var searcher=new DS.DirectorySearcher(root) { SearchScope=DS.SearchScope.Base };
            DS.SearchResult result;
            if (query=="FindOne") result=searcher.FindOne() ?? throw new InvalidOperationException("Managed result was missing");
            else
            {
                using var results=searcher.FindAll();
                result=results.Cast<DS.SearchResult>().Single();
            }
            if ((string)result.Properties["sAMAccountName"][0]!="snapshot-user")
                throw new InvalidOperationException("Managed result role precondition failed");
            if (change=="path") root.Path="LDAP://snapshot.invalid/DC=placeholder,DC=invalid";
            else root.AuthenticationType=DS.AuthenticationTypes.Anonymous;
            // This entry is never bound; the result carries an immutable recipe.
            using var entry=result.GetDirectoryEntry();
            if (result.Path!=Path || entry.Path!=Path)
                throw new InvalidOperationException("Local captured-path control failed");
            var row=new Sequence();row.Observe(141,(int)entry.AuthenticationType);rows.Add(row);
            if (!SpinWait.SpinUntil(() => resources.Count>=2 && resources.All(r => Volatile.Read(ref r.Disposals)==1),TimeSpan.FromSeconds(5)))
                throw new InvalidOperationException("Result-factory managed session cleanup failed");
            var opens=resources.Sum(r => r.Opens);var closes=resources.Sum(r => r.Closes);
            if (opens!=1 || closes!=opens)
                throw new InvalidOperationException("Result-factory streaming cursor ownership failed");
        }
        verify("CompatibilityResultPathMutationComparisonTests.Entry_factory_retains_search_time_root_state_like_microsoft",rows);
        NamesOnly(verify);
    }

    private static void NamesOnly(Action<string,List<Sequence>> verify)
    {
        foreach (var descriptionPresent in new[] { true,false })
        {
            var resources=new List<Transport>();
            using var root=new DS.DirectoryEntry(Path,null,null,DS.AuthenticationTypes.SecureSocketsLayer);
            root.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
            {
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid names-only admission");
                return Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport(descriptionPresent);resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            };
            using var searcher=new DS.DirectorySearcher(root) { SearchScope=DS.SearchScope.Base,PropertyNamesOnly=true };
            searcher.PropertiesToLoad.AddRange(descriptionPresent
                ? new[] { "displayName","description" } : new[] { "sAMAccountName","description" });
            var result=searcher.FindOne() ?? throw new InvalidOperationException("Names-only result was absent");
            var names=result.Properties.PropertyNames.Cast<string>().Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var expected=descriptionPresent ? new[] { "adspath","description","displayName" } : new[] { "adspath","sAMAccountName" };
            if (!names.SequenceEqual(expected,StringComparer.OrdinalIgnoreCase) || result.Path!=Path
                || (!descriptionPresent && result.Properties.Contains("description")))
                throw new InvalidOperationException("Names-only local key/path shape control failed");
            var row=new Sequence();
            foreach (var name in names) row.Observe(descriptionPresent ? 54 : 98,result.Properties[name].Count);
            if (!SpinWait.SpinUntil(() => resources.Count>=2 && resources.All(r => Volatile.Read(ref r.Disposals)==1),TimeSpan.FromSeconds(5))
                || resources.Sum(r => r.Opens)!=1 || resources.Sum(r => r.Closes)!=1)
                throw new InvalidOperationException("Names-only managed cursor/session ownership failed");
            verify("PropertyNamesOnlyComparisonTests."+(descriptionPresent
                ? "PropertyNamesOnly_result_shape_matches_microsoft"
                : "PropertyNamesOnly_does_not_include_absent_requested_attributes"),[row]);
        }
    }

    private sealed class Transport(bool? namesOnly=null) : ILdapConversationTransport,ILdapSearchCursor,IDisposable
    {
        internal int Disposals,Opens,Closes;
        private int position;
        private bool typesOnly;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        private LdapTransportEntry Item(bool requestedTypesOnly)
        {
            if (requestedTypesOnly && namesOnly is { } present)
            {
                Dictionary<string,byte[][]> names=new(StringComparer.OrdinalIgnoreCase);
                if (present) { names["displayName"]=[];names["description"]=[]; }
                else names["sAMAccountName"]=[];
                return new(Dn,names,[]);
            }
            return new(Dn,new(StringComparer.OrdinalIgnoreCase)
            {
                ["distinguishedName"]=[Encoding.UTF8.GetBytes(Dn)],
                ["sAMAccountName"]=[Encoding.UTF8.GetBytes("snapshot-user")],
            },[]);
        }
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.BaseDn=="" && command.Attributes.SequenceEqual(new[] { "schemaNamingContext" }))
                return new(ResultCode.Success,"",null,[],[],[],[]);
            Validate(command);
            return new(ResultCode.Success,"",null,[Item(command.TypesOnly)],[],[],[]);
        }
        private void Validate(LdapSearchCommand command)
        {
            if (command.BaseDn!=Dn || command.Scope!=System.DirectoryServices.Protocols.SearchScope.Base
                || command.Filter!="(objectClass=*)" || (command.Controls ?? []).Any(c => c.Oid!="1.2.840.113556.1.4.801"))
                throw new InvalidDataException("Unexpected result-factory read request");
            if (command.TypesOnly)
            {
                if (namesOnly is not { } present) throw new InvalidDataException("Unreviewed types-only request");
                var expected=(present ? new[] { "displayName","description","ADsPath" }
                    : new[] { "sAMAccountName","description","ADsPath" }).Order(StringComparer.OrdinalIgnoreCase);
                if (!command.Attributes.Order(StringComparer.OrdinalIgnoreCase).SequenceEqual(expected,StringComparer.OrdinalIgnoreCase))
                    throw new InvalidDataException("Names-only requested attribute controls failed");
            }
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Validate(command);
            if (pageSize!=0) throw new InvalidDataException("Result-factory source did not request paging");
            typesOnly=command.TypesOnly;Opens++;return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (position++==0) return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(Item(typesOnly)));
            if (position!=2) throw new InvalidDataException("Result-factory cursor read past terminal event");
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success,"",null,[],[]),false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining,CancellationToken token,TimeSpan? serverTimeLimit=null)
            => throw new InvalidDataException("Result-factory cursor unexpectedly paged");
        public ValueTask DisposeAsync() { Interlocked.Increment(ref Closes);return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
            => throw new InvalidDataException("Result-factory fixture attempted mutation");
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }
}
