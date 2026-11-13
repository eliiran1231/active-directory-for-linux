using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using DS = AdForLinux.DirectoryServices;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using Sequence = OfflineTheoryMirrors.Sequence;

// Normal managed transport/session constructors only. No LDAP handles, native
// backend, private field edits or live endpoint are used by this producer.
internal static class NeutralFailureMirrors
{
    private const string RootDn="DC=example,DC=test";
    private const string MissingDn="CN=controlled-missing,"+RootDn;

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var findAll in new[] { false,true })
        {
            var resources=new List<Transport>();
            LdapConnectionProvider.Session[] Open(LdapConnectionOptions options,int count,DS.ReferralChasingOption referrals,bool fresh,long minimum)
            {
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid controlled search admission");
                return Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport();
                    resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            }
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test",RootDn,
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            context.SearchRoot.OperationSessionFactory=Open;
            using var filter=new AM.UserPrincipal(context);
            using var searcher=new AM.PrincipalSearcher(filter);
            var native=(DS.DirectorySearcher)searcher.GetUnderlyingSearcher();
            var originalRoot=native.SearchRoot!;
            if (string.IsNullOrEmpty(originalRoot.Name)) throw new InvalidOperationException("Controlled positive root did not resolve");
            using var missing=new DS.DirectoryEntry("LDAP://unused.example.test/"+MissingDn);
            missing.OperationSessionFactory=Open;
            var absence=OfflineTheoryMirrors.Capture(() => missing.RefreshCache(new[] { "distinguishedName" }));
            if (absence is not DS.DirectoryServicesCOMException noSuchObject || noSuchObject.ErrorCode!=unchecked((int)0x80072030))
                throw new InvalidOperationException("Controlled missing-root precondition failed",absence);
            native.SizeLimit=7;
            try
            {
                native.SearchRoot=missing;
                var error=OfflineTheoryMirrors.Capture(() =>
                {
                    if (findAll) { using var result=searcher.FindAll(); }
                    else { using var result=searcher.FindOne(); }
                });
                var row=new Sequence();
                row.Observe(86,error?.GetType().Name,exceptionType:true);
                row.Observe(87,(error as AM.PrincipalOperationException)?.ErrorCode);
                row.Observe(89,native.SizeLimit);
                row.Observe(90,ReferenceEquals(missing,native.SearchRoot));
                rows.Add(row);
            }
            finally { native.SearchRoot=originalRoot; }
            if (resources.Count==0 || resources.Any(resource => resource.Disposals!=1))
                throw new InvalidOperationException("Controlled search session leaked");
            if (!resources.Any(resource => resource.MissingReads>0)) throw new InvalidOperationException("Controlled failure was not exercised");
        }
        verify("CompatibilityNativeFailureStateComparisonTests.Failed_search_preserves_native_limit_like_microsoft",rows);
        RetainedRoot(verify);
        MissingEntries(verify);
    }

    private static void MissingEntries(Action<string,List<Sequence>> verify)
    {
        var resources=new List<Transport>();
        Exception? Read(Action<DS.DirectoryEntry> action)
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/"+MissingDn);
            entry.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
            {
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid missing-entry admission");
                return Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport();resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            };
            return OfflineTheoryMirrors.Capture(() => action(entry));
        }
        var name=Read(entry => _=entry.Name);
        var parent=Read(entry => _=entry.Parent);
        var row=new Sequence();
        row.Observe(189,name?.GetType().Name,exceptionType:true);
        row.Observe(190,(name as DS.DirectoryServicesCOMException)?.ErrorCode);
        row.Observe(191,parent?.GetType().Name,exceptionType:true);
        row.Observe(192,(parent as DS.DirectoryServicesCOMException)?.ErrorCode);
        verify("DirectoryEntryComparisonTests.Missing_entry_name_and_parent_errors_match",[row]);
        var refresh=Read(entry => entry.RefreshCache());
        row=new Sequence();
        row.Observe(207,refresh?.GetType().Name,exceptionType:true);
        row.Observe(208,refresh?.HResult);
        verify("ExceptionTranslationComparisonTests.MissingObjectHasDirectoryServicesComExceptionParity",[row]);
        if (resources.Count==0 || resources.Sum(resource => resource.MissingReads)!=3
            || resources.Any(resource => resource.Disposals!=1))
            throw new InvalidOperationException("Missing-entry read/session ownership failed");
    }

    private static void RetainedRoot(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var owner in new[] { "Neither","Searcher","Context" })
        {
            var resources=new List<Transport>();
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test",RootDn,
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            context.SearchRoot.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
                Enumerable.Range(0,count).Select(_ =>
                {
                    var transport=new Transport();resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            using var filter=new AM.UserPrincipal(context);
            using var searcher=new AM.PrincipalSearcher(filter);
            var native=(DS.DirectorySearcher)searcher.GetUnderlyingSearcher();
            var root=native.SearchRoot ?? throw new InvalidOperationException("Retained root was missing");
            var before=root.Name;
            if (string.IsNullOrEmpty(before) || resources.Count==0)
                throw new InvalidOperationException("Retained root did not complete its positive read");
            if (owner=="Searcher") searcher.Dispose();
            else if (owner=="Context") context.Dispose();
            string? after=null;
            var error=OfflineTheoryMirrors.Capture(() => after=root.Name);
            var row=new Sequence();
            row.Observe(81,error?.GetType().Name,exceptionType:true);
            if (owner=="Context") row.Observe(84,after);
            else
            {
                row.Observe(82,(error as ObjectDisposedException)?.ObjectName);
                if (after!=before) throw new InvalidOperationException("Borrowed root positive name control changed");
            }
            rows.Add(row);
            // The context owns the borrowed root even after searcher disposal.
            context.Dispose();
            if (resources.Any(resource => resource.Disposals!=1 || resource.MissingReads!=0))
                throw new InvalidOperationException("Retained root session ownership failed");
        }
        verify("CompatibilityRetainedSearchRootComparisonTests.Retained_native_root_lifetime_matches_microsoft",rows);
    }

    private sealed class Transport : ILdapConversationTransport,ILdapSearchCursor,IDisposable
    {
        internal int Disposals,MissingReads;
        private bool terminal;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls
            | LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        private static void Check(CancellationToken token) => token.ThrowIfCancellationRequested();
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            Check(token);
            if (command.BaseDn==MissingDn)
            {
                MissingReads++;
                return new(ResultCode.NoSuchObject,"",null,[],[],[],[]);
            }
            if (command.BaseDn!=RootDn) throw new InvalidDataException("Unexpected controlled root read");
            return new(ResultCode.Success,"",null,[new(RootDn,new(StringComparer.OrdinalIgnoreCase),[])],[],[],[]);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
        {
            Check(token);
            if (command.BaseDn!=MissingDn) throw new InvalidDataException("Unexpected controlled query root");
            MissingReads++;
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining,CancellationToken token)
        {
            Check(token);
            if (terminal) throw new InvalidDataException("Controlled failure cursor read after terminal result");
            terminal=true;
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.NoSuchObject,"",null,[],[]),false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining,CancellationToken token,TimeSpan? serverTimeLimit=null)
            => throw new InvalidDataException("Controlled failure advanced a page");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
            => throw new InvalidDataException("Controlled read-only fixture attempted a mutation");
        public void Dispose() => Disposals++;
    }
}
