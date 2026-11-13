using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Finite normal insert/save/delete fixture. Its one synthetic identity is created
// only by an actual Add command, never by editing Principal/DirectoryEntry state.
internal static class SavedPrincipalMirrors
{
    private const string RootDn="DC=example,DC=test",Name="saved-cache-user",Dn="CN="+Name+","+RootDn;
    private static readonly Guid Identity=new("11111111-2222-3333-4444-555555555555");

    internal static void ValidateCreationBoundary()
    {
        foreach (var budgetAware in new[] { false,true })
        {
            using var fixture=new Fixture(budgetAware);
            if (!fixture.User.IsPersisted || fixture.User.Guid!=Identity || fixture.User.Enabled!=false)
                throw new InvalidOperationException("Normal saved-new principal control failed");
        }
    }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var timestamp in new[] { "absent","zero","positive" })
        {
            using var fixture=new Fixture();var entry=fixture.Entry;
            var logon=new DateTime(2030,1,2,3,4,5,DateTimeKind.Utc).ToFileTimeUtc();
            var replicated=new DateTime(2031,2,3,4,5,6,DateTimeKind.Utc).ToFileTimeUtc();
            entry.Properties["lastLogon"].Value=logon;
            if (timestamp=="absent") entry.Properties["lastLogonTimestamp"].Clear();
            else entry.Properties["lastLogonTimestamp"].Value=timestamp=="zero" ? 0L : replicated;
            if (Convert.ToInt64(entry.Properties["lastLogon"].Value,CultureInfo.InvariantCulture)!=logon
                || entry.Properties["lastLogonTimestamp"].Count!=(timestamp=="absent" ? 0 : 1))
                throw new InvalidOperationException("Saved-new timestamp cache precondition failed");
            var value=fixture.User.LastLogon;
            if (timestamp!="zero" && value is null) throw new InvalidOperationException("Saved-new timestamp did not project");
            var row=new Sequence();row.Observe(70,value?.Ticks);row.ObserveDateTimeKind(71,value?.Kind);rows.Add(row);
        }
        verify("CompatibilityCachedLogonProjectionComparisonTests.LastLogon_projects_cached_timestamp_presence_like_microsoft",rows);
        rows=[];
        foreach (var change in new[] { false,true })
        {
            using var fixture=new Fixture();var entry=fixture.Entry;
            var initial=new DateTime(2030,1,2,3,4,5,DateTimeKind.Utc);var replacement=initial.AddDays(11);
            entry.Properties["lastLogon"].Value=initial.AddDays(-1).ToFileTimeUtc();
            entry.Properties["lastLogonTimestamp"].Value=initial.ToFileTimeUtc();
            var first=fixture.User.LastLogon;
            if (first is null || first.Value.Ticks!=initial.Ticks)
                throw new InvalidOperationException("Saved-new first LastLogon projection control failed");
            var row=new Sequence();row.Observe(118,first.Value.Ticks);row.ObserveDateTimeKind(119,first.Value.Kind);
            if (change) entry.Properties["lastLogonTimestamp"].Value=replacement.ToFileTimeUtc();
            if (Convert.ToInt64(entry.Properties["lastLogonTimestamp"].Value,CultureInfo.InvariantCulture)!=(change ? replacement : initial).ToFileTimeUtc())
                throw new InvalidOperationException("Saved-new changed raw timestamp control failed");
            var second=fixture.User.LastLogon;
            row.Observe(118,second?.Ticks);row.ObserveDateTimeKind(119,second?.Kind);rows.Add(row);
        }
        verify("CompatibilityCachedLogonProjectionComparisonTests.LastLogon_reread_observes_underlying_cache_changes_like_microsoft",rows);
        PendingMembers(verify);
        UnsavedGroupQueries(verify);
        IdentityAddedLifetime(verify);
        IdentityLookups(verify);
        MissingSearchResult(verify);
        ExtensionAlias(verify);
        ExpirationPersistence(verify);
        ChildSchemaLookup(verify);
        QbeFindOne(verify);
        QbeCustomization(verify);
    }

    private static void PendingMembers(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var operation in new[] { "contains","remove","add" })
        {
            AM.GroupPrincipal? group=null;
            try
            {
                using var fixture=new Fixture(beforeSave:user =>
                {
                    group=new AM.GroupPrincipal(user.Context);
                    if (user.DistinguishedName is not null) throw new InvalidOperationException("Pending member was already saved");
                    group.Members.Add(user);
                });
                var owner=group ?? throw new InvalidOperationException("Pending member owner was missing");
                using var reloadedEntry=fixture.Context.CreateDirectoryEntry(Dn);
                using var reloaded=AM.Principal.Materialize(fixture.Context,typeof(AM.UserPrincipal),reloadedEntry) as AM.UserPrincipal
                    ?? throw new InvalidOperationException("Reloaded member did not materialize");
                if (ReferenceEquals(fixture.User,reloaded) || !fixture.User.Equals(reloaded) || reloaded.Guid!=Identity)
                    throw new InvalidOperationException("Reloaded member stored-identity control failed");
                bool? result=null;
                var error=OfflineTheoryMirrors.Capture(() =>
                {
                    if (operation=="contains") result=owner.Members.Contains(reloaded);
                    else if (operation=="remove") result=owner.Members.Remove(reloaded);
                    else owner.Members.Add(reloaded);
                });
                // Local source contract guards only; the recorded Error strings are opaque.
                if ((operation=="add" && error is not AM.PrincipalExistsException) || (operation!="add" && error is not null))
                    throw new InvalidOperationException("Pending member operation control failed",error);
                var row=new Sequence();row.Observe(61,result);row.Observe(62,owner.Members.Count);
                row.Observe(63,owner.Members.Contains(fixture.User));rows.Add(row);
            }
            finally { group?.Dispose(); }
        }
        verify("MembershipLifecycleComparisonTests.Pending_member_matches_reloaded_wrapper_after_member_save",rows);
        using (var fixture=new Fixture())
        {
            using var group=new AM.GroupPrincipal(fixture.Context);
            group.Members.Add(fixture.User);
            fixture.User.DisplayName="pending-member-display";
            using var cursor=group.Members.GetEnumerator();
            if (!cursor.MoveNext()) throw new InvalidOperationException("Pending enumeration was empty");
            var member=cursor.Current;
            try
            {
                if (member.Guid!=fixture.User.Guid) throw new InvalidOperationException("Pending enumeration identity control failed");
                var row=new Sequence();row.Observe(82,ReferenceEquals(fixture.User,member));
                if (member.DisplayName!="pending-member-display" || cursor.MoveNext())
                    throw new InvalidOperationException("Pending enumeration staged-value/count control failed");
                verify("NextBatchMembershipComparisonTests.Pending_membership_enumeration_retains_the_inserted_principal_instance",[row]);
            }
            finally { if (!ReferenceEquals(fixture.User,member)) member.Dispose(); }
        }
    }

    private static void UnsavedGroupQueries(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var recursive in new[] { false,true })
        foreach (var stageMember in new[] { false,true })
        {
            using var fixture=new Fixture();
            using var group=new AM.GroupPrincipal(fixture.Context);
            if (stageMember) group.Members.Add(fixture.User);
            if (group.Members.Count!=(stageMember ? 1 : 0)) throw new InvalidOperationException("Unsaved group pending count control failed");
            int? count=null;
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                using var results=group.GetMembers(recursive);
                var members=results.ToArray();
                try { count=members.Length; }
                finally { foreach (var member in members) if (!ReferenceEquals(member,fixture.User)) member.Dispose(); }
            });
            // Source also requires successful completion; its Error string is not admitted.
            if (error is not null) throw new InvalidOperationException("Unsaved GetMembers operation failed",error);
            var row=new Sequence();row.Observe(130,count);row.Observe(131,group.Members.Count);rows.Add(row);
        }
        verify("NextBatchMembershipComparisonTests.GetMembers_queries_persisted_membership_rather_than_pending_collection",rows);
    }

    private static void IdentityAddedLifetime(Action<string,List<Sequence>> verify)
    {
        using var fixture=new Fixture(identityLookup:true);
        using var group=new AM.GroupPrincipal(fixture.Context);
        group.Members.Add(fixture.Context,AM.IdentityType.DistinguishedName,Dn);
        using var member=group.Members.Single();
        if (member.Guid!=fixture.User.Guid || ReferenceEquals(member,fixture.User))
            throw new InvalidOperationException("Identity-added lookup/materialization control failed");
        group.Dispose();
        bool? matches=null;
        var error=OfflineTheoryMirrors.Capture(() => matches=member.SamAccountName==fixture.User.SamAccountName);
        if (error is not null) throw new InvalidOperationException("Identity-added member became unusable",error);
        var row=new Sequence();row.Observe(106,matches);
        if (fixture.Store.LookupOpens!=1 || !SpinWait.SpinUntil(() => Volatile.Read(ref fixture.Store.LookupCloses)==1,TimeSpan.FromSeconds(5)))
            throw new InvalidOperationException("Identity-added query cursor ownership failed");
        verify("MembershipLifecycleComparisonTests.Identity_added_member_remains_usable_after_group_disposal",[row]);
    }

    private static void IdentityLookups(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var type in new[] { AM.IdentityType.SamAccountName,AM.IdentityType.Name })
        {
            using var fixture=new Fixture(identityLookup:true);
            using var found=AM.UserPrincipal.FindByIdentity(fixture.Context,type,Name);
            if (found is null || found.Guid!=Identity || ReferenceEquals(found,fixture.User))
                throw new InvalidOperationException("Explicit user lookup materialization control failed");
            var row=new Sequence();row.Observe(117,found is not null);rows.Add(row);
            if (fixture.Store.LookupOpens!=1) throw new InvalidOperationException("Explicit lookup was not bounded to one query");
        }
        verify("UserPrincipalComparisonTests.FindByIdentity_agrees_for_each_identity_type",rows);
        using var missingFixture=new Fixture(identityLookup:true);
        using var missing=AM.UserPrincipal.FindByIdentity(missingFixture.Context,"no-such-user-xyz-123");
        var absent=new Sequence();absent.Observe(135,missing is not null);
        if (missingFixture.Store.LookupOpens==0) throw new InvalidOperationException("Missing lookup skipped managed dispatch");
        verify("UserPrincipalComparisonTests.FindByIdentity_agrees_when_the_user_is_missing",[absent]);
    }

    private static void MissingSearchResult(Action<string,List<Sequence>> verify)
    {
        using var fixture=new Fixture(identityLookup:true);
        using var root=fixture.Context.CreateDirectoryEntry(RootDn);
        using var searcher=new DS.DirectorySearcher(root,"(sAMAccountName=no-such-user-xyz-123)");
        var row=new Sequence();row.Observe(699,searcher.FindOne() is not null);
        if (fixture.Store.LookupOpens!=1 || fixture.User.Guid!=Identity)
            throw new InvalidOperationException("Empty FindOne dispatch/nonempty-store control failed");
        verify("DirectoryEntryComparisonTests.Searcher_findone_agrees_when_nothing_matches",[row]);
    }

    private static void ExtensionAlias(Action<string,List<Sequence>> verify)
    {
        const string marker="owned-extension-marker";
        var rows=new List<Sequence>();
        using (var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test",RootDn,
            AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null))
        using (var user=new ExtensionUser(context))
        {
            object?[] input=[marker];user.Write(input);
            if (!ReferenceEquals(input,user.Read()) || user.IsPersisted)
                throw new InvalidOperationException("Unsaved extension staging precondition failed");
            var row=new Sequence();row.Observe(39,ReferenceEquals(input,user.Read()));rows.Add(row);
            input[0]="local-array-edit";
            if (user.Read().Length!=1 || !Equals(user.Read()[0],"local-array-edit"))
                throw new InvalidOperationException("Unsaved retained array edit control failed");
        }
        object?[] savedInput=[marker];
        using (var fixture=new Fixture(extension:true,beforeSave:user =>
        {
            var extension=(ExtensionUser)user;extension.Write(savedInput);
            if (!ReferenceEquals(savedInput,extension.Read())) throw new InvalidOperationException("Pre-save extension alias failed");
        }))
        {
            var user=(ExtensionUser)fixture.User;
            RequirePersistedMarker();
            var row=new Sequence();row.Observe(39,ReferenceEquals(savedInput,user.Read()));rows.Add(row);
            savedInput[0]="local-array-edit";
            if (user.Read().Length!=1 || !Equals(user.Read()[0],"local-array-edit"))
                throw new InvalidOperationException("Saved retained array edit control failed");
            RequirePersistedMarker();
            void RequirePersistedMarker()
            {
                using var fresh=fixture.Context.CreateDirectoryEntry(Dn);
                fresh.RefreshCache(["otherTelephone","objectGUID"]);
                if (fresh.Guid!=Identity || fresh.Properties["otherTelephone"].Count!=1
                    || !Equals(fresh.Properties["otherTelephone"].Value,marker))
                    throw new InvalidOperationException("Fresh persisted extension marker control failed");
            }
        }
        verify("CompatibilityExtensionPersistenceLifecycleComparisonTests.Extension_array_retains_local_alias_across_save_like_microsoft",rows);
    }

    private static void QbeCustomization(Action<string,List<Sequence>> verify)
    {
        using var fixture=new Fixture(identityLookup:true,pagedQbe:true);
        using var example=new AM.UserPrincipal(fixture.Context) { SamAccountName=Name };
        using var searcher=new AM.PrincipalSearcher(example);
        var underlying=searcher.GetUnderlyingSearcher() as DS.DirectorySearcher
            ?? throw new InvalidOperationException("QBE underlying searcher had an unexpected type");
        if (searcher.GetUnderlyingSearcherType()!=typeof(DS.DirectorySearcher) || underlying.ServerTimeLimit!=TimeSpan.FromSeconds(30))
            throw new InvalidOperationException("QBE underlying configuration controls failed");
        var row=new Sequence();row.Observe(161,underlying.PageSize);
        underlying.PageSize=1;underlying.SizeLimit=1;
        _=fixture.Context.SearchRoot.Name;
        fixture.Store.PairNextAdmission=true;
        using var results=searcher.FindAll();
        using var found=results.Single();
        if (found is not AM.UserPrincipal || found.Guid!=Identity || ReferenceEquals(found,fixture.User)
            || fixture.Store.LookupOpens!=1 || fixture.Store.PagedLookups!=1 || fixture.Store.PairAdmissions!=1 || fixture.Store.PairNextAdmission)
            throw new InvalidOperationException("Customized QBE query/materialization controls failed");
        row.Observe(176,underlying.PageSize);row.Observe(177,underlying.SizeLimit);
        verify("PrincipalSearcherComparisonTests.Underlying_searcher_customization_matches",[row]);
    }

    private static void QbeFindOne(Action<string,List<Sequence>> verify)
    {
        foreach (var missing in new[] { false,true })
        {
            using var fixture=new Fixture(identityLookup:true);
            using var example=new AM.UserPrincipal(fixture.Context) { SamAccountName=missing ? "no-such-user-xyz-123" : Name };
            using var searcher=new AM.PrincipalSearcher(example);
            using var found=searcher.FindOne();
            if (fixture.Store.LookupOpens!=1 || fixture.User.Guid!=Identity
                || (!missing && (found?.Guid!=Identity || ReferenceEquals(found,fixture.User))))
                throw new InvalidOperationException("QBE FindOne dispatch/materialization control failed");
            var row=new Sequence();row.Observe(missing ? 138 : 70,found is not null);
            if (!missing) row.Observe(72,found is AM.UserPrincipal);
            verify("PrincipalSearcherComparisonTests."+(missing ? "FindOne_agrees_when_nothing_matches" : "FindOne_by_sam_account_name_matches"),[row]);
        }
    }

    private static void ChildSchemaLookup(Action<string,List<Sequence>> verify)
    {
        using var fixture=new Fixture();
        using var root=fixture.Context.CreateDirectoryEntry(RootDn);
        using var control=root.Children.Find("CN="+Name,"user");
        if (control.Guid!=Identity || control.SchemaClassName!="user")
            throw new InvalidOperationException("Child lookup positive schema/identity control failed");
        var error=OfflineTheoryMirrors.Capture(() => { using var unexpected=root.Children.Find("CN="+Name,"person"); });
        if (error is not InvalidOperationException) throw new InvalidOperationException("Child lookup did not reject the ancestor class",error);
        using var recovered=root.Children.Find("CN="+Name,"user");
        if (recovered.Guid!=Identity) throw new InvalidOperationException("Child lookup did not recover after schema rejection");
        var row=new Sequence();row.Observe(480,error is not null);
        verify("DirectoryEntryComparisonTests.Directory_entries_find_requires_the_actual_schema_class",[row]);
    }

    private static void ExpirationPersistence(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var kind in new[] { DateTimeKind.Utc,DateTimeKind.Local,DateTimeKind.Unspecified })
        {
            var value=new DateTime(2030,6,1,12,34,56,kind).AddTicks(1234);
            if (TimeZoneInfo.Local.GetUtcOffset(value)!=TimeSpan.Zero)
                throw new InvalidOperationException("Recorded expiration replay requires zero local offset; nonzero-zone equivalence is not captured");
            using var fixture=new Fixture(identityLookup:true,expiration:true);
            using var found=AM.UserPrincipal.FindByIdentity(fixture.Context,AM.IdentityType.DistinguishedName,Dn)
                ?? throw new InvalidOperationException("Expiration setup lookup failed");
            if (found.Guid!=Identity || ReferenceEquals(found,fixture.User)) throw new InvalidOperationException("Expiration found-principal control failed");
            found.AccountExpirationDate=value;
            var error=OfflineTheoryMirrors.Capture(found.Save);
            var row=new Sequence();row.Observe(66,error?.GetType().Name,exceptionType:true);
            row.Observe(67,(error as ArgumentException)?.ParamName);
            if (error is not null) throw new InvalidOperationException("Expiration Save failed",error);
            row.Observe(131,found.AccountExpirationDate?.Ticks);row.ObserveDateTimeKind(132,found.AccountExpirationDate?.Kind);
            using var rawEntry=fixture.Context.CreateDirectoryEntry(Dn);
            rawEntry.RefreshCache(["accountExpires","objectGUID"]);
            if (rawEntry.Guid!=Identity || rawEntry.Properties["accountExpires"].Count!=1)
                throw new InvalidOperationException("Expiration fresh raw read precondition failed");
            var raw=Convert.ToInt64(rawEntry.Properties["accountExpires"].Value,CultureInfo.InvariantCulture);
            row.Observe(78,raw);
            using var reloaded=AM.UserPrincipal.FindByIdentity(fixture.Context,AM.IdentityType.DistinguishedName,Dn)
                ?? throw new InvalidOperationException("Expiration reload failed");
            if (reloaded.Guid!=Identity || reloaded.AccountExpirationDate is not { Kind:DateTimeKind.Utc } date
                || date.ToFileTimeUtc()!=raw || found.AccountExpirationDate!=value)
                throw new InvalidOperationException("Expiration cached/fresh typed read controls failed");
            row.Observe(131,reloaded.AccountExpirationDate?.Ticks);row.ObserveDateTimeKind(132,reloaded.AccountExpirationDate?.Kind);
            rows.Add(row);
        }
        verify("CompatibilityExpirationPersistenceComparisonTests.Expiration_Save_conversion_and_fresh_reload_match_microsoft",rows);
    }

    [AM.DirectoryObjectClass("user")]
    [AM.DirectoryRdnPrefix("CN")]
    private sealed class ExtensionUser(AM.PrincipalContext context) : AM.UserPrincipal(context)
    {
        internal object?[] Read() => ExtensionGet("otherTelephone");
        internal void Write(object?[] values) => ExtensionSet("otherTelephone",values);
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly AM.PrincipalContext Context;
        internal readonly AM.UserPrincipal User;
        internal readonly State Store=new();
        internal readonly List<Transport> Resources=[];
        internal DS.DirectoryEntry Entry => User.GetUnderlyingObject() as DS.DirectoryEntry
            ?? throw new InvalidOperationException("Saved principal had no native entry");

        internal Fixture(bool budgetAware=false,Action<AM.UserPrincipal>? beforeSave=null,bool identityLookup=false,bool extension=false,bool expiration=false,bool pagedQbe=false)
        {
            Store.AllowLookup=identityLookup;Store.AllowExtension=extension;Store.AllowExpiration=expiration;Store.AllowPagedQbe=pagedQbe;
            Context=new(AM.ContextType.Domain,"unused.example.test",RootDn,
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            LdapConnectionProvider.Session[] Open(LdapConnectionOptions options,int count,DS.ReferralChasingOption referrals,
                bool fresh,long minimum,Func<TimeSpan>? remaining,CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if (remaining?.Invoke() is { } left && left<=TimeSpan.Zero) throw new TimeoutException("Saved-new admission budget expired");
                if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid saved-new fixture admission");
                var admittedCount=count;
                if (Store.PairNextAdmission)
                {
                    if (!Store.AllowPagedQbe || count!=1) throw new InvalidOperationException("Unreviewed paired fixture admission");
                    // This neutral test factory atomically supplies both owned siblings.
                    // Production restricted-backend admission planning remains unchanged.
                    admittedCount=2;Store.PairNextAdmission=false;Store.PairAdmissions++;
                }
                return Enumerable.Range(0,admittedCount).Select(_ =>
                {
                    var transport=new Transport(Store);Resources.Add(transport);
                    var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                    return new LdapConnectionProvider.Session(session,() => { },() => { });
                }).ToArray();
            }
            if (budgetAware) Context.SearchRoot.OperationSessionFactoryWithBudget=Open;
            else Context.SearchRoot.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
                Open(options,count,referrals,fresh,minimum,null,default);
            User=extension ? new ExtensionUser(Context) : new AM.UserPrincipal(Context);
            User.Name=Name;User.SamAccountName=Name;User.Enabled=false;
            try
            {
                if (User.IsPersisted) throw new InvalidOperationException("New principal was already persisted");
                beforeSave?.Invoke(User);
                User.Save();
                if (Store.Adds!=1 || !Store.Exists || User.Guid!=Identity || !Entry.UsePropertyCache)
                    throw new InvalidOperationException("Saved-new Add/identity/cache controls failed");
            }
            catch { User.Dispose();Context.Dispose();throw; }
        }
        public void Dispose()
        {
            try { if (Store.Exists) User.Delete(); }
            finally { User.Dispose();Context.Dispose(); }
            if (!SpinWait.SpinUntil(() => Resources.All(r => Volatile.Read(ref r.Disposals)==1),TimeSpan.FromSeconds(5))
                || Store.Exists || Store.Adds!=1 || Store.Deletes!=1 || Store.Modifications!=(Store.AllowExpiration ? 1 : 0) || Resources.Count==0 || Store.LookupOpens!=Store.LookupCloses)
                throw new InvalidOperationException("Saved-new create/delete/session ownership failed");
        }
    }

    private sealed class State
    {
        internal bool Exists,AllowLookup,AllowExtension,AllowExpiration,AllowPagedQbe,PairNextAdmission;
        internal int Adds,Deletes,Reads,Modifications,LookupOpens,LookupCloses,PagedLookups,PairAdmissions;
        internal Dictionary<string,byte[][]> Attributes=new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class Transport(State store) : ILdapConversationTransport,ILdapMutationTransport,IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls
            | LdapTransportCapabilities.Add | LdapTransportCapabilities.Delete
            | (store.AllowLookup ? LdapTransportCapabilities.StreamingSearch : LdapTransportCapabilities.None)
            | (store.AllowExpiration ? LdapTransportCapabilities.Modify : LdapTransportCapabilities.None)
            | (store.AllowPagedQbe ? LdapTransportCapabilities.PagedSearch : LdapTransportCapabilities.None);
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        private static byte[][] Text(string value) => [Encoding.UTF8.GetBytes(value)];
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.BaseDn=="" && command.Attributes.SequenceEqual(new[] { "schemaNamingContext" }))
                return new(ResultCode.Success,"",null,[],[],[],[]);
            if (command.Scope!=System.DirectoryServices.Protocols.SearchScope.Base
                || (command.Controls ?? []).Any(c => c.Oid!="1.2.840.113556.1.4.801"))
                throw new InvalidDataException("Unreviewed saved-new read shape");
            Dictionary<string,byte[][]> attributes;
            if (command.BaseDn==RootDn) attributes=new(StringComparer.OrdinalIgnoreCase)
                { ["objectClass"]=Text("container"),["distinguishedName"]=Text(RootDn) };
            else if (command.BaseDn==Dn && store.Exists)
                attributes=store.Attributes.ToDictionary(p => p.Key,p => p.Value.Select(v => v.ToArray()).ToArray(),StringComparer.OrdinalIgnoreCase);
            else if (command.BaseDn==Dn) return new(ResultCode.NoSuchObject,"",null,[],[],[],[]);
            else throw new InvalidDataException("Unreviewed saved-new read target");
            if (command.Attributes.Length>0 && !command.Attributes.Contains("*"))
                attributes=attributes.Where(p => command.Attributes.Contains(p.Key,StringComparer.OrdinalIgnoreCase))
                    .ToDictionary(p => p.Key,p => p.Value,StringComparer.OrdinalIgnoreCase);
            store.Reads++;
            return new(ResultCode.Success,"",null,[new(command.BaseDn,attributes,[])],[],[],[]);
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command,LdapSubmission submission,CancellationToken token)
        {
            if (command is LdapModifyCommand modify) return ModifyAsync(modify,submission,token);
            token.ThrowIfCancellationRequested();
            if (command.DistinguishedName!=Dn || command.Controls.Length!=0)
                throw new InvalidDataException("Unreviewed saved-new mutation target/control");
            if (command is LdapAddCommand add && !store.Exists && store.Adds==0)
            {
                var allowed=new[] { "objectClass","cn","sAMAccountName","userAccountControl" };
                if (add.Attributes.Any(a => !(allowed.Contains(a.Name,StringComparer.OrdinalIgnoreCase) || (store.AllowExtension && a.Name=="otherTelephone"))))
                    throw new InvalidDataException("Unreviewed saved-new attribute");
                var values=add.Attributes.ToDictionary(a => a.Name,a => a.Values.Select(v => v.ToArray()).ToArray(),StringComparer.OrdinalIgnoreCase);
                if (!values.TryGetValue("sAMAccountName",out var sam) || sam.Length!=1 || Encoding.UTF8.GetString(sam[0])!=Name
                    || !values.TryGetValue("userAccountControl",out var uac) || uac.Length!=1
                    || (int.Parse(Encoding.UTF8.GetString(uac[0]),CultureInfo.InvariantCulture)&2)==0
                    || !values.TryGetValue("objectClass",out var classes) || !classes.Any(v => Encoding.UTF8.GetString(v)=="user"))
                    throw new InvalidDataException("Disabled user Add precondition failed");
                if (store.AllowExtension && (!values.TryGetValue("otherTelephone",out var extensionValues)
                    || extensionValues.Length!=1 || Encoding.UTF8.GetString(extensionValues[0])!="owned-extension-marker"))
                    throw new InvalidDataException("Extension Add marker precondition failed");
                values["objectClass"]=new[] { "top","person","organizationalPerson","user" }.Select(Encoding.UTF8.GetBytes).ToArray();
                values["objectCategory"]=Text("person");values["cn"]=Text(Name);values["distinguishedName"]=Text(Dn);values["objectGUID"]=[Identity.ToByteArray()];
                values["objectSid"]=[Convert.FromHexString("010500000000000515000000010000000200000003000000E9030000")];
                submission.BeforeSend();store.Attributes=values;store.Exists=true;store.Adds++;
            }
            else if (command is LdapDeleteCommand && store.Exists && store.Deletes==0)
            { submission.BeforeSend();store.Exists=false;store.Deletes++; }
            else throw new InvalidDataException("Unreviewed saved-new mutation; cache staging must never be committed");
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success,"",null,[],[]));
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var paged=store.AllowPagedQbe && pageSize==1 && command.SizeLimit==1
                && command.Filter=="(&(objectCategory=user)(objectClass=user)(sAMAccountName="+Name+"))";
            const string Categories="(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectClass=foreignSecurityPrincipal))";
            if (!store.AllowLookup || !store.Exists || command.BaseDn!=RootDn
                || command.Scope!=System.DirectoryServices.Protocols.SearchScope.Subtree || (pageSize!=0 && !paged)
                || command.TypesOnly
                || (command.Controls ?? []).Any(c => c.Oid!="1.2.840.113556.1.4.801"))
                throw new InvalidDataException("Unreviewed bounded identity query");
            if (command.SizeLimit!=((command.Filter=="(sAMAccountName=no-such-user-xyz-123)"
                || command.Filter.StartsWith("(&(objectCategory=user)(objectClass=user)(sAMAccountName=",StringComparison.Ordinal)) ? 1 : 2))
                throw new InvalidDataException("Unreviewed bounded query size");
            const string UserType="(&(objectCategory=person)(objectClass=user))";
            var filters=new Dictionary<string,(string Attribute,string Value)>(StringComparer.Ordinal)
            {
                ["(&(objectCategory=user)(objectClass=user)(sAMAccountName="+Name+"))"]=("sAMAccountName",Name),
                ["(&(objectCategory=user)(objectClass=user)(sAMAccountName=no-such-user-xyz-123))"]=("sAMAccountName","no-such-user-xyz-123"),
                ["(sAMAccountName=no-such-user-xyz-123)"]=("sAMAccountName","no-such-user-xyz-123"),
                ["(&"+Categories+"(distinguishedName="+Dn+"))"]=("distinguishedName",Dn),
                ["(&"+UserType+"(sAMAccountName="+Name+"))"]=("sAMAccountName",Name),
                ["(&"+UserType+"(cn="+Name+"))"]=("cn",Name),
                ["(&"+UserType+"(distinguishedName="+Dn+"))"]=("distinguishedName",Dn),
            };
            foreach (var attribute in new[] { "sAMAccountName","userPrincipalName","distinguishedName","name" })
                filters.Add("(&"+UserType+"("+attribute+"=no-such-user-xyz-123))",(attribute,"no-such-user-xyz-123"));
            if (!filters.TryGetValue(command.Filter,out var predicate))
                throw new InvalidDataException("Unreviewed identity predicate: "+command.Filter);
            var matches=store.Attributes.TryGetValue(predicate.Attribute,out var values)
                && values.Any(value => Encoding.UTF8.GetString(value)==predicate.Value);
            if (paged) Interlocked.Increment(ref store.PagedLookups);
            Interlocked.Increment(ref store.LookupOpens);
            return ValueTask.FromResult<ILdapSearchCursor>(new LookupCursor(store,command.Attributes,matches));
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (!store.AllowExpiration || !store.Exists || store.Modifications!=0 || command.DistinguishedName!=Dn
                || command.Controls.Length!=0 || command.Changes.Length!=1)
                throw new InvalidDataException("Saved-new fixture cannot commit unreviewed cache data");
            var change=command.Changes[0];
            if (change.Name!="accountExpires" || change.Operation!=DirectoryAttributeOperation.Replace || change.Values.Length!=1
                || !long.TryParse(Encoding.UTF8.GetString(change.Values[0]),NumberStyles.Integer,CultureInfo.InvariantCulture,out var raw)
                || raw<=0 || raw==long.MaxValue)
                throw new InvalidDataException("Unreviewed expiration replacement");
            submission.BeforeSend();store.Attributes["accountExpires"]=change.Values.Select(v => v.ToArray()).ToArray();store.Modifications++;
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success,"",null,[],[]));
        }

        private sealed class LookupCursor : ILdapSearchCursor
        {
            private readonly State owner;
            private readonly LdapTransportEntry? entry;
            private int position,closed;
            internal LookupCursor(State state,string[] requested,bool matches)
            {
                owner=state;
                var attributes=state.Attributes.Where(p => requested.Length==0 || requested.Contains("*")
                    || requested.Contains(p.Key,StringComparer.OrdinalIgnoreCase))
                    .ToDictionary(p => p.Key,p => p.Value.Select(v => v.ToArray()).ToArray(),StringComparer.OrdinalIgnoreCase);
                entry=matches ? new(Dn,attributes,[]) : null;
            }
            public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining,CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if (position==0 && entry is not null) { position=1;return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(entry)); }
                if (position!=(entry is null ? 0 : 1)) throw new InvalidDataException("Identity cursor read after terminal event");
                position=2;
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success,"",null,[],[]),false));
            }
            public ValueTask NextPageAsync(TimeSpan remaining,CancellationToken token,TimeSpan? serverTimeLimit=null)
                => throw new InvalidDataException("Bounded identity query attempted paging");
            public ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref closed,1)==0) Interlocked.Increment(ref owner.LookupCloses);
                return ValueTask.CompletedTask;
            }
        }
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }
}
