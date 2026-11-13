using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Security.AccessControl;
using PortableSid = AdForLinux.Security.Principal.SecurityIdentifier;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// A finite in-memory LDAP model accepts only reads and selected modifications of
// one synthetic persisted identity. No native backend or live writes exist.
// Each scenario selects one permitted mutable attribute before admission.
internal static class StatefulEntryMirrors
{
    private const string Dn="CN=merge-user,DC=example,DC=test";
    private const int Disabled=2,NeverExpires=0x10000,NotDelegated=0x100000;
    private const int Observed=Disabled|NeverExpires|NotDelegated;
    private static readonly Guid Identity=new("11111111-2222-3333-4444-555555555555");

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var editNative in new[] { false,true })
        {
            var state=new State();var resources=new List<Transport>();
            DS.DirectoryEntry Open() => CreateEntry(state,resources);
            int ReadFlags()
            {
                using var fresh=Open();
                fresh.RefreshCache(new[] { "distinguishedName","sAMAccountName","otherTelephone","userAccountControl","objectGUID" });
                if (fresh.Guid!=Identity || (string)fresh.Properties["distinguishedName"].Value! !=Dn
                    || (string)fresh.Properties["sAMAccountName"].Value! !="merge-user"
                    || (string)fresh.Properties["otherTelephone"].Value! !="owned-merge-model")
                    throw new InvalidOperationException("Fresh UAC identity control failed");
                return Convert.ToInt32(fresh.Properties["userAccountControl"].Value,CultureInfo.InvariantCulture);
            }
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using var entry=Open();
            using var user=(AM.UserPrincipal)AM.Principal.Materialize(context,typeof(AM.UserPrincipal),entry)!;
            if (user.Guid!=Identity || user.Enabled!=false || user.PasswordNeverExpires!=false)
                throw new InvalidOperationException("Found UAC principal precondition failed");
            user.PasswordNeverExpires=true;
            if (!user.PasswordNeverExpires) throw new InvalidOperationException("Staged UAC getter failed");
            var native=user.GetUnderlyingObject() as DS.DirectoryEntry
                ?? throw new InvalidOperationException("Found principal did not expose a directory entry");
            var initial=Convert.ToInt32(native.Properties["userAccountControl"].Value,CultureInfo.InvariantCulture);
            var row=new Sequence();row.Observe(69,initial&Observed);
            if (editNative)
            {
                native.Properties["userAccountControl"].Value=initial|NotDelegated;
                native.CommitChanges();
            }
            row.Observe(79,ReadFlags()&Observed);
            user.Save();
            var saved=ReadFlags();
            row.Observe(86,saved&Observed);
            row.Observe(89,saved&Disabled);
            row.Observe(93,saved&Observed);
            rows.Add(row);
            user.Dispose();entry.Dispose();
            if (state.Modifications!=(editNative ? 2 : 1) || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("UAC model commit/session ownership failed");
        }
        verify("CompatibilityAccountControlMergeComparisonTests.Staged_account_flag_merges_with_native_entry_changes",rows);
        ImplicitWrites(verify);
        ReadOnlyCacheCases(verify);
        RenameCaches(verify);
        SchemaFilters(verify);
        EmptySecurityCommit(verify);
        SecurityAssignments(verify);
        ExistingGroupUpdates(verify);
        PersistedQueryFilter(verify);
    }

    private static void ImplicitWrites(Action<string,List<Sequence>> verify)
    {
        const string Seed="compat-implicit-seed",Edited="compat-implicit-edited";
        var rows=new List<Sequence>();
        foreach (var cache in new[] { false,true })
        {
            var state=new State { MutationAttribute="description" };
            var resources=new List<Transport>();
            using var entry=CreateEntry(state,resources);
            string ReadPersisted()
            {
                using var fresh=CreateEntry(state,resources);
                fresh.RefreshCache(new[] { "description","objectGUID" });
                if (fresh.Guid!=Identity) throw new InvalidOperationException("Implicit write identity control failed");
                return (string)fresh.Properties["description"].Value!;
            }
            entry.UsePropertyCache=cache;
            entry.RefreshCache();
            var properties=entry.Properties;
            var values=properties["description"];
            if ((string)values.Cast<object>().Single()!=Seed || !ReferenceEquals(properties,entry.Properties))
                throw new InvalidOperationException("Implicit write cache precondition failed");
            values[0]=Edited;
            if ((string)values.Cast<object>().Single()!=Edited || ReadPersisted()!=(cache ? Seed : Edited))
                throw new InvalidOperationException("Implicit write local persistence control failed");
            var after=entry.Properties;
            var reacquired=after["description"];
            var row=new Sequence();
            row.Observe(62,ReferenceEquals(properties,after));
            row.Observe(63,ReferenceEquals(values,reacquired));
            if ((string)reacquired.Cast<object>().Single()!=Edited)
                throw new InvalidOperationException("Implicit write reacquired value control failed");
            row.Observe(66,ReferenceEquals(properties,after));
            row.Observe(68,ReferenceEquals(values,reacquired));
            entry.CommitChanges();
            if (ReadPersisted()!=Edited || (string)entry.Properties["description"].Value! !=Edited)
                throw new InvalidOperationException("Explicit commit recovery control failed");
            row.Observe(81,entry.UsePropertyCache);
            rows.Add(row);entry.Dispose();
            if (state.Modifications!=1 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Implicit write commit/session ownership failed");
        }
        verify("CompatibilityImplicitWriteCacheComparisonTests.Scalar_write_replaces_managed_cache_at_the_same_commit_boundary",rows);
    }

    private static void PersistedQueryFilter(Action<string,List<Sequence>> verify)
    {
        var state=new State { MutationAttribute="none" };var resources=new List<Transport>();
        using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",
            AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
        using var entry=CreateEntry(state,resources);
        using var user=AM.Principal.Materialize(context,typeof(AM.UserPrincipal),entry) as AM.UserPrincipal
            ?? throw new InvalidOperationException("Persisted query principal did not materialize");
        if (user.Guid!=Identity || !ReferenceEquals(entry,user.GetUnderlyingObject()))
            throw new InvalidOperationException("Persisted query identity control failed");
        var error=OfflineTheoryMirrors.Capture(() => { using var searcher=new AM.PrincipalSearcher(user); });
        var row=new Sequence();row.Observe(234,error?.GetType().Name,exceptionType:true);
        user.Dispose();entry.Dispose();
        if (resources.Count==0 || state.Modifications!=0 || state.Renames!=0 || resources.Any(r => r.Disposals!=1))
            throw new InvalidOperationException("Persisted query fixture admission/session ownership failed");
        verify("PrincipalSearcherComparisonTests.Persisted_query_filter_is_rejected_like_microsoft",[row]);
    }

    private static void ExistingGroupUpdates(Action<string,List<Sequence>> verify)
    {
        const string Edited="issue 104 update";
        var rows=new List<Sequence>();
        foreach (var cache in new[] { true,false })
        {
            var state=new State { MutationAttribute="description",ObjectClass="group",HasDescription=false };
            var resources=new List<Transport>();
            using var entry=CreateEntry(state,resources);
            entry.UsePropertyCache=cache;
            var properties=entry.Properties;
            entry.Properties["description"].Value=Edited;
            entry.CommitChanges();
            var row=new Sequence();row.Observe(271,!ReferenceEquals(properties,entry.Properties));
            if ((string)entry.Properties["description"].Value! !=Edited)
                throw new InvalidOperationException("Existing group committed-value local control failed");
            using (var fresh=CreateEntry(state,resources))
            {
                fresh.RefreshCache(new[] { "objectGUID","objectClass","description" });
                if (fresh.Guid!=Identity || (string)fresh.Properties["objectClass"].Value! !="group"
                    || (string)fresh.Properties["description"].Value! !=Edited)
                    throw new InvalidOperationException("Existing group fresh identity/value control failed");
            }
            rows.Add(row);entry.Dispose();
            if (state.Modifications==0 || state.Renames!=0 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Existing group update/session ownership failed");
        }
        verify("DirectoryEntryComparisonTests.CommitChanges_after_update_matches_cached_and_uncached_behavior",rows);
    }

    private static void SecurityAssignments(Action<string,List<Sequence>> verify)
    {
        var objectType=new Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        foreach (var cache in new[] { true,false })
        {
            var state=new State { MutationAttribute="security-write" };var resources=new List<Transport>();
            PortableSid identity;
            using (var sidEntry=CreateEntry(state,resources))
            {
                // Narrow synthetic identity precondition; actual Microsoft SID bytes are unavailable.
                sidEntry.RefreshCache(new[] { "objectSid" });
                identity=new PortableSid((byte[])sidEntry.Properties["objectSid"].Value!,0);
            }
            bool Contains(DS.ActiveDirectorySecurity security) => security.GetAccessRules(true,false,typeof(PortableSid))
                .Cast<DS.ActiveDirectoryAccessRule>().Any(candidate => candidate.IdentityReference.Equals(identity)
                    && candidate.ActiveDirectoryRights==DS.ActiveDirectoryRights.ReadProperty
                    && candidate.AccessControlType==AccessControlType.Allow && candidate.ObjectType==objectType);
            bool Visible()
            {
                using var fresh=CreateEntry(state,resources);
                fresh.Options.SecurityMasks=DS.SecurityMasks.Dacl;
                return Contains(fresh.ObjectSecurity);
            }
#pragma warning disable CA1416 // Enum flag passed to the portable AD facade; no Windows ACL API is called.
            var rule=new DS.ActiveDirectoryAccessRule(identity,DS.ActiveDirectoryRights.ReadProperty,
                AccessControlType.Allow,objectType,DS.ActiveDirectorySecurityInheritance.None);
#pragma warning restore CA1416
            using var entry=CreateEntry(state,resources);
            entry.Options.SecurityMasks=DS.SecurityMasks.Dacl;entry.UsePropertyCache=cache;
            var properties=entry.Properties;var security=entry.ObjectSecurity;
            security.AddAccessRule(rule);
            if (!Contains(security)) throw new InvalidOperationException("Security rule staging positive control failed");
            entry.ObjectSecurity=security;
            var invalidated=!ReferenceEquals(properties,entry.Properties);
            var before=Visible();
            if (cache) entry.CommitChanges();
            var after=Visible();
            if (!after) throw new InvalidOperationException("Security rule persisted model control failed");
            var row=new Sequence();
            if (cache) { row.Observe(32,before);row.Observe(33,after); }
            else { row.Observe(47,before);row.Observe(48,invalidated); }
            // Source-shaped exact-rule removal through a fresh normal entry.
            using (var cleanup=CreateEntry(state,resources))
            {
                cleanup.Options.SecurityMasks=DS.SecurityMasks.Dacl;
                var current=cleanup.ObjectSecurity;current.RemoveAccessRuleSpecific(rule);
                cleanup.ObjectSecurity=current;cleanup.CommitChanges();
            }
            if (Visible()) throw new InvalidOperationException("Security rule cleanup did not remove the controlled ACE");
            entry.Dispose();
            if (state.SecurityReads<5 || state.Modifications!=2 || state.Renames!=0 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Security assignment mutation/read/session ownership failed");
            verify("ObjectSecurityComparisonTests."+(cache
                ? "ObjectSecurity_assignment_with_cache_enabled_is_deferred_like_Microsoft"
                : "ObjectSecurity_assignment_with_cache_disabled_commits_immediately_like_Microsoft"),[row]);
        }
    }

    private static void EmptySecurityCommit(Action<string,List<Sequence>> verify)
    {
        var state=new State { MutationAttribute="security" };var resources=new List<Transport>();
        using var entry=CreateEntry(state,resources);
        entry.Options.SecurityMasks=DS.SecurityMasks.Dacl;
        var initial=entry.ObjectSecurity;
        if (initial.RetrievedMasks!=DS.SecurityMasks.Dacl
            || !initial.GetSecurityDescriptorBinaryForm().SequenceEqual(State.EmptyDacl())
            || !ReferenceEquals(initial,entry.ObjectSecurity))
            throw new InvalidOperationException("Initialized security descriptor control failed");
        entry.CommitChanges();
        var later=entry.ObjectSecurity;
        var row=new Sequence();row.Observe(71,!ReferenceEquals(initial,later));
        if (later.RetrievedMasks!=DS.SecurityMasks.Dacl || !later.GetSecurityDescriptorBinaryForm().SequenceEqual(State.EmptyDacl()))
            throw new InvalidOperationException("Reloaded security descriptor control failed");
        entry.Dispose();
        if (state.SecurityReads!=2 || state.Modifications!=0 || state.Renames!=0 || resources.Any(r => r.Disposals!=1))
            throw new InvalidOperationException("Empty security commit read/session ownership failed");
        verify("ObjectSecurityComparisonTests.Empty_cached_commit_invalidates_initialized_security_like_Microsoft",[row]);
    }

    private static void SchemaFilters(Action<string,List<Sequence>> verify)
    {
        string Snapshot(DS.SchemaNameCollection filter) => string.Join("|",filter.Cast<string?>());
        var rows=new List<Sequence>();
        foreach (var reuse in new[] { false,true })
        {
            var state=new State { MutationAttribute="none" };var resources=new List<Transport>();
            using var entry=CreateEntry(state,resources);
            if (string.IsNullOrEmpty(entry.Name)) throw new InvalidOperationException("Schema filter positive root read failed");
            var children=entry.Children;var first=children.SchemaFilter;
            var second=(reuse ? children : entry.Children).SchemaFilter;
            var row=new Sequence();row.Observe(26,ReferenceEquals(first,second));
            first.Clear();first.Add("group");
            if (Snapshot(second)!="group" || Snapshot(entry.Children.SchemaFilter)!="group")
                throw new InvalidOperationException("Schema filter shared-state local control failed");
            second.Clear();second.Add("user");
            if (Snapshot(first)!="user") throw new InvalidOperationException("Schema filter reverse-sharing local control failed");
            second.Clear();
            if (Snapshot(first)!="") throw new InvalidOperationException("Schema filter clear local control failed");
            using (var other=CreateEntry(state,resources))
            {
                other.Children.SchemaFilter.Add("computer");
                if (Snapshot(first)!="" || Snapshot(other.Children.SchemaFilter)!="computer")
                    throw new InvalidOperationException("Independent schema filter local control failed");
            }
            rows.Add(row);entry.Dispose();
            if (resources.Count==0 || state.Modifications!=0 || state.Renames!=0 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Schema filter read/session ownership failed");
        }
        verify("SchemaFilterBindingComparisonTests.Schema_filters_share_parent_binding_state",rows);
    }

    private static void RenameCaches(Action<string,List<Sequence>> verify)
    {
        const string NewCn="renamed-user",NewDn="CN="+NewCn+",DC=example,DC=test";
        var rows=new List<Sequence>();
        foreach (var cache in new[] { false,true })
        {
            var state=new State { MutationAttribute="rename" };var resources=new List<Transport>();
            using var entry=CreateEntry(state,resources);
            entry.UsePropertyCache=cache;entry.RefreshCache();
            var properties=entry.Properties;var cn=properties["cn"];
            if ((string)cn.Cast<object>().Single()!="merge-user" || !ReferenceEquals(properties,entry.Properties))
                throw new InvalidOperationException("Rename cache baseline control failed");
            entry.Rename("CN="+NewCn);
            using (var moved=CreateEntry(state,resources,NewDn))
            {
                moved.RefreshCache(new[] { "cn","objectGUID","distinguishedName" });
                if (moved.Guid!=Identity || (string)moved.Properties["cn"].Value! !=NewCn
                    || (string)moved.Properties["distinguishedName"].Value! !=NewDn)
                    throw new InvalidOperationException("Fresh renamed identity control failed");
            }
            using (var old=CreateEntry(state,resources))
            {
                var error=OfflineTheoryMirrors.Capture(() => old.RefreshCache());
                if (error is not DS.DirectoryServicesCOMException absent || absent.ErrorCode!=unchecked((int)0x80072030))
                    throw new InvalidOperationException("Old rename identity remained present",error);
            }
            if (entry.Name!="CN="+NewCn || !entry.Path.EndsWith("/"+NewDn,StringComparison.Ordinal))
                throw new InvalidOperationException("Rename path/name control failed");
            using (var parent=entry.Parent)
                if (parent is null || !parent.Path.EndsWith("/DC=example,DC=test",StringComparison.Ordinal))
                    throw new InvalidOperationException("Rename parent control failed");
            var after=entry.Properties;var cnAfter=after["cn"];var value=(string)cnAfter.Cast<object>().Single();
            if (value!=(cache ? NewCn : "merge-user") || (string)cn.Cast<object>().Single()!="merge-user")
                throw new InvalidOperationException("Rename retained/reacquired local name control failed");
            var row=new Sequence();
            row.Observe(78,ReferenceEquals(properties,after));
            row.Observe(83,ReferenceEquals(properties,after));
            row.Observe(85,ReferenceEquals(cn,cnAfter));
            row.Observe(87,value=="merge-user");row.Observe(89,value==NewCn);
            row.Observe(91,entry.UsePropertyCache);rows.Add(row);
            entry.Dispose();
            if (state.Renames!=1 || state.Modifications!=0 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Rename model mutation/session ownership failed");
        }
        verify("CompatibilityRenameRetainedCacheComparisonTests.Rename_retains_or_replaces_managed_cache_like_microsoft",rows);
    }

    private static void ReadOnlyCacheCases(Action<string,List<Sequence>> verify)
    {
        foreach (var scenario in new[] { "Missing_property_behaves_the_same",
            "Partial_refresh_cache_and_pending_change_semantics_match","Partial_refresh_edge_cases_match",
            "Parent_identity_and_inherited_state_match" })
        {
            var state=new State { MutationAttribute="none" };var resources=new List<Transport>();
            using var entry=CreateEntry(state,resources);
            var row=new Sequence();
            if (scenario=="Missing_property_behaves_the_same")
            {
                row.Observe(318,entry.Properties["noSuchAttributeHere"].Value);
                row.Observe(320,entry.Properties["noSuchAttributeHere"].Count);
            }
            else if (scenario=="Parent_identity_and_inherited_state_match")
            {
                entry.UsePropertyCache=false;
                using var parent=entry.Parent ?? throw new InvalidOperationException("Managed parent was missing");
                if (string.IsNullOrEmpty(parent.Name) || !parent.Path.EndsWith("/DC=example,DC=test",StringComparison.Ordinal)
                    || parent.Username!=entry.Username || parent.AuthenticationType!=entry.AuthenticationType)
                    throw new InvalidOperationException("Managed parent identity/configuration control failed");
                row.Observe(164,parent.UsePropertyCache);
            }
            else if (scenario=="Partial_refresh_cache_and_pending_change_semantics_match")
            {
                var properties=entry.Properties;
                var requested=properties["displayName"];var unrelated=properties["mail"];
                requested.Value="staged display name";unrelated.Value="staged mail";
                entry.RefreshCache(new[] { "displayName" });
                row.Observe(346,ReferenceEquals(properties,entry.Properties));
                row.Observe(349,ReferenceEquals(requested,entry.Properties["displayName"]));
                if ((string)entry.Properties["displayName"].Value! !="Ada Lovelace" || (string)requested.Value! !="staged display name")
                    throw new InvalidOperationException("Partial refresh requested-value local control failed");
                row.Observe(358,ReferenceEquals(unrelated,entry.Properties["mail"]));
                if ((string)entry.Properties["mail"].Value! !="staged mail")
                    throw new InvalidOperationException("Partial refresh discarded unrelated pending state");
            }
            else
            {
                var properties=entry.Properties;var unrelated=properties["mail"];var missing=properties["noSuchAttributeHere"];
                entry.RefreshCache(new[] { "DISPLAYNAME","displayName","noSuchAttributeHere" });
                if ((string)entry.Properties["displayName"].Value! !="Ada Lovelace")
                    throw new InvalidOperationException("Case-varied refresh local value control failed");
                row.Observe(386,ReferenceEquals(missing,entry.Properties["noSuchAttributeHere"]));
                row.Observe(389,entry.Properties["noSuchAttributeHere"].Value);
                row.Observe(392,ReferenceEquals(unrelated,entry.Properties["mail"]));
                var empty=OfflineTheoryMirrors.Capture(() => entry.RefreshCache(Array.Empty<string>()));
                row.Observe(401,empty is not null);
                row.Observe(402,ReferenceEquals(properties,entry.Properties));
                row.Observe(405,ReferenceEquals(unrelated,entry.Properties["mail"]));
                if ((string)entry.Properties["mail"].Value! !="ada@example.com")
                    throw new InvalidOperationException("Empty refresh unrelated-value local control failed");
                var nullArray=OfflineTheoryMirrors.Capture(() => entry.RefreshCache(null!));
                row.Observe(414,nullArray?.GetType().Name,exceptionType:true);
                var nullElement=OfflineTheoryMirrors.Capture(() => entry.RefreshCache(new string[] { null! }));
                row.Observe(417,nullElement?.GetType().Name,exceptionType:true);
            }
            entry.Dispose();
            if (resources.Count==0 || state.Modifications!=0 || resources.Any(r => r.Disposals!=1))
                throw new InvalidOperationException("Read-only cache model admission/ownership failed");
            verify("DirectoryEntryComparisonTests."+scenario,[row]);
        }
    }

    private static DS.DirectoryEntry CreateEntry(State state,List<Transport> resources,string? dn=null)
    {
        var entry=new DS.DirectoryEntry("LDAP://unused.example.test/"+(dn ?? Dn));
        entry.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
        {
            if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid managed entry model admission");
            return Enumerable.Range(0,count).Select(_ =>
            {
                var transport=new Transport(state);resources.Add(transport);
                var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                return new LdapConnectionProvider.Session(session,() => { },() => { });
            }).ToArray();
        };
        return entry;
    }

    private sealed class State
    {
        internal int Flags=0x200|Disabled,Modifications,Renames,SecurityReads;
        internal static byte[] EmptyDacl()
        {
            // Self-relative revision-1 descriptor with a revision-4 empty DACL.
            var raw=new byte[28];raw[0]=1;raw[2]=4;raw[3]=128;raw[16]=20;raw[20]=4;raw[22]=8;
            return raw;
        }
        internal string DistinguishedName=Dn,Cn="merge-user",ObjectClass="user";
        internal bool HasDescription=true;
        internal string MutationAttribute="userAccountControl",Description="compat-implicit-seed";
        internal byte[] Descriptor=EmptyDacl();
    }

    private sealed class Transport(State state) : ILdapConversationTransport,ILdapMutationTransport,IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.Modify
            | (state.MutationAttribute=="rename" ? LdapTransportCapabilities.ModifyDn : LdapTransportCapabilities.None)
            | (state.MutationAttribute=="security-write" ? LdapTransportCapabilities.ModifyControls : LdapTransportCapabilities.None);
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
                throw new InvalidDataException("Unexpected managed entry read");
            if (state.MutationAttribute=="rename" && command.BaseDn==Dn && state.DistinguishedName!=Dn)
                return new(ResultCode.NoSuchObject,"",null,[],[],[],[]);
            if ((state.MutationAttribute=="rename" || state.MutationAttribute=="none") && command.BaseDn=="DC=example,DC=test")
                return new(ResultCode.Success,"",null,[new(command.BaseDn,new(StringComparer.OrdinalIgnoreCase)
                    { ["distinguishedName"]=Text(command.BaseDn),["objectClass"]=Text("container") },[])],[],[],[]);
            if (command.BaseDn!=state.DistinguishedName) throw new InvalidDataException("Unreviewed managed entry DN");
            Dictionary<string,byte[][]> attributes=new(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"]=[Identity.ToByteArray()],["objectClass"]=Text(state.ObjectClass),
                ["distinguishedName"]=Text(state.DistinguishedName),["cn"]=Text(state.Cn),["sAMAccountName"]=Text("merge-user"),
                ["otherTelephone"]=Text("owned-merge-model"),["description"]=Text(state.Description),
                ["displayName"]=Text("Ada Lovelace"),["mail"]=Text("ada@example.com"),
                ["userAccountControl"]=Text(state.Flags.ToString(CultureInfo.InvariantCulture)),
            };
            if (!state.HasDescription) attributes.Remove("description");
            if (state.MutationAttribute=="security" || state.MutationAttribute=="security-write")
            {
                attributes["nTSecurityDescriptor"]=[state.Descriptor.ToArray()];
                attributes["objectSid"]=[Convert.FromHexString("010500000000000515000000010000000200000003000000E9030000")];
                if (command.Attributes.Contains("nTSecurityDescriptor",StringComparer.OrdinalIgnoreCase))
                {
                    var control=(command.Controls ?? []).Single();
                    if (!command.Attributes.SequenceEqual(new[] { "nTSecurityDescriptor" }) || !control.Critical || !control.HasValue
                        || !control.Value.SequenceEqual(new byte[] { 0x30,3,2,1,4 }))
                        throw new InvalidDataException("Security read mask/attribute precondition failed");
                    state.SecurityReads++;
                }
            }
            if (command.Attributes.Length>0 && !command.Attributes.Contains("*"))
                attributes=attributes.Where(pair => command.Attributes.Contains(pair.Key,StringComparer.OrdinalIgnoreCase))
                    .ToDictionary(pair => pair.Key,pair => pair.Value,StringComparer.OrdinalIgnoreCase);
            return new(ResultCode.Success,"",null,[new(state.DistinguishedName,attributes,[])],[],[],[]);
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command,LdapSubmission submission,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (state.MutationAttribute=="security-write")
            {
                if (command.DistinguishedName!=Dn || command.Changes.Length!=1 || command.Controls.Length!=1)
                    throw new InvalidDataException("Unreviewed security assignment command");
                var change=command.Changes[0];var control=command.Controls[0];
                if (!change.Name.Equals("nTSecurityDescriptor",StringComparison.OrdinalIgnoreCase)
                    || change.Operation!=DirectoryAttributeOperation.Replace || change.Values.Length!=1
                    || control.Oid!="1.2.840.113556.1.4.801" || !control.Critical || !control.HasValue
                    || !control.Value.SequenceEqual(new byte[] { 0x30,3,2,1,4 }))
                    throw new InvalidDataException("Security assignment section/attribute control failed");
                var raw=change.Values[0];
                if (raw.Length<28 || raw[0]!=1 || (raw[2]&4)==0 || (raw[3]&128)==0)
                    throw new InvalidDataException("Security assignment descriptor header failed");
                submission.BeforeSend();state.Descriptor=raw.ToArray();state.Modifications++;
                return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success,"",null,[],[]));
            }
            if (command.DistinguishedName!=Dn || command.Controls.Length!=0 || command.Changes.Length==0
                || command.Changes.Any(c => !c.Name.Equals(state.MutationAttribute,StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Unexpected managed entry modification");
            var values=new List<string>();
            if (state.MutationAttribute!="description") values.Add(state.Flags.ToString(CultureInfo.InvariantCulture));
            else if (state.HasDescription) values.Add(state.Description);
            foreach (var change in command.Changes)
            {
                var next=change.Values.Select(bytes => Encoding.UTF8.GetString(bytes)).ToArray();
                switch (change.Operation)
                {
                    case DirectoryAttributeOperation.Replace: values.Clear();values.AddRange(next);break;
                    case DirectoryAttributeOperation.Delete:
                        if (next.Length==0) values.Clear();else foreach (var value in next) values.Remove(value);
                        break;
                    case DirectoryAttributeOperation.Add: values.AddRange(next);break;
                    default: throw new InvalidDataException("Unknown managed entry operation");
                }
            }
            if (values.Count>1 || (values.Count==0 && state.MutationAttribute!="description"))
                throw new InvalidDataException("Managed attribute must remain single-valued");
            var flags=state.MutationAttribute=="description" ? state.Flags : int.Parse(values[0],CultureInfo.InvariantCulture);
            submission.BeforeSend();
            if (state.MutationAttribute=="description")
            {
                state.HasDescription=values.Count==1;
                if (state.HasDescription) state.Description=values[0];
            }
            else state.Flags=flags;
            state.Modifications++;
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success,"",null,[],[]));
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command,LdapSubmission submission,CancellationToken token)
        {
            if (command is LdapModifyCommand modify) return ModifyAsync(modify,submission,token);
            token.ThrowIfCancellationRequested();
            if (state.MutationAttribute!="rename" || command is not LdapModifyDnCommand rename
                || rename.DistinguishedName!=Dn || state.DistinguishedName!=Dn || rename.NewRdn!="CN=renamed-user"
                || rename.NewSuperior!="DC=example,DC=test" || !rename.DeleteOldRdn || rename.Controls.Length!=0)
                throw new InvalidDataException("Unreviewed managed entry mutation");
            submission.BeforeSend();
            state.Cn=rename.NewRdn["CN=".Length..];
            state.DistinguishedName=rename.NewRdn+","+rename.NewSuperior;state.Renames++;
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success,"",null,[],[]));
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command,int pageSize,CancellationToken token)
            => throw new InvalidDataException("Managed entry model attempted an unreviewed search");
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }
}
