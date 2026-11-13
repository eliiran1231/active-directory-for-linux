using System.DirectoryServices.Protocols;
using System.Text;
using System.Runtime.CompilerServices;
using AdForLinux.DirectoryServices.Ldap;
using DS = AdForLinux.DirectoryServices;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using Sequence = OfflineTheoryMirrors.Sequence;

// Synthetic GUID roles feed the normal found-principal materialization route.
// This exercises stored-identity capture/equality, not live lookup or AD GUIDs.
internal static class StoredIdentityMirrors
{
    private static readonly Guid First=new("11111111-2222-3333-4444-555555555555");
    private static readonly Guid Other=new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PersistedPrincipalEqualityDisposalComparisonTests.Equality_of_separately_loaded_principals_survives_disposal_like_microsoft",Equality());
        verify("CompatibilityPendingMemberEqualityComparisonTests.Pending_contains_honors_principal_equality",PendingMembers());
        verify("CompatibilityQueriedPrincipalNativeLifetimeComparisonTests.First_description_read_after_native_close_or_dispose_matches_microsoft",NativeLifetime());
        verify("CompatibilityRetainedPropertyWriteAfterCloseComparisonTests.Cached_write_through_retained_or_fresh_wrapper_matches_after_close",CachedWrites());
        verify("PropertyCollectionMissingLookupComparisonTests.Reading_an_absent_property_does_not_add_it_to_the_property_list",MissingLookupSubset());
    }

    private static List<Sequence> Equality()
    {
        var rows=new List<Sequence>();
        foreach (var same in new[] { true,false })
        foreach (var disposeLeft in new[] { false,true })
        foreach (var disposeRight in new[] { false,true })
        {
            var resources=new List<Transport>();
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using var leftEntry=CreateEntry(resources,"CN=first,DC=example,DC=test",First);
            using var rightEntry=CreateEntry(resources,same ? "CN=first,DC=example,DC=test" : "CN=other,DC=example,DC=test",same ? First : Other);
            using var left=(AM.UserPrincipal)AM.Principal.Materialize(context,typeof(AM.UserPrincipal),leftEntry)!;
            using var right=(AM.UserPrincipal)AM.Principal.Materialize(context,typeof(AM.UserPrincipal),rightEntry)!;
            if (ReferenceEquals(left,right) || left.Guid!=First || right.Guid!=(same ? First : Other))
                throw new InvalidOperationException("Controlled identity materialization precondition failed");
            var row=new Sequence();
            row.Observe(46,left.Equals(right));
            if (disposeLeft) left.Dispose();
            if (disposeRight) right.Dispose();
            void Compare(Func<bool> read)
            {
                bool? value=null;
                var error=OfflineTheoryMirrors.Capture(() => value=read());
                row.Observe(76,error?.GetType().FullName,exceptionType:true);
                row.Observe(77,value);
            }
            Compare(() => left.Equals(right));
            Compare(() => right.Equals(left));
            Compare(() => left.Equals(left));
            Compare(() => left.Equals(null));
            Compare(() => left.Equals("not a principal"));
            rows.Add(row);
            if (resources.Count==0 || resources.Any(resource => resource.Disposals!=1)
                || !resources.Any(resource => resource.DataReads>0))
                throw new InvalidOperationException("Controlled identity read/lease ownership failed");
        }
        return rows;
    }

    private static List<Sequence> PendingMembers()
    {
        var rows=new List<Sequence>();
        foreach (var referenceEquality in new[] { false,true })
        {
            var resources=new List<Transport>();
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using var firstEntry=CreateEntry(resources,"CN=first,DC=example,DC=test",First);
            using var secondEntry=CreateEntry(resources,"CN=first,DC=example,DC=test",First);
            var type=referenceEquality ? typeof(ReferenceUser) : typeof(AM.UserPrincipal);
            using var first=(AM.UserPrincipal)AM.Principal.Materialize(context,type,firstEntry)!;
            using var second=(AM.UserPrincipal)AM.Principal.Materialize(context,type,secondEntry)!;
            if (ReferenceEquals(first,second) || first.Guid!=First || second.Guid!=First
                || first.DistinguishedName!=second.DistinguishedName || !first.Equals(first))
                throw new InvalidOperationException("Controlled member identity precondition failed");
            var row=new Sequence();
            row.Observe(66,first.Equals(second));
            row.Observe(68,second.Equals(first));
            using var group=new AM.GroupPrincipal(context);
            if (group.Guid is not null || group.Members.Contains(second)) throw new InvalidOperationException("Unsaved group control failed");
            group.Members.Add(first);
            if (group.Members.Count!=1 || !group.Members.Contains(first)) throw new InvalidOperationException("Pending member control failed");
            var contains=group.Members.Contains(second);
            row.Observe(87,contains);
            row.Observe(92,contains);
            row.Observe(93,group.Members.Count);
            if (group.DistinguishedName is not null || resources.Any(resource => resource.Disposals!=1))
                throw new InvalidOperationException("Pending member fixture ownership failed");
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> NativeLifetime()
    {
        const string seeded="differential test user";
        var rows=new List<Sequence>();
        foreach (var disposeNative in new[] { false,true })
        {
            var resources=new List<Transport>();
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            // The principal owns this entry after successful materialization.
            var entry=CreateEntry(resources,"CN=first,DC=example,DC=test",First,seeded);
            using var principal=(AM.UserPrincipal)AM.Principal.Materialize(context,typeof(AM.UserPrincipal),entry)!;
            var native=principal.GetUnderlyingObject() as DS.DirectoryEntry
                ?? throw new InvalidOperationException("Materialized principal lost its native entry");
            if (!ReferenceEquals(entry,native) || native.Properties["description"].Value is not string value || value!=seeded)
                throw new InvalidOperationException("Cold description/native wrapper precondition failed");
            // Do not read principal.Description before the native lifetime action.
            if (disposeNative) native.Dispose(); else native.Close();
            if (!ReferenceEquals(context,principal.Context)) throw new InvalidOperationException("Principal context changed");
            var identity=ReferenceEquals(native,principal.GetUnderlyingObject());
            string? description=null;
            var error=OfflineTheoryMirrors.Capture(() => description=principal.Description);
            if (error is null && description!=seeded) throw new InvalidOperationException("Controlled snapshot description was lost");
            var row=new Sequence();
            row.Observe(87,identity);
            row.Observe(88,error?.GetType().Name,exceptionType:true);
            row.Observe(89,(error as ArgumentException)?.ParamName);
            if (resources.Any(resource => resource.Disposals!=1)) throw new InvalidOperationException("Native lifetime fixture lease leaked");
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> CachedWrites()
    {
        const string dn="CN=first,DC=example,DC=test";
        const string seeded="differential test user";
        const string pending="pending retained wrapper comparison";
        var rows=new List<Sequence>();
        foreach (var scenario in new[] { "retained-without-close","retained-after-close","fresh-after-close" })
        {
            var resources=new List<Transport>();
            using var entry=CreateEntry(resources,dn,First,seeded);
            if (!entry.UsePropertyCache) throw new InvalidOperationException("Cached writer prerequisite failed");
            var before=entry.Properties;
            var retained=before["description"];
            if (retained.Value is not string initial || initial!=seeded || (string?)before["distinguishedName"].Value!=dn)
                throw new InvalidOperationException("Retained property producer control failed");
            if (scenario!="retained-without-close") entry.Close();
            var writer=scenario=="fresh-after-close" ? entry.Properties["description"] : retained;
            if (!entry.UsePropertyCache || writer.Value is not string value || value!=seeded)
                throw new InvalidOperationException("Retained/fresh writer setup failed");
            var error=OfflineTheoryMirrors.Capture(() => writer.Value=pending);
            var after=entry.Properties;
            var current=after["description"];
            var row=new Sequence();
            row.Observe(66,error?.GetType().FullName,exceptionType:true);
            // Preserve source reads 67-69 even though their string payloads
            // were redacted; they occur before the wrapper identity checks.
            var written=writer.Value;
            _=current.Value;
            _=retained.Value;
            if (error is null && !Equals(written,pending)) throw new InvalidOperationException("Local writer value control failed");
            row.Observe(70,ReferenceEquals(before,after));
            row.Observe(72,ReferenceEquals(retained,current));
            row.Observe(74,ReferenceEquals(writer,current));
            row.Observe(76,ReferenceEquals(current,entry.Properties["description"]));
            if (resources.Count==0 || resources.Any(resource => resource.Disposals!=1))
                throw new InvalidOperationException("Cached writer fixture lease leaked");
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> MissingLookupSubset()
    {
        const string missing="adflNonexistentCompatibilityAttribute";
        var rows=new List<Sequence>();
        // PropertyNames has no public normalized collection. It is explicitly
        // excluded in inputProjection, not executed with an empty oracle row.
        foreach (var observation in new[] { "Contains","Count" })
        {
            var resources=new List<Transport>();
            using var entry=CreateEntry(resources,"CN=first,DC=example,DC=test",First,"differential test user");
            var properties=entry.Properties;
            if (properties.Contains(missing)) throw new InvalidOperationException("Missing-property producer contained the missing key");
            var before=properties.Count;
            if (before==0) throw new InvalidOperationException("Nonempty property-list control failed");
            _=properties.PropertyNames.Cast<string>().Select(name => name.ToLowerInvariant()).Order(StringComparer.Ordinal).ToArray();
            if (properties[missing].Cast<object>().Any() || properties[missing].Value is not null)
                throw new InvalidOperationException("Missing-property lookup control failed");
            var row=new Sequence();
            if (observation=="Contains") row.Observe(49,properties.Contains(missing));
            else row.Observe(55,properties.Count-before);
            if (resources.Any(resource => resource.Disposals!=1)) throw new InvalidOperationException("Missing-property fixture lease leaked");
            rows.Add(row);
        }
        return rows;
    }

    [AM.DirectoryObjectClass("user")]
    [AM.DirectoryRdnPrefix("CN")]
    public sealed class ReferenceUser : AM.UserPrincipal
    {
        public ReferenceUser(AM.PrincipalContext context) : base(context) { }
        public override bool Equals(object? other) => ReferenceEquals(this,other);
        public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);
    }

    private static DS.DirectoryEntry CreateEntry(List<Transport> resources,string dn,Guid guid,string? description=null)
    {
        var entry=new DS.DirectoryEntry("LDAP://unused.example.test/"+dn);
        entry.OperationSessionFactory=(options,count,referrals,fresh,minimum) =>
        {
            if (!OfflineTestGuard.Enabled || count is <1 or >2) throw new InvalidOperationException("Invalid stored-identity model admission");
            return Enumerable.Range(0,count).Select(_ =>
            {
                var transport=new Transport(dn,guid,description);resources.Add(transport);
                var session=new BoundLdapSession(transport,transport,options,new LdapAuthenticationSource(options),referrals);
                return new LdapConnectionProvider.Session(session,() => { },() => { });
            }).ToArray();
        };
        return entry;
    }

    private sealed class Transport(string dn,Guid guid,string? description) : ILdapRequestTransport,IDisposable
    {
        internal int Disposals,DataReads;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if ((command.Controls ?? []).Any(control => control.Oid!="1.2.840.113556.1.4.801"))
                throw new InvalidDataException("Unexpected controlled identity request control");
            if (command.BaseDn=="" && command.Attributes.SequenceEqual(new[] { "schemaNamingContext" }))
                return new(ResultCode.Success,"",null,[],[],[],[]);
            if (command.BaseDn!=dn || command.Scope!=System.DirectoryServices.Protocols.SearchScope.Base)
                throw new InvalidDataException("Unexpected controlled identity read");
            DataReads++;
            Dictionary<string,byte[][]> values=new(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"]=[guid.ToByteArray()],
                ["distinguishedName"]=[Encoding.UTF8.GetBytes(dn)],
                ["objectClass"]=[Encoding.UTF8.GetBytes("user")],
            };
            if (description is not null) values["description"]=[Encoding.UTF8.GetBytes(description)];
            return new(ResultCode.Success,"",null,[new(dn,values,[])],[],[],[]);
        }
        public void Dispose() => Disposals++;
    }
}
