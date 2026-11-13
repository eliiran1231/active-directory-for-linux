using System.Collections;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using Sequence = OfflineTheoryMirrors.Sequence;

// Projection-mode cursor guards, reference identity and shared position only.
// Controlled unsaved rows do not represent live query or persisted identity.
internal static class PrincipalCursorMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PrincipalSearchResultLivePositionComparisonTests.FindAll_Current_matches_position_validation", Position());
        verify("CompatibilityPrincipalCurrentOwnershipComparisonTests.Repeated_Current_returns_matching_wrapper_ownership", Repeated());
        verify("CompatibilityPrincipalCurrentOwnershipComparisonTests.Interleaved_cursors_observe_matching_shared_result_position", Interleaved());
    }

    private sealed class Producer : IDisposable
    {
        private readonly AM.PrincipalContext context=new(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",null,null);
        private readonly List<AM.Principal> owned=new();
        internal AM.PrincipalSearchResult<AM.Principal> Results { get; }
        internal Producer(int count)
        {
            Results=new(count,index =>
            {
                if (index<0 || index>=count) throw new InvalidOperationException("Projection index outside producer");
                var user=new AM.UserPrincipal(context) { SamAccountName="cursor-"+index };
                owned.Add(user);
                return user;
            });
        }
        internal string Role(IEnumerator<AM.Principal> cursor)
        {
            var role=cursor.Current.SamAccountName;
            if (role is not ("cursor-0" or "cursor-1")) throw new InvalidOperationException("Healthy row projection control failed");
            return role;
        }
        public void Dispose()
        {
            Results.Dispose();
            foreach (var principal in owned) principal.Dispose();
            context.Dispose();
        }
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Source-required cursor control failed");
    }

    private static List<Sequence> Repeated()
    {
        var rows=new List<Sequence>();
        foreach (var disposeFirst in new[] { false,true })
        {
            using var producer=new Producer(1);
            using var cursor=producer.Results.GetEnumerator();
            Require(cursor.MoveNext());
            var first=cursor.Current;
            var second=cursor.Current;
            Require(first.SamAccountName=="cursor-0" && second.SamAccountName=="cursor-0");
            Require(!cursor.MoveNext());
            var row=new Sequence();
            row.Observe(54,ReferenceEquals(first,second));
            if (disposeFirst) first.Dispose();
            // Source's persisted DN/error reads after disposal are excluded.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Interleaved()
    {
        var rows=new List<Sequence>();
        foreach (var operation in new[] { "advance","reset","exhaust" })
        {
            using var producer=new Producer(2);
            using (var probe=producer.Results.GetEnumerator())
            {
                var roles=new HashSet<string>(StringComparer.Ordinal);
                while (probe.MoveNext()) roles.Add(producer.Role(probe));
                Require(roles.SetEquals(new[] { "cursor-0","cursor-1" }));
            }
            using var a=producer.Results.GetEnumerator();
            using var b=producer.Results.GetEnumerator();
            Require(a.MoveNext());
            var first=producer.Role(a);
            Require(a.MoveNext());
            var second=producer.Role(a);
            Require(first!=second);
            Require(b.MoveNext());
            var bFirst=producer.Role(b);
            var aAfter=producer.Role(a);
            var row=new Sequence();
            row.Observe(137,StringComparer.OrdinalIgnoreCase.Equals(aAfter,bFirst));
            row.Observe(139,StringComparer.OrdinalIgnoreCase.Equals(aAfter,second));
            Require(a.MoveNext());
            _=producer.Role(b); // Healthy projection, not an admitted DN oracle.
            if (operation=="reset")
            {
                a.Reset();
                Require(OfflineTheoryMirrors.Capture(() => _=a.Current) is InvalidOperationException);
                _=producer.Role(b);
                Require(a.MoveNext());
                _=producer.Role(b);
            }
            else if (operation=="exhaust")
            {
                Require(!a.MoveNext());
                b.Reset();
                Require(b.MoveNext());
                for (var attempt=0;attempt<2;attempt++)
                {
                    row.Observe(169,a.MoveNext());
                    Require(OfflineTheoryMirrors.Capture(() => _=a.Current) is InvalidOperationException);
                    _=producer.Role(b);
                }
                a.Reset();
                Require(a.MoveNext());
                _=producer.Role(a);
            }
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Position()
    {
        var rows=new List<Sequence>();
        foreach (var nonGeneric in new[] { false,true })
        foreach (var position in new[] { "before-start","after-end","after-reset" })
        {
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,"unused.example.test","DC=example,DC=test",null,null);
            var owned=new List<AM.Principal>();
            using var results=new AM.PrincipalSearchResult<AM.Principal>(1,index =>
            {
                if (index!=0) throw new InvalidOperationException("Projection index outside the one-row producer");
                var user=new AM.UserPrincipal(context) { SamAccountName="cursor-user" };
                owned.Add(user);
                return user;
            });
            using var cursor=results.GetEnumerator();
            try
            {
                Exception? Read() => OfflineTheoryMirrors.Capture(() =>
                {
                    object? value=nonGeneric ? ((IEnumerator)cursor).Current : cursor.Current;
                    if (value is null) throw new InvalidDataException("Current returned a null principal");
                });
                var error=Read();
                if (!cursor.MoveNext()) throw new InvalidOperationException("One-row principal producer was empty");
                if (cursor.Current.SamAccountName!="cursor-user") throw new InvalidOperationException("Healthy projection control failed");
                if (cursor.MoveNext()) throw new InvalidOperationException("One-row principal producer returned extra rows");
                if (position=="after-reset") cursor.Reset();
                if (position!="before-start") error=Read();
                var row=new Sequence();
                row.Observe(66,error?.GetType().FullName,exceptionType:true);
                rows.Add(row);
            }
            finally { foreach (var user in owned) user.Dispose(); }
        }
        return rows;
    }
}
