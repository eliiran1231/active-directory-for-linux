#pragma warning disable SYSLIB0050, SYSLIB0051 // Exercise metadata serialization only; never invoke a formatter.
using System.Collections;
using System.Runtime.Serialization;
using P = System.Security.Principal;

internal static class IdentityCollectionContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        foreach (var (operation, count) in new[] {
            ("IdentityCollectionCtor", 5), ("IdentityCollectionIndex", 15), ("IdentityCollectionNull", 3),
            ("IdentityCollectionCopy", 20), ("IdentityCollectionEquality", 1), ("IdentityCollectionEnumerator", 13),
            ("IdentityCollectionTranslate", 12), ("IdentityCollectionTarget", 8),
            ("IdentityMappingException", 6), ("IdentityMappingSerialization", 2) })
            for (var scenario = 0; scenario < count; scenario++)
            {
                var current = scenario;
                record(operation, new { Scenario = current }, () => Execute(operation, current));
            }
    }
    internal static object? Execute(string operation, int scenario)
    {
        if (operation == "IdentityCollectionCtor")
        {
            var collection = scenario == 0 ? new P.IdentityReferenceCollection() : new P.IdentityReferenceCollection(new[] { -1, 0, 1, 16 }[scenario - 1]);
            return new { collection.Count, ReadOnly = ((ICollection<P.IdentityReference>)collection).IsReadOnly };
        }
        if (operation == "IdentityCollectionIndex")
        {
            var collection = Make(); var index = new[] { -1, 0, 1, 2, int.MaxValue }[scenario % 5];
            if (scenario < 5) return collection[index].Value;
            collection[index] = scenario < 10 ? new P.NTAccount("replacement") : null!;
            return Values(collection);
        }
        if (operation == "IdentityCollectionNull")
        {
            var collection = Make();
            if (scenario == 0) collection.Add(null!);
            else if (scenario == 1) return collection.Contains(null!);
            else return collection.Remove(null!);
            return Values(collection);
        }
        if (operation == "IdentityCollectionCopy")
        {
            var collection = Make(); var offset = new[] { -1, 0, 1, 3 }[scenario % 4];
            var length = new[] { -1, 0, 1, 2, 4 }[scenario / 4];
            P.IdentityReference[]? array = length < 0 ? null : Enumerable.Repeat<P.IdentityReference>(new P.NTAccount("sentinel"), length).ToArray();
            collection.CopyTo(array!, offset);
            return array!.Select(i => i.Value).ToArray();
        }
        if (operation == "IdentityCollectionEquality")
        {
            var first = new P.SecurityIdentifier("S-1-1-0"); var duplicate = new P.SecurityIdentifier("S-1-1-0");
            var account = new P.NTAccount("EXAMPLE", "Alice"); var equivalent = new P.NTAccount("example", "ALICE");
            var collection = new P.IdentityReferenceCollection { first, duplicate, account, equivalent, first };
            var containsSid = collection.Contains(new P.SecurityIdentifier("S-1-1-0"));
            var containsName = collection.Contains(new P.NTAccount("example", "alice"));
            var removed = collection.Remove(new P.SecurityIdentifier("S-1-1-0"));
            var firstIsDuplicate = ReferenceEquals(collection[0], duplicate);
            var removedName = collection.Remove(new P.NTAccount("EXAMPLE", "ALICE"));
            var remaining = Values(collection);
            var absent = collection.Remove(new P.SecurityIdentifier("S-1-5-18"));
            collection.Clear();
            return new { containsSid, containsName, removed, firstIsDuplicate, removedName, remaining, absent, collection.Count };
        }
        if (operation == "IdentityCollectionEnumerator")
        {
            var collection = Make(); var enumerator = collection.GetEnumerator();
            if (scenario == 0) return enumerator.Current.Value;
            if (scenario == 1) return ((IEnumerator)enumerator).Current;
            if (scenario == 2) { while (enumerator.MoveNext()) { } return enumerator.Current.Value; }
            if (scenario == 3) { while (enumerator.MoveNext()) { } enumerator.Reset(); return new { Next = enumerator.MoveNext(), Value = enumerator.Current.Value }; }
            enumerator.MoveNext();
            if (scenario == 4) { enumerator.Dispose(); return new { Next = enumerator.MoveNext(), Value = enumerator.Current.Value }; }
            if (scenario == 5)
            {
                collection.Add(new P.NTAccount("added")); var remaining = new List<string>();
                while (enumerator.MoveNext()) remaining.Add(enumerator.Current.Value);
                return remaining.ToArray();
            }
            if (scenario == 6) { collection[0] = new P.NTAccount("replacement"); return enumerator.Current.Value; }
            if (scenario == 7) { collection.Remove(collection[0]); return enumerator.Current.Value; }
            if (scenario == 8) { collection.Clear(); return enumerator.Current.Value; }
            if (scenario == 9) { while (enumerator.MoveNext()) { } collection.Add(new P.NTAccount("added")); return enumerator.MoveNext(); }
            if (scenario == 10) { var nongeneric = ((IEnumerable)collection).GetEnumerator(); nongeneric.MoveNext(); return ReferenceEquals(nongeneric.Current, collection[0]); }
            if (scenario == 11) { var empty = new P.IdentityReferenceCollection().GetEnumerator(); return empty.Current.Value; }
            while (enumerator.MoveNext()) { }
            var firstFalse = enumerator.MoveNext(); var secondFalse = enumerator.MoveNext();
            collection.Add(new P.NTAccount("third")); collection.Add(new P.NTAccount("fourth")); collection.Add(new P.NTAccount("fifth"));
            return new { firstFalse, secondFalse, AfterGrowth = enumerator.MoveNext() };
        }
        if (operation == "IdentityCollectionTranslate")
        {
            // Only empty or homogeneous same-kind calls. No account lookup is permitted.
            var collection = new P.IdentityReferenceCollection();
            var target = scenario / 6 == 0 ? typeof(P.SecurityIdentifier) : typeof(P.NTAccount);
            var mode = scenario % 6;
            if (mode >= 3)
            {
                P.IdentityReference identity = target == typeof(P.SecurityIdentifier) ? new P.SecurityIdentifier("S-1-1-0") : new P.NTAccount("unresolved-name");
                collection.Add(identity); collection.Add(identity);
            }
            var translated = mode % 3 == 0 ? collection.Translate(target) : collection.Translate(target, mode % 3 == 2);
            return new { Values = Values(translated), NewCollection = !ReferenceEquals(collection, translated),
                SameInstances = Enumerable.Range(0, collection.Count).All(i => ReferenceEquals(collection[i], translated[i])),
                DuplicateReferences = translated.Count == 2 && ReferenceEquals(translated[0], translated[1]) };
        }
        if (operation == "IdentityCollectionTarget")
        {
            var collection = scenario >= 4 ? Make() : new P.IdentityReferenceCollection();
            var target = new Type?[] { null, typeof(object), typeof(P.IdentityReference), typeof(string) }[scenario % 4];
            return collection.Translate(target!, true).Count; // Invalid target rejects before any resolution.
        }
        if (operation == "IdentityMappingException")
        {
            var inner = new InvalidOperationException("inner");
            var exception = scenario switch
            {
                0 => new P.IdentityNotMappedException(),
                1 => new P.IdentityNotMappedException((string?)null),
                2 => new P.IdentityNotMappedException(""),
                3 => new P.IdentityNotMappedException("custom"),
                4 => new P.IdentityNotMappedException(null, inner),
                _ => new P.IdentityNotMappedException("custom", inner)
            };
            var first = exception.UnmappedIdentities; var second = exception.UnmappedIdentities;
            first.Add(new P.SecurityIdentifier("S-1-1-0"));
            return new { exception.Message, exception.HResult, SameInner = ReferenceEquals(exception.InnerException, inner),
                SameCollection = ReferenceEquals(first, second), Values = Values(second),
                IndependentException = new P.IdentityNotMappedException().UnmappedIdentities.Count == 0 };
        }
        if (operation == "IdentityMappingSerialization")
        {
            // Metadata API only: no formatter, deserialization, file or network I/O.
            var exception = new P.IdentityNotMappedException("custom");
            exception.UnmappedIdentities.Add(new P.SecurityIdentifier("S-1-1-0"));
            var info = scenario == 0 ? null : new SerializationInfo(typeof(P.IdentityNotMappedException), new FormatterConverter());
            exception.GetObjectData(info!, new StreamingContext(StreamingContextStates.All));
            var keys = new List<string>(); var entries = info!.GetEnumerator();
            while (entries.MoveNext()) keys.Add(entries.Name);
            return new { Keys = keys.Order(StringComparer.Ordinal).ToArray(), Message = info.GetString("Message"),
                HResult = info.GetInt32("HResult"), InnerIsNull = info.GetValue("InnerException", typeof(Exception)) is null };
        }
        throw new InvalidOperationException("Unknown identity collection operation: " + operation);
    }
    private static P.IdentityReferenceCollection Make() => new() { new P.SecurityIdentifier("S-1-1-0"), new P.NTAccount("EXAMPLE", "Alice") };
    private static string[] Values(P.IdentityReferenceCollection collection) => collection.Select(i => i.Value).ToArray();
}
