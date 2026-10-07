using B = System.Security.Principal;

internal static class SidClosureContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        var types = Enumerable.Range(-1, 98).Append(999).ToArray();
        foreach (var type in types)
        foreach (var domain in new string?[] { null, "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-1001", "S-1-5-32-544" })
            record("SidClosureConstruct", new { Type=type, Domain=domain }, () => {
                var sid=new B.SecurityIdentifier((B.WellKnownSidType)type,domain is null?null:new B.SecurityIdentifier(domain));
                var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
                return new {sid.Value,Hex=Convert.ToHexString(bytes),IsWellKnown=sid.IsWellKnown((B.WellKnownSidType)type)};
            });
        foreach (var value in new[] { "S-1-5-5-1-2", "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-501", "S-1-5-32-544", "S-1-1-0" })
        foreach (var type in types)
            record("SidClosureIsWellKnown",new {Value=value,Type=type},()=>new B.SecurityIdentifier(value).IsWellKnown((B.WellKnownSidType)type));
    }
}
