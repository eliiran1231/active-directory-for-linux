using B = System.Security.Principal;

internal static class SidClosureContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        // ConvertStringSid constructor aliases are separate from SDDL grammar. Exclude LA/LG:
        // their binary value depends on the host machine and is measured by SddlHostRelative.
        foreach(var alias in "AA AC AN AO AP AS AU BA BG BO BU CA CD CG CN CO CY DA DC DD DG DU EA ED EK ER ES HA HI HO IS IU KA LA LG LS LU LW ME MP MU NO NS NU OW PA PO PS PU RA RC RD RE RM RO RS RU SA SH SI SO SS SU SY UD WD WR".Split(' ')
            .Where(value=>value is not ("LA" or "LG")))
        foreach(var text in new[] {alias,alias.ToLowerInvariant()})
            record("SidClosureAlias",new {Text=text},()=>{
                var sid=new B.SecurityIdentifier(text);var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
                return new {sid.Value,Hex=Convert.ToHexString(bytes)};
            });
        var types = Enumerable.Range(-1, 98).Append(999).ToArray();
        foreach(var hex in new[] {"010100000000000200000000","010000000000000F"})
        foreach(var type in types)
            record("SidClosureIsWellKnownBinary",new {Hex=hex,Type=type},()=>
                new B.SecurityIdentifier(Convert.FromHexString(hex),0).IsWellKnown((B.WellKnownSidType)type));
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
