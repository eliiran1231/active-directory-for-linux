// Data-only questions about complete ACE size and competing invalid fields.
// Separate from the frozen 948-case allocation investigation; no predicted outcomes.
internal static class SddlAceSizeInputs
{
    internal static IEnumerable<SddlBoundaryInputs.Input> Create()
    {
        const string firstGuid = "11111111-2222-3333-4444-555555555555";
        const string secondGuid = "66666666-7777-8888-9999-aaaaaaaaaaaa";
        foreach (var (name, type, section, flags, objectGuid, inheritedGuid, length) in new[]
        {
            ("XD", "XD", "D", "", "", "", 32748),
            ("XU", "XU", "S", "SA", "", "", 32748),
            ("ZA0", "ZA", "D", "", "", "", 32746),
            ("ZA1", "ZA", "D", "", firstGuid, "", 32738),
            ("ZA1Inherited", "ZA", "D", "", "", secondGuid, 32738),
            ("ZA2", "ZA", "D", "", firstGuid, secondGuid, 32730)
        })
        foreach (var oversized in new[] { false, true })
        foreach (var fault in new[] { "none", "flags", "rights", "sid", "object-guid", "inherited-guid", "condition", "section", "all" })
        {
            var all = fault == "all";
            var acl = all || fault == "section" ? section == "D" ? "S" : "D" : section;
            var aceFlags = all || fault == "flags" ? "ZZ" : flags;
            var rights = all || fault == "rights" ? "ZZ" : "RP";
            var sid = all || fault == "sid" ? "garbage" : "WD";
            var objectType = all || fault == "object-guid" ? "bad-guid" : objectGuid;
            var inheritedType = all || fault == "inherited-guid" ? "bad-guid" : inheritedGuid;
            var value = new string('x', oversized ? length : 8);
            var expression = $"(@User.A == \"{value}\"{(all || fault == "condition" ? " &&" : "")})";
            yield return new($"ace-size/{name}/{(oversized ? "oversize" : "ordinary")}/{fault}", type,
                $"{acl}:({type};{aceFlags};{rights};{objectType};{inheritedType};{sid};{expression})");
        }
    }
}
