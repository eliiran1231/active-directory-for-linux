#pragma warning disable CA1416 // Shared enum values; portable execution never calls Windows APIs.
using System.Security.AccessControl;

// Eight ordinary-sized fixtures crossed with eight independent operations.
// Data only: these inputs predict neither native normalization nor error outcomes.
internal static class SddlMixedInputs
{
    internal sealed record Input(string Fixture, string Operation, string Text, AccessControlSections Sections, string? Edit)
    {
        internal string Label => $"mixed/{Fixture}/{Operation}";
    }

    internal static IEnumerable<Input> Create()
    {
        const string identities = "O:S-1-5-18G:S-1-5-32-544";
        const string dacl = "D:PAI(D;;WP;;;S-1-5-32-545)(A;CI;RP;;;S-1-1-0)";
        const string sacl = "S:PAI(AU;SA;RP;;;S-1-5-18)";
        const string g = "11111111-2222-3333-4444-555555555555";
        const string h = "66666666-7777-8888-9999-aaaaaaaaaaaa";
        foreach (var (name, access, audit, malformed, target) in new[]
        {
            ("XA", "(XA;;RP;;;S-1-1-0;((@User.Level >= 2) && (@User.Title Any_of {\"Engineer\",\"Manager\"})))", "",
                "D:(XA;;RP;;;S-1-1-0;(@User.Level ==))", AccessControlSections.Access),
            ("XD", "(XD;;WP;;;S-1-1-0;(Member_of {SID(S-1-5-32-544),SID(S-1-1-0)}))", "",
                "D:(XD;;WP;;;S-1-1-0;(@User.Level ==))", AccessControlSections.Access),
            ("ZA-object", $"(ZA;;RP;{g};;S-1-1-0;(@Resource.Department == \"Research\"))", "",
                $"D:(ZA;;RP;{g};;S-1-1-0;(@User.Level ==))", AccessControlSections.Access),
            ("ZA-inherited", $"(ZA;CI;RP;;{h};S-1-1-0;(@Device.Trusted == 1))", "",
                $"D:(ZA;CI;RP;;{h};S-1-1-0;(@User.Level ==))", AccessControlSections.Access),
            ("ZA-both", $"(ZA;CIIO;RP;{g};{h};S-1-1-0;(!(@User.Disabled == 1)))", "",
                $"D:(ZA;CIIO;RP;{g};{h};S-1-1-0;(@User.Level ==))", AccessControlSections.Access),
            ("XU", "", "(XU;SAFA;RP;;;S-1-1-0;(@User.Level >= 1))",
                "S:(XU;SAFA;RP;;;S-1-1-0;(@User.Level ==))", AccessControlSections.Audit),
            ("RA", "", "(RA;;;;;S-1-1-0;(\"Department\",TS,0,\"Research\",\"Ops\"))(RA;;;;;S-1-1-0;(\"Level\",TU,0,1,2))(RA;;;;;S-1-1-0;(\"Enabled\",TB,0,1))(RA;;;;;S-1-1-0;(\"Team\",TD,0,S-1-5-32-544))",
                "S:(RA;;;;;S-1-1-0;(\"Enabled\",TB,0,2))", AccessControlSections.Audit),
            ("FL", "", "(FL;;RP;;;S-1-1-0;(@User.Level >= 2))",
                "S:(FL;;RP;;;S-1-1-0;(@User.Level ==))", AccessControlSections.Audit)
        })
        {
            var text = identities + dacl + access + sacl + audit;
            if (text.Length > 2048) throw new InvalidOperationException("Mixed fixture exceeds its ordinary-size bound.");
            yield return new(name, "parse-copy", text, AccessControlSections.All, null);
            yield return new(name, "export-owner-group", text, AccessControlSections.Owner | AccessControlSections.Group, null);
            yield return new(name, "export-access", text, AccessControlSections.Access, null);
            yield return new(name, "export-audit", text, AccessControlSections.Audit, null);
            yield return new(name, "export-all", text, AccessControlSections.All, null);
            yield return new(name, "edit-owner", text, AccessControlSections.Owner, "O:S-1-5-19");
            yield return new(name, "edit-group", text, AccessControlSections.Group, "G:S-1-5-32-545");
            yield return new(name, "malformed-selected-edit", text,
                AccessControlSections.Owner | AccessControlSections.Group | target,
                "O:S-1-5-19G:S-1-5-32-545" + malformed);
        }
    }
}
