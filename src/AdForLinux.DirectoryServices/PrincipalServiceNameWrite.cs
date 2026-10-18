using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices;

// A single data-only contribution to the entry's ordinary atomic Modify. It is
// never installed in the property cache, so rejection cannot leave stale edits.
internal sealed class PrincipalServiceNameWrite(
    string[] removed, (string Original, string Current)[] changed, string[] inserted, string[]? desiredValues = null)
{
    internal enum Outcome { Prepared, Acknowledged, Uncertain, Reconciled }
    internal Outcome State { get; set; }
    internal bool ReconciledIntentMatches { get; set; }
    internal bool RequiresReadback { get; private set; }
    private readonly Dictionary<string, bool> _postconditions = new(StringComparer.Ordinal);
    internal const string Attribute = "servicePrincipalName";

    internal void AppendTo(ModifyRequest request, IEnumerable<object?> effectiveValues)
    {
        var values = effectiveValues.ToList();
        void Add(string value)
        {
            // A matching entry-ledger add may already supply this value in the
            // scratch cache. It still needs server readback proof after timeout.
            _postconditions[value] = true;
            if (values.Contains(value)) return;
            values.Add(value);
            Append(DirectoryAttributeOperation.Add, value);
        }
        void Delete(string value)
        {
            values.Remove(value);
            Append(DirectoryAttributeOperation.Delete, value);
        }
        void Append(DirectoryAttributeOperation operation, string value)
        {
            _postconditions[value] = operation == DirectoryAttributeOperation.Add;
            var modification = new DirectoryAttributeModification { Name = Attribute, Operation = operation };
            modification.Add(value);
            request.Modifications.Add(modification);
        }
        // Microsoft SDSUtils.MultiStringToDirectoryEntryConverter order/guards.
        foreach (var value in removed)
        {
            // Symmetric with Add: a staged ordinary delete is not delivery proof.
            _postconditions[value] = false;
            if (values.Contains(value)) Delete(value);
        }
        foreach (var pair in changed) { Delete(pair.Original); Add(pair.Current); }
        foreach (var value in inserted) Add(value);
        if (desiredValues is not null && desiredValues.Any(value => !values.Contains(value)))
            throw new InvalidOperationException("Direct entry edits conflict with the retained service-name set. Resolve both pending intents before saving.");
        RequiresReadback = !request.Modifications.Cast<DirectoryAttributeModification>()
            .Any(modification => modification.Name.Equals(Attribute, StringComparison.OrdinalIgnoreCase));
        if (RequiresReadback && desiredValues is not null)
            foreach (var value in desiredValues) _postconditions[value] = true;
    }

    internal bool MatchesReadback(IEnumerable<object?> values)
    {
        var actual = values.ToHashSet();
        return _postconditions.All(pair => actual.Contains(pair.Key) == pair.Value);
    }
}
