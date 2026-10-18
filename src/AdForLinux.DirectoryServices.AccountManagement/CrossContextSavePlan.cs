namespace AdForLinux.DirectoryServices.AccountManagement;

// Read-only evidence, not a reusable authorization ticket. No entry, context,
// connection, resolver, credential or pending descriptor is retained here.
internal sealed record CrossContextSavePlan(Guid DomainGuid, string DomainSid,
    Guid ObjectGuid, string ObjectSid, string SourceDn, string ReplicaDn,
    Guid ContainerGuid, string ContainerDn, string CurrentRdn, string? PendingName)
{
    internal const string ExecutionBoundary = "Cross-context Save preflight succeeded, but execution is not enabled: " +
        "identity-safe destination ModifyDN/Modify addressing, uncertain-write quarantine and retained-wrapper " +
        "authority rebinding require validation. No write was sent; pending edits and the source binding are retained.";

    internal static CrossContextSavePlan Prepare(PrincipalContext source, PrincipalContext destination,
        DirectoryEntry entry, Guid? retainedObjectGuid, string containerDn, string? pendingName, TimeProvider? timeProvider = null)
    {
        using var operation = new CrossContextSaveOperation(source, destination, entry, retainedObjectGuid, timeProvider);
        return operation.Prepare(containerDn, pendingName);
    }
}
