namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>An Active Directory computer account.</summary>
[DirectoryRdnPrefix("CN")]
public class ComputerPrincipal : AuthenticablePrincipal
{
    private PrincipalValueCollection<string>? _servicePrincipalNames;
    private PrincipalServiceNameWrite? _serviceNamesWrite;
    private PrincipalValueCollection<string>.ChangeSet? _serviceNamesSnapshot;

    public ComputerPrincipal(PrincipalContext context)
        : base(context)
    {
    }

    public ComputerPrincipal(PrincipalContext context, string samAccountName, string password, bool enabled)
        : base(context, samAccountName, password, enabled)
    {
        if (samAccountName is null || password is null) throw new ArgumentException("The account name and password cannot be null.");
        Name = samAccountName;
    }

    internal ComputerPrincipal(PrincipalContext context, DirectoryEntry entry) : base(context)
    {
        AttachExisting(context, entry);
    }

    private protected override string CreateObjectClass => "computer";
    internal override string CategoryFilter => "(objectClass=computer)";
    private protected override int DefaultUserAccountControl => 0x1000;

    public PrincipalValueCollection<string> ServicePrincipalNames
    {
        get
        {
            CheckDisposedOrDeleted();
            return _servicePrincipalNames ??= new PrincipalValueCollection<string>(
                GetValues("servicePrincipalName"),
                values => { if (Entry is null) SetValues("servicePrincipalName", values.Distinct().ToArray()); }, trackChanges: true);
        }
    }

    private void AcknowledgeServiceNames()
    {
        if (_serviceNamesWrite is null) return;
        if (_serviceNamesWrite.State == PrincipalServiceNameWrite.Outcome.Reconciled
            && !_serviceNamesWrite.ReconciledIntentMatches)
            throw new InvalidOperationException("Service-name readback does not establish the requested result. Verify the uncertain operation and acquire a fresh principal before editing service names again.");
        if (_serviceNamesWrite.State is PrincipalServiceNameWrite.Outcome.Acknowledged or PrincipalServiceNameWrite.Outcome.Reconciled)
        {
            _servicePrincipalNames!.Acknowledge(_serviceNamesSnapshot!);
            _serviceNamesWrite = null;
            _serviceNamesSnapshot = null;
        }
    }

    private protected override void OnBeforeSave()
    {
        AcknowledgeServiceNames();
        if (_serviceNamesWrite?.State == PrincipalServiceNameWrite.Outcome.Uncertain)
            throw new InvalidOperationException("Refresh the underlying entry to reconcile the uncertain service-name write before saving again.");
        base.OnBeforeSave();
        if (Entry is null) _serviceNamesSnapshot = _servicePrincipalNames?.CaptureChanges();
    }

    private protected override void CommitEntryChanges(DirectoryEntry entry)
    {
        if (_servicePrincipalNames is null) { base.CommitEntryChanges(entry); return; }
        _serviceNamesSnapshot = _servicePrincipalNames.CaptureChanges();
        if (_serviceNamesSnapshot.Removed.Length == 0 && _serviceNamesSnapshot.Changed.Length == 0
            && _serviceNamesSnapshot.Inserted.Length == 0)
        {
            _servicePrincipalNames.Acknowledge(_serviceNamesSnapshot);
            _serviceNamesSnapshot = null; _serviceNamesWrite = null;
            base.CommitEntryChanges(entry);
            return;
        }
        _serviceNamesWrite = new PrincipalServiceNameWrite(_serviceNamesSnapshot.Removed,
            _serviceNamesSnapshot.Changed, _serviceNamesSnapshot.Inserted);
        try { entry.CommitPrincipalServiceNames(_serviceNamesWrite); }
        finally { AcknowledgeServiceNames(); }
    }

    private protected override void OnAfterSave()
    {
        base.OnAfterSave();
        // Persisted writes are acknowledged before post-save work. A new object
        // still follows Principal's existing insert/rollback lifecycle.
        if (_serviceNamesWrite is null && _serviceNamesSnapshot is { } snapshot)
        {
            _servicePrincipalNames!.Acknowledge(snapshot);
            _serviceNamesSnapshot = null;
        }
    }

    public static new ComputerPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        (ComputerPrincipal?)FindByIdentityWithType(context, typeof(ComputerPrincipal), identityValue);

    public static new ComputerPrincipal? FindByIdentity(PrincipalContext context, IdentityType identityType, string identityValue) =>
        (ComputerPrincipal?)FindByIdentityWithType(context, typeof(ComputerPrincipal), identityType, identityValue);

    public static new PrincipalSearchResult<ComputerPrincipal> FindByLockoutTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByLockoutTime<ComputerPrincipal>(context, time, type);
    public static new PrincipalSearchResult<ComputerPrincipal> FindByLogonTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByLogonTime<ComputerPrincipal>(context, time, type);
    public static new PrincipalSearchResult<ComputerPrincipal> FindByExpirationTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByExpirationTime<ComputerPrincipal>(context, time, type);
    public static new PrincipalSearchResult<ComputerPrincipal> FindByBadPasswordAttempt(PrincipalContext context, DateTime time, MatchType type) =>
        FindByBadPasswordAttempt<ComputerPrincipal>(context, time, type);
    public static new PrincipalSearchResult<ComputerPrincipal> FindByPasswordSetTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByPasswordSetTime<ComputerPrincipal>(context, time, type);

}
