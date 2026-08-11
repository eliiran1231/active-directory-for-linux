using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>An Active Directory computer account.</summary>
[DirectoryRdnPrefix("CN")]
public class ComputerPrincipal : AuthenticablePrincipal
{
    private PrincipalValueCollection<string>? _servicePrincipalNames;

    public ComputerPrincipal(PrincipalContext context)
        : base(context)
    {
    }

    public ComputerPrincipal(PrincipalContext context, string samAccountName, string password, bool enabled)
        : base(context, samAccountName, password, enabled)
    {
    }

    internal ComputerPrincipal(PrincipalContext context, DirectoryEntry entry) : base(context)
    {
        AttachExisting(context, entry);
    }

    private protected override string CreateObjectClass => "computer";
    internal override string CategoryFilter => "(objectCategory=computer)";
    private protected override int DefaultUserAccountControl => 0x1000;

    public PrincipalValueCollection<string> ServicePrincipalNames =>
        _servicePrincipalNames ??= new PrincipalValueCollection<string>(
            GetValues("servicePrincipalName"),
            values => SetValues("servicePrincipalName", values));

    public static new ComputerPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        Find(context, null, identityValue);

    public static new ComputerPrincipal? FindByIdentity(PrincipalContext context, IdentityType identityType, string identityValue) =>
        Find(context, identityType, identityValue);

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

    private static ComputerPrincipal? Find(PrincipalContext context, IdentityType? identityType, string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(identityValue);
        var filter = $"(&(objectCategory=computer){IdentityFilter.Build(identityType, identityValue)})";
        using var root = context.CreateDirectoryEntry(context.Container);
        using var searcher = new DirectorySearcher(root, filter);
        var result = searcher.FindOne();
        return result is null ? null : new ComputerPrincipal(context, result.GetDirectoryEntry());
    }

}
