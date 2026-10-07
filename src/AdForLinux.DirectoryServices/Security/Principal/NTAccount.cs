namespace AdForLinux.Security.Principal;

/// <summary>An unresolved account-name value. Creating this value never resolves the name.</summary>
public sealed class NTAccount : IdentityReference
{
    private readonly string _name;
    public NTAccount(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.Length > 512) throw new ArgumentException("The account name is too long.", nameof(name));
        _name = name;
    }
    public NTAccount(string? domainName, string accountName)
    {
        ArgumentException.ThrowIfNullOrEmpty(accountName);
        if (accountName.Length > 256) throw new ArgumentException("The account name is too long.", nameof(accountName));
        if (domainName?.Length > 255) throw new ArgumentException("The domain name is too long.", nameof(domainName));
        _name = string.IsNullOrEmpty(domainName) ? accountName : domainName + "\\" + accountName;
    }
    public override string Value => _name;
    public override string ToString() => _name;
    public override bool Equals(object? o) => o is NTAccount account && StringComparer.OrdinalIgnoreCase.Equals(_name, account._name);
    public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(_name);
    public override bool IsValidTargetType(Type targetType) => targetType == typeof(SecurityIdentifier) || targetType == typeof(NTAccount);
    public override IdentityReference Translate(Type targetType) => TranslateDetached(targetType);
    public static bool operator ==(NTAccount? left, NTAccount? right) => ReferenceEquals(left, right) || left is not null && left.Equals(right);
    public static bool operator !=(NTAccount? left, NTAccount? right) => !(left == right);
}
