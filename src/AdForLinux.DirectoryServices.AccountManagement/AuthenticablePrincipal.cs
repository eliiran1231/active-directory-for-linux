namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A principal that can log on (a user), like Microsoft's
/// <c>AuthenticablePrincipal</c>. Adds account-state members on top of
/// <see cref="Principal"/>.
/// </summary>
public abstract class AuthenticablePrincipal : Principal
{
    // userAccountControl bit that means the account is disabled.
    private const int AccountDisabled = 0x2;

    /// <summary>
    /// Whether the account is enabled. Read from the ACCOUNTDISABLE bit of
    /// <c>userAccountControl</c>. Null before the object is saved.
    /// </summary>
    public bool? Enabled
    {
        get
        {
            var raw = GetString("userAccountControl");
            if (raw is null || !int.TryParse(raw, out var flags))
            {
                return null;
            }

            return (flags & AccountDisabled) == 0;
        }
    }
}
