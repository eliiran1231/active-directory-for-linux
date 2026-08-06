using System.Text;
using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A principal that can log on (a user), like Microsoft's
/// <c>AuthenticablePrincipal</c>. Adds account state and password operations on
/// top of <see cref="Principal"/>.
/// </summary>
public abstract class AuthenticablePrincipal : Principal
{
    // userAccountControl bits.
    private const int AccountDisabled = 0x2;
    private const int NormalAccount = 0x200;

    /// <summary>
    /// Whether the account is enabled. Reads and writes the ACCOUNTDISABLE bit
    /// of <c>userAccountControl</c>. Setting it needs a <see cref="Principal.Save"/>.
    /// Null before the object is saved.
    /// </summary>
    public bool? Enabled
    {
        get
        {
            var flags = ReadUserAccountControl();
            return flags is null ? null : (flags.Value & AccountDisabled) == 0;
        }
        set
        {
            if (value is not null)
            {
                SetUserAccountControlBit(AccountDisabled, on: !value.Value);
            }
        }
    }

    /// <summary>
    /// Resets the account password (admin reset). Takes effect immediately, so
    /// the object must already be saved. Requires a TLS connection, which this
    /// port always uses.
    /// </summary>
    public void SetPassword(string newPassword)
    {
        var entry = RequireSaved();

        // AD wants the password quoted and encoded as little-endian UTF-16.
        var quoted = "\"" + newPassword + "\"";
        var bytes = Encoding.Unicode.GetBytes(quoted);
        entry.ReplaceAttributeImmediate("unicodePwd", bytes);
    }

    /// <summary>Unlocks a locked-out account. Takes effect immediately.</summary>
    public void UnlockAccount()
    {
        var entry = RequireSaved();
        entry.ReplaceAttributeImmediate("lockoutTime", "0");
    }

    /// <summary>Forces the password to be changed at next logon. Immediate.</summary>
    public void ExpirePasswordNow()
    {
        var entry = RequireSaved();
        entry.ReplaceAttributeImmediate("pwdLastSet", "0");
    }

    private protected int? ReadUserAccountControl()
    {
        var raw = GetString("userAccountControl");
        return raw is not null && int.TryParse(raw, out var flags) ? flags : null;
    }

    private protected void SetUserAccountControlBit(int bit, bool on)
    {
        var flags = ReadUserAccountControl() ?? NormalAccount;
        flags = on ? flags | bit : flags & ~bit;
        SetString("userAccountControl", flags.ToString());
    }

    private DirectoryEntry RequireSaved() =>
        Entry ?? throw new InvalidOperationException(
            "The account must be saved before this operation.");
}
