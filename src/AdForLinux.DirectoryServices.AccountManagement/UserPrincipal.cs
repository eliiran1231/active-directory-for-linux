using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A user account, like Microsoft's <c>UserPrincipal</c>. Find one with
/// <see cref="FindByIdentity(PrincipalContext, string)"/>, then read its
/// properties.
/// </summary>
public class UserPrincipal : AuthenticablePrincipal
{
    /// <summary>Starts a new, unsaved user in a context. Saving arrives later.</summary>
    public UserPrincipal(PrincipalContext context)
    {
        ContextRef = context;
    }

    internal UserPrincipal(PrincipalContext context, DirectoryEntry entry)
    {
        AttachExisting(context, entry);
    }

    /// <summary>The first name (<c>givenName</c>).</summary>
    public string? GivenName
    {
        get => GetString("givenName");
        set => SetString("givenName", value);
    }

    /// <summary>The last name (<c>sn</c>).</summary>
    public string? Surname
    {
        get => GetString("sn");
        set => SetString("sn", value);
    }

    /// <summary>The email address (<c>mail</c>).</summary>
    public string? EmailAddress
    {
        get => GetString("mail");
        set => SetString("mail", value);
    }

    /// <summary>The phone number (<c>telephoneNumber</c>).</summary>
    public string? VoiceTelephoneNumber
    {
        get => GetString("telephoneNumber");
        set => SetString("telephoneNumber", value);
    }

    /// <summary>Finds a user by a value across the common identity attributes.</summary>
    public static UserPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        Find(context, null, identityValue);

    /// <summary>Finds a user by a specific identity type.</summary>
    public static UserPrincipal? FindByIdentity(
        PrincipalContext context, IdentityType identityType, string identityValue) =>
        Find(context, identityType, identityValue);

    private static UserPrincipal? Find(PrincipalContext context, IdentityType? identityType, string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(identityValue);

        var idFilter = IdentityFilter.Build(identityType, identityValue);
        var filter = $"(&(objectCategory=person)(objectClass=user){idFilter})";

        var root = context.CreateDirectoryEntry(context.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter);
            var result = searcher.FindOne();
            if (result is null)
            {
                return null;
            }

            return new UserPrincipal(context, result.GetDirectoryEntry());
        }
        finally
        {
            root.Dispose();
        }
    }
}
