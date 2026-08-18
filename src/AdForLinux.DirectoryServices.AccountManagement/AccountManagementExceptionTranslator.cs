using System.Security.Authentication;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Applies the AccountManagement exception contract to ADSI failures.</summary>
internal static class AccountManagementExceptionTranslator
{
    public static T Execute<T>(Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (COMException exception)
        {
            throw Translate(exception);
        }
    }

    public static void Execute(Action operation) => Execute(() =>
    {
        operation();
        return true;
    });

    public static Exception Translate(COMException exception) =>
        exception.ErrorCode switch
        {
            unchecked((int)0x80070005) =>
                new UnauthorizedAccessException(exception.Message, exception),
            unchecked((int)0x800708C5) or
            unchecked((int)0x80070056) or
            unchecked((int)0x8007052) =>
                new PasswordException(exception.Message, exception),
            unchecked((int)0x800708B0) or
            unchecked((int)0x80071392) =>
                new PrincipalExistsException(exception.Message, exception),
            unchecked((int)0x8007052E) =>
                new AuthenticationException(exception.Message, exception),
            unchecked((int)0x8007202F) or
            unchecked((int)0x80072035) =>
                new InvalidOperationException(exception.Message, exception),
            unchecked((int)0x80070008) =>
                new OutOfMemoryException(exception.Message, exception),
            unchecked((int)0x8007203A) or
            unchecked((int)0x8007200E) or
            unchecked((int)0x8007200F) =>
                new PrincipalServerDownException(
                    exception.Message,
                    exception,
                    exception.ErrorCode,
                    serverName: null!),
            _ => new PrincipalOperationException(
                exception.Message,
                exception,
                exception.ErrorCode),
        };

    public static Exception TranslateProtocol(Exception exception) =>
        Translate(LdapExceptionTranslator.Translate(exception));
}
