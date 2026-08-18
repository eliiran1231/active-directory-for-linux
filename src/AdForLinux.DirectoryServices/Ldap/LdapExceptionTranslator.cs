using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Converts the Protocols implementation detail into the exception contract
/// exposed by System.DirectoryServices.
/// </summary>
internal static class LdapExceptionTranslator
{
    private const int AdsUnknownError = unchecked((int)0x80072000);

    public static DirectoryResponse SendRequestCompatible(
        this LdapConnection connection,
        DirectoryRequest request)
    {
        try
        {
            return connection.SendRequest(request);
        }
        catch (Exception exception) when (IsProtocolFailure(exception))
        {
            throw Translate(exception);
        }
    }

    public static T Execute<T>(Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (Exception exception) when (IsProtocolFailure(exception))
        {
            throw Translate(exception);
        }
    }

    public static bool IsProtocolFailure(Exception exception) =>
        exception is LdapException or DirectoryOperationException;

    public static COMException Translate(Exception exception)
    {
        if (exception is DirectoryServicesCOMException compatible)
        {
            return compatible;
        }

        var response = (exception as DirectoryOperationException)?.Response;
        var resultCode = response?.ResultCode;
        var protocolCode = resultCode is null
            ? (exception as LdapException)?.ErrorCode ?? 0
            : (int)resultCode.Value;
        var errorCode = ToHResult(resultCode, protocolCode);
        var serverMessage = string.IsNullOrWhiteSpace(response?.ErrorMessage)
            ? null
            : response.ErrorMessage;
        var message = serverMessage is null
            ? exception.Message
            : $"{exception.Message} {serverMessage}";

        return response is null
            ? new COMException(message, errorCode)
            : new DirectoryServicesCOMException(
                message,
                exception,
                errorCode,
                protocolCode,
                serverMessage);
    }

    public static DirectoryServicesCOMException Translate(
        ResultCode resultCode,
        string message)
    {
        var protocol = new DirectoryOperationException(message);
        return new DirectoryServicesCOMException(
            message,
            protocol,
            ToHResult(resultCode, (int)resultCode),
            (int)resultCode,
            message);
    }

    private static int ToHResult(ResultCode? resultCode, int protocolCode)
    {
        if (resultCode is not null)
        {
            return resultCode.Value switch
            {
                ResultCode.OperationsError => unchecked((int)0x80072020),
                ResultCode.ProtocolError => unchecked((int)0x80072021),
                ResultCode.TimeLimitExceeded => unchecked((int)0x80072022),
                ResultCode.SizeLimitExceeded => unchecked((int)0x80072023),
                ResultCode.AuthMethodNotSupported => unchecked((int)0x80072027),
                ResultCode.StrongAuthRequired => unchecked((int)0x80072028),
                ResultCode.Referral => unchecked((int)0x8007202B),
                ResultCode.UnavailableCriticalExtension => unchecked((int)0x8007202C),
                ResultCode.ConfidentialityRequired => unchecked((int)0x8007202D),
                ResultCode.NoSuchAttribute => unchecked((int)0x8007200A),
                ResultCode.UndefinedAttributeType => unchecked((int)0x8007200C),
                ResultCode.InappropriateMatching => unchecked((int)0x8007200E),
                ResultCode.ConstraintViolation => unchecked((int)0x8007202F),
                ResultCode.AttributeOrValueExists => unchecked((int)0x8007200D),
                ResultCode.InvalidAttributeSyntax => unchecked((int)0x8007200B),
                ResultCode.NoSuchObject => unchecked((int)0x80072030),
                ResultCode.AliasProblem => unchecked((int)0x80072031),
                ResultCode.InvalidDNSyntax => unchecked((int)0x80072032),
                ResultCode.AliasDereferencingProblem => unchecked((int)0x80072034),
                ResultCode.InsufficientAccessRights => unchecked((int)0x80070005),
                ResultCode.Busy => unchecked((int)0x8007200E),
                ResultCode.Unavailable => unchecked((int)0x8007200F),
                ResultCode.UnwillingToPerform => unchecked((int)0x80072035),
                ResultCode.LoopDetect => unchecked((int)0x80072036),
                ResultCode.NamingViolation => unchecked((int)0x80072037),
                ResultCode.NotAllowedOnNonLeaf => unchecked((int)0x80072015),
                ResultCode.NotAllowedOnRdn => unchecked((int)0x80072016),
                ResultCode.EntryAlreadyExists => unchecked((int)0x80071392),
                ResultCode.ObjectClassModificationsProhibited => unchecked((int)0x80072017),
                ResultCode.AffectsMultipleDsas => unchecked((int)0x80072018),
                _ => AdsUnknownError,
            };
        }

        return protocolCode switch
        {
            49 or 1326 => unchecked((int)0x8007052E),
            51 => unchecked((int)0x8007200E),
            52 => unchecked((int)0x8007200F),
            81 => unchecked((int)0x8007203A),
            85 => unchecked((int)0x80072022),
            87 => unchecked((int)0x8007203E),
            _ => AdsUnknownError,
        };
    }
}
