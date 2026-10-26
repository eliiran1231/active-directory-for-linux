using System.DirectoryServices.Protocols;
using System.Runtime.ExceptionServices;

namespace AdForLinux.DirectoryServices.Ldap;

// Dispatch by complete request capability, never by the public method that built it.
// This borrows a lease; no acquisition, backend switching, disposal or replay occurs here.
internal static class LdapMutationDispatcher
{
    internal static LdapWriteOutcome Send(ILdapRequestTransport transport, DirectoryRequest request,
        Func<DirectoryResponse> sendProtocols, Action invalidate)
    {
        if (transport is ProtocolsLdapTransport)
            return ClassifySubmitted(() => Envelope(sendProtocols()));

        var submission = new LdapSubmission();
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var invoked = false;
        try
        {
            if (request is not ModifyRequest modify || transport is not ILdapConversationTransport conversation ||
                (transport.Capabilities & LdapTransportCapabilities.Modify) == 0)
                throw new PlatformNotSupportedException("This transport cannot represent the mutation; no request was sent.");
            if (request.RequestId is not null || request.Controls.Cast<DirectoryControl>().Any(c => !c.ServerSide))
                throw new PlatformNotSupportedException("The native mutation cannot represent the request metadata or client-side controls; no request was sent.");
            if (request.Controls.Count != 0 && (transport.Capabilities & LdapTransportCapabilities.ModifyControls) == 0)
                throw new PlatformNotSupportedException("This transport cannot represent the mutation controls; no request was sent.");
            static string Text(string value) => value is null || value.Contains('\0')
                ? throw new ArgumentException("LDAP request strings cannot be null or contain NUL.") : value;
            var changes = modify.Modifications.Cast<DirectoryAttributeModification>().Select(change =>
            {
                if (change.Operation is < DirectoryAttributeOperation.Add or > DirectoryAttributeOperation.Replace)
                    throw new ArgumentException("Invalid modification operation.");
                return new LdapAttributeChange(Text(change.Name), change.Operation,
                    change.GetValues(typeof(byte[])).Cast<byte[]>().Select(bytes => bytes.ToArray()).ToArray());
            }).ToArray();
            if (changes.Length == 0) throw new ArgumentException("A modify request must contain a change.");
            var controls = request.Controls.Cast<DirectoryControl>().Select(control =>
                new LdapTransportControl(Text(control.Type), control.GetValue().ToArray(), control.IsCritical)).ToArray();
            var remaining = transport.Timeout - System.Diagnostics.Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Mutation preparation exhausted the operation budget.");
            var command = new LdapModifyCommand(Text(modify.DistinguishedName), changes, remaining, controls);
            invoked = true;
            var result = conversation.ModifyAsync(command, submission, CancellationToken.None).GetAwaiter().GetResult();
            if (!submission.Started || result is null) throw new InvalidOperationException("Invalid mutation completion contract.");
            return new(LdapWriteDisposition.Completed, result, null);
        }
        catch (Exception error)
        {
            if (invoked) invalidate();
            return new(submission.Started ? LdapWriteDisposition.Indeterminate : LdapWriteDisposition.NotSent, null, error);
        }
    }

    // Existing controlled commit seams have the same conservative send boundary as
    // Protocols: once invoked, an exception without a negative LDAP response is unknown.
    internal static LdapWriteOutcome ClassifySubmitted(Func<LdapResultEnvelope> send)
    {
        try { return new(LdapWriteDisposition.Completed, send(), null); }
        catch (DirectoryOperationException error) when (error.Response is { ResultCode: not ResultCode.Success } response)
        { return new(LdapWriteDisposition.Completed, Envelope(response), error); }
        catch (Exception error) { return new(LdapWriteDisposition.Indeterminate, null, error); }
    }

    private static LdapResultEnvelope Envelope(DirectoryResponse response) => new(response.ResultCode,
        response.MatchedDN, response.ErrorMessage, response.Referral.Select(uri => uri.ToString()).ToArray(),
        response.Controls.Select(control => new LdapTransportControl(control.Type, control.GetValue(), control.IsCritical)).ToArray());

    internal static void ThrowIfFailed(LdapWriteOutcome outcome)
    {
        if (outcome.Error is { } error)
        {
            if (LdapExceptionTranslator.IsProtocolFailure(error)) throw LdapExceptionTranslator.Translate(error);
            ExceptionDispatchInfo.Capture(error).Throw();
        }
        if (outcome.Disposition != LdapWriteDisposition.Completed || outcome.Result is null)
            throw new InvalidOperationException("The directory write has no definitive response.");
        if (outcome.Result.Code != ResultCode.Success)
            throw LdapExceptionTranslator.Translate(outcome.Result.Code,
                outcome.Result.Diagnostic ?? $"The directory write failed with result {outcome.Result.Code}.");
    }
}
