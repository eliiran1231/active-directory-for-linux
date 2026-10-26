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
            if (request.RequestId is not null || request.Controls.Cast<DirectoryControl>().Any(c => !c.ServerSide))
                throw new PlatformNotSupportedException("The native mutation cannot represent the request metadata or client-side controls; no request was sent.");
            static byte[][] Values(DirectoryAttribute attribute) => attribute.GetValues(typeof(byte[])).Cast<byte[]>().Select(bytes => bytes.ToArray()).ToArray();
            var controlSources = request.Controls.Cast<DirectoryControl>().ToArray();
            // Describe the complete control policy before invoking any encoder.
            var controls = controlSources.Select(control =>
                new LdapTransportControl(control.Type, [], control.IsCritical)).ToArray();
            var timeout = transport.Timeout;
            LdapMutationCommand command = request switch
            {
                ModifyRequest modify => new LdapModifyCommand(modify.DistinguishedName,
                    modify.Modifications.Cast<DirectoryAttributeModification>().Select(change => new LdapAttributeChange(change.Name, change.Operation, Values(change))).ToArray(), timeout, controls),
                AddRequest add => new LdapAddCommand(add.DistinguishedName,
                    add.Attributes.Cast<DirectoryAttribute>().Select(attribute => new LdapAttributeValues(attribute.Name, Values(attribute))).ToArray(), timeout, controls),
                DeleteRequest delete => new LdapDeleteCommand(delete.DistinguishedName, timeout, controls),
                ModifyDNRequest rename => new LdapModifyDnCommand(rename.DistinguishedName, rename.NewName, rename.NewParentDistinguishedName, rename.DeleteOldRdn, timeout, controls),
                _ => throw new PlatformNotSupportedException("This transport cannot represent the mutation; no request was sent.")
            };
            LdapMutationCommands.RequireCapabilities(transport, command);
            command = command with { Controls = controlSources.Select(control =>
                LdapControlCodec.FromProtocol(control)).ToArray() };
            command = LdapMutationCommands.Prepare(command);
            var remaining = timeout - System.Diagnostics.Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Mutation preparation exhausted the operation budget.");
            command = command with { Timeout = remaining };
            invoked = true;
            var result = LdapMutationCommands.SendAsync(transport, command, submission, CancellationToken.None).GetAwaiter().GetResult();
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
        response.Controls.Select(control => LdapControlCodec.FromProtocol(control)).ToArray());

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
