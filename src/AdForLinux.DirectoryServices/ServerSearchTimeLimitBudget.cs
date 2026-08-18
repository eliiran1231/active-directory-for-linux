using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Tracks a search-wide server time limit independently from the limit applied
/// to each LDAP page request.
/// </summary>
internal sealed class ServerSearchTimeLimitBudget
{
    private readonly TimeSpan _serverTimeLimit;
    private readonly TimeSpan _serverPageTimeLimit;
    private readonly bool _isPaged;
    private readonly TimeProvider _timeProvider;
    private readonly long _startedAt;

    internal ServerSearchTimeLimitBudget(
        TimeSpan serverTimeLimit,
        TimeSpan serverPageTimeLimit,
        bool isPaged,
        TimeProvider timeProvider)
    {
        _serverTimeLimit = serverTimeLimit;
        _serverPageTimeLimit = serverPageTimeLimit;
        _isPaged = isPaged;
        _timeProvider = timeProvider;
        _startedAt = timeProvider.GetTimestamp();
    }

    /// <summary>
    /// Applies the limit for the next request. Returns false when a positive
    /// overall limit has already elapsed and another page must not be sent.
    /// </summary>
    internal bool TryApply(SearchRequest request)
    {
        TimeSpan? requestTimeLimit = null;

        if (_serverTimeLimit >= TimeSpan.Zero)
        {
            var remaining = _serverTimeLimit;
            if (_isPaged && _serverTimeLimit > TimeSpan.Zero)
            {
                remaining -= _timeProvider.GetElapsedTime(_startedAt);
                if (remaining <= TimeSpan.Zero)
                {
                    return false;
                }
            }

            requestTimeLimit = remaining;
        }

        if (_isPaged &&
            _serverPageTimeLimit >= TimeSpan.Zero &&
            (requestTimeLimit is null || _serverPageTimeLimit < requestTimeLimit.Value))
        {
            requestTimeLimit = _serverPageTimeLimit;
        }

        if (requestTimeLimit is not null)
        {
            request.TimeLimit = requestTimeLimit.Value;
        }

        return true;
    }
}
