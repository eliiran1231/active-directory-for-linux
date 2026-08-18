using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Tracks a search-wide server time limit independently from the limit applied
/// to each LDAP page request.
/// </summary>
internal sealed class ServerSearchTimeLimitBudget
{
    private static readonly TimeSpan MinimumLdapTimeLimit = TimeSpan.FromSeconds(1);

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

        if (_serverTimeLimit > TimeSpan.Zero)
        {
            var remaining = _serverTimeLimit;
            if (_isPaged)
            {
                remaining -= _timeProvider.GetElapsedTime(_startedAt);
                // LDAP encodes the request time limit as integer seconds. A
                // positive fraction would become zero, which means unlimited.
                if (remaining < MinimumLdapTimeLimit)
                {
                    return false;
                }
            }

            requestTimeLimit = remaining;
        }
        // Zero is LDAP's unlimited sentinel. For paging, leave the overall
        // limit unset so an independently configured page limit can apply.
        else if (_serverTimeLimit == TimeSpan.Zero && !_isPaged)
        {
            requestTimeLimit = TimeSpan.Zero;
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
