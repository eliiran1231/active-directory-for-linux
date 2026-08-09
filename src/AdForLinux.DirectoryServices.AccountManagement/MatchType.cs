namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Comparison used by query-by-example advanced filters.</summary>
public enum MatchType
{
    Equals = 0,
    NotEquals = 1,
    GreaterThan = 2,
    GreaterThanOrEquals = 3,
    LessThan = 4,
    LessThanOrEquals = 5,
}
