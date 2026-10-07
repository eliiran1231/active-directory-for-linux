namespace AdForLinux.Security.Principal;

/// <summary>An immutable identity value. Identity construction performs no name resolution.</summary>
public abstract class IdentityReference
{
    internal IdentityReference() { }
    public abstract string Value { get; }
    public abstract bool IsValidTargetType(Type targetType);
    public abstract IdentityReference Translate(Type targetType);
    public abstract override bool Equals(object? o);
    public abstract override int GetHashCode();
    public abstract override string ToString();
    public static bool operator ==(IdentityReference? left, IdentityReference? right) =>
        ReferenceEquals(left, right) || left is not null && left.Equals(right);
    public static bool operator !=(IdentityReference? left, IdentityReference? right) => !(left == right);

    internal IdentityReference TranslateDetached(Type targetType)
    {
        ArgumentNullException.ThrowIfNull(targetType);
        if (!IsValidTargetType(targetType))
            throw new ArgumentException("The target must be a supported identity type.", nameof(targetType));
        if (targetType == GetType()) return this;
        // Foundation staging only: no resolver authority is inferred from a detached value.
        // This exception is not the final context-bound resolver exception contract.
        throw new NotSupportedException("Cross-kind translation requires the pending context-bound identity resolver.");
    }
}
