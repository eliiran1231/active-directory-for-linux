namespace AdForLinux.DirectoryServices.AccountManagement;

[AttributeUsage(AttributeTargets.Property, AllowMultiple = true)]
public sealed class DirectoryPropertyAttribute : Attribute
{
    private ContextType? _context;

    public DirectoryPropertyAttribute(string? schemaAttributeName)
    {
        SchemaAttributeName = schemaAttributeName;
    }

    public string? SchemaAttributeName { get; }
    public ContextType? Context
    {
        get => _context;
        set => _context = value;
    }
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class DirectoryRdnPrefixAttribute : Attribute
{
    public DirectoryRdnPrefixAttribute(string? rdnPrefix)
    {
        RdnPrefix = rdnPrefix;
    }

    public string? RdnPrefix { get; }
    public ContextType? Context => null;
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class DirectoryObjectClassAttribute : Attribute
{
    public DirectoryObjectClassAttribute(string? objectClass)
    {
        ObjectClass = objectClass;
    }

    public string? ObjectClass { get; }
    public ContextType? Context => null;
}
