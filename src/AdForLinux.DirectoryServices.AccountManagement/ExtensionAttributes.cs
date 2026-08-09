namespace AdForLinux.DirectoryServices.AccountManagement;

[AttributeUsage(AttributeTargets.Property, AllowMultiple = true)]
public sealed class DirectoryPropertyAttribute : Attribute
{
    public DirectoryPropertyAttribute(string schemaAttributeName)
    {
        ArgumentNullException.ThrowIfNull(schemaAttributeName);
        SchemaAttributeName = schemaAttributeName;
    }

    public string SchemaAttributeName { get; }
    public ContextType? Context
    {
        get => null;
        set { }
    }
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class DirectoryRdnPrefixAttribute : Attribute
{
    public DirectoryRdnPrefixAttribute(string rdnPrefix)
    {
        ArgumentNullException.ThrowIfNull(rdnPrefix);
        RdnPrefix = rdnPrefix;
    }

    public string RdnPrefix { get; }
    public ContextType? Context => null;
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class DirectoryObjectClassAttribute : Attribute
{
    public DirectoryObjectClassAttribute(string objectClass)
    {
        ArgumentNullException.ThrowIfNull(objectClass);
        ObjectClass = objectClass;
    }

    public string ObjectClass { get; }
    public ContextType? Context => null;
}
