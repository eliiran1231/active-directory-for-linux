namespace AdForLinux.DirectoryServices;

/// <summary>Specifies when aliases are dereferenced during an LDAP search.</summary>
public enum DereferenceAlias
{
    Never = 0,
    InSearching = 1,
    FindingBaseObject = 2,
    Always = 3,
}

/// <summary>Specifies the extended distinguished-name format returned by the server.</summary>
public enum ExtendedDN
{
    None = 0,
    Standard = 1,
    HexString = 2,
}

/// <summary>Specifies a directory-search sort direction.</summary>
public enum SortDirection
{
    Ascending = 0,
    Descending = 1,
}

/// <summary>Describes the server-side sort requested for a directory search.</summary>
public sealed class SortOption
{
    /// <summary>Creates an ascending sort with no property configured.</summary>
    public SortOption()
    {
    }

    /// <summary>Creates a sort for a property and direction.</summary>
    public SortOption(string propertyName, SortDirection direction)
    {
        PropertyName = propertyName;
        Direction = direction;
    }

    /// <summary>The LDAP attribute to sort by.</summary>
    public string? PropertyName { get; set; }

    /// <summary>The sort direction.</summary>
    public SortDirection Direction { get; set; }
}

/// <summary>Options controlling Active Directory directory synchronization.</summary>
[Flags]
public enum DirectorySynchronizationOptions : long
{
    None = 0,
    ObjectSecurity = 0x1,
    ParentsFirst = 0x800,
    PublicDataOnly = 0x2000,
    IncrementalValues = 0x80000000,
}

/// <summary>Stores the cookie and options used by an Active Directory DirSync search.</summary>
public sealed class DirectorySynchronization
{
    private byte[] _cookie = Array.Empty<byte>();

    /// <summary>Creates a synchronization request with no prior cookie.</summary>
    public DirectorySynchronization()
    {
    }

    /// <summary>Creates a synchronization request from a prior cookie.</summary>
    public DirectorySynchronization(byte[] cookie) => ResetDirectorySynchronizationCookie(cookie);

    /// <summary>Creates a synchronization request with options.</summary>
    public DirectorySynchronization(DirectorySynchronizationOptions option) => Option = option;

    /// <summary>Creates a synchronization request with options and a prior cookie.</summary>
    public DirectorySynchronization(DirectorySynchronizationOptions option, byte[] cookie)
    {
        Option = option;
        ResetDirectorySynchronizationCookie(cookie);
    }

    /// <summary>Creates a copy of another synchronization request.</summary>
    public DirectorySynchronization(DirectorySynchronization synchronization)
    {
        ArgumentNullException.ThrowIfNull(synchronization);
        Option = synchronization.Option;
        _cookie = synchronization.GetDirectorySynchronizationCookie();
    }

    /// <summary>Gets or sets the synchronization options.</summary>
    public DirectorySynchronizationOptions Option { get; set; }

    /// <summary>Returns an independent copy of the current synchronization cookie.</summary>
    public byte[] GetDirectorySynchronizationCookie() => _cookie.ToArray();

    /// <summary>Creates an independent copy of this synchronization state.</summary>
    public DirectorySynchronization Copy() => new(this);

    /// <summary>Clears the synchronization cookie.</summary>
    public void ResetDirectorySynchronizationCookie() => _cookie = Array.Empty<byte>();

    /// <summary>Replaces the synchronization cookie.</summary>
    public void ResetDirectorySynchronizationCookie(byte[] cookie)
    {
        ArgumentNullException.ThrowIfNull(cookie);
        _cookie = cookie.ToArray();
    }

    /// <summary>Creates the Protocols control for the current request state.</summary>
    internal System.DirectoryServices.Protocols.DirSyncRequestControl CreateControl() =>
        new(_cookie, (System.DirectoryServices.Protocols.DirectorySynchronizationOptions)(long)Option);

    /// <summary>Captures the cookie returned by the server.</summary>
    internal void Update(System.DirectoryServices.Protocols.DirSyncResponseControl response) =>
        _cookie = response.Cookie?.ToArray() ?? Array.Empty<byte>();
}

/// <summary>Context returned by a virtual-list-view search.</summary>
public sealed class DirectoryVirtualListViewContext
{
    private byte[] _contextId = Array.Empty<byte>();

    /// <summary>Creates an empty virtual-list-view context.</summary>
    public DirectoryVirtualListViewContext()
    {
    }

    internal DirectoryVirtualListViewContext(byte[]? contextId) => _contextId = contextId?.ToArray() ?? Array.Empty<byte>();

    /// <summary>Returns an independent copy of this context.</summary>
    public DirectoryVirtualListViewContext Copy() => new(_contextId);

    internal byte[] ContextId => _contextId;
}

/// <summary>Configures a virtual-list-view LDAP search.</summary>
public sealed class DirectoryVirtualListView
{
    /// <summary>Creates a default virtual-list-view configuration.</summary>
    public DirectoryVirtualListView()
    {
    }

    /// <summary>Creates a configuration centered on an offset.</summary>
    public DirectoryVirtualListView(int offset) => Offset = offset;

    /// <summary>Creates a configuration centered on an offset with surrounding entries.</summary>
    public DirectoryVirtualListView(int beforeCount, int afterCount, int offset)
    {
        BeforeCount = beforeCount;
        AfterCount = afterCount;
        Offset = offset;
    }

    /// <summary>Creates an offset configuration using a prior context.</summary>
    public DirectoryVirtualListView(int beforeCount, int afterCount, int offset, DirectoryVirtualListViewContext context)
        : this(beforeCount, afterCount, offset) => DirectoryVirtualListViewContext = context;

    /// <summary>Creates a configuration centered on a target value.</summary>
    public DirectoryVirtualListView(int beforeCount, int afterCount, string target)
    {
        BeforeCount = beforeCount;
        AfterCount = afterCount;
        Target = target;
    }

    /// <summary>Creates a target configuration using a prior context.</summary>
    public DirectoryVirtualListView(int beforeCount, int afterCount, string target, DirectoryVirtualListViewContext context)
        : this(beforeCount, afterCount, target) => DirectoryVirtualListViewContext = context;

    /// <summary>Entries to return before the target.</summary>
    public int BeforeCount { get; set; }

    /// <summary>Entries to return after the target.</summary>
    public int AfterCount { get; set; }

    /// <summary>The target offset, using LDAP's one-based convention.</summary>
    public int Offset { get; set; } = 1;

    /// <summary>Approximate total entries in the server-side list.</summary>
    public int ApproximateTotal { get; set; }

    /// <summary>Target percentage used when the server computes an offset.</summary>
    public int TargetPercentage { get; set; }

    /// <summary>The optional target value.</summary>
    public string? Target { get; set; }

    /// <summary>The context returned from the previous virtual-list-view request.</summary>
    public DirectoryVirtualListViewContext? DirectoryVirtualListViewContext { get; set; }

    internal System.DirectoryServices.Protocols.VlvRequestControl CreateControl()
    {
        var control = Target is { Length: > 0 }
            ? new System.DirectoryServices.Protocols.VlvRequestControl(BeforeCount, AfterCount, Target)
            : new System.DirectoryServices.Protocols.VlvRequestControl(BeforeCount, AfterCount, Offset);
        control.EstimateCount = ApproximateTotal;
        control.ContextId = DirectoryVirtualListViewContext?.ContextId;
        return control;
    }

    internal void Update(System.DirectoryServices.Protocols.VlvResponseControl response)
    {
        Offset = response.TargetPosition;
        ApproximateTotal = response.ContentCount;
        DirectoryVirtualListViewContext = new DirectoryVirtualListViewContext(response.ContextId);
    }
}
