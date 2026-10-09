#pragma warning disable CA1416 // Shared enum constants; this path performs portable LDAP operations.
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.Ldap;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    private readonly object _entryWriteGate = new();
    private long _entryChangeVersion;
    private int _commitRunning;
    private sealed record UncertainWrite(bool Creating, long Generation, string[] Attributes,
        SecurityMasks SecuritySections, PropertyValueCollection[] Properties, long[] Versions,
        ActiveDirectorySecurity? Security, long SecurityVersion);
    private UncertainWrite? _uncertainWrite;
    // Controlled seams execute the same production planner/publication paths. They
    // replace transport or pause scheduling, and never become public callbacks or copied authority.
    internal Func<SecurityMasks, byte[]>? SecurityReadOverride { get; set; }
    internal Func<DirectoryRequest, ResultCode>? WriteRequestOverride { get; set; }
    internal Action<PropertyValueCollection>? BeforePropertyRegistration { get; set; }

    private void RefreshPortableCache(string[] names, bool full, bool requireObject = false)
    {
        var generation = IdentityLifetime.Capture(ThrowIfDisposed);
        ActiveDirectorySecurity? security; long entryVersion; long securityVersion; UncertainWrite? uncertainty;
        lock (A.FacadeMutation.Gate)
        lock (_entryWriteGate)
        {
            security = _objectSecurity; entryVersion = _entryChangeVersion;
            securityVersion = security?.CaptureIdentityRead().Version ?? 0;
            uncertainty = _uncertainWrite;
        }
        if (uncertainty is { } prior && prior.Generation != generation)
            throw new InvalidOperationException("An uncertain write belongs to an earlier entry binding. Reconcile that target separately before using a new entry handle.");
        var readMasks = EffectiveSecurityMasks();
        var requested = full && uncertainty is not null
            ? names.Concat(uncertainty.Attributes).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() : names;
        var refreshed = ReadProperties(requested.Length == 0 ? new[] { "1.1" } : requested, full, readMasks, uncertainty is not null);
        if (uncertainty is { Creating: true })
            throw new InvalidOperationException("The Add outcome is uncertain. A same-DN object, even with matching attributes, does not prove creation identity. Verify it separately and explicitly acquire an existing-entry handle; this creation handle cannot replay Add.");
        if (requireObject && refreshed.Count == 0)
            throw new DirectoryServicesCOMException("The newly created directory entry could not be read back from the directory.");
        IdentityLifetime.Checked(generation, ThrowIfDisposed, () =>
        {
            lock (A.FacadeMutation.Gate)
            lock (_entryWriteGate)
            {
                if (_entryChangeVersion != entryVersion || !ReferenceEquals(_objectSecurity, security)
                    || (security?._securityDescriptor.MutationVersion ?? 0) != securityVersion)
                    throw new InvalidOperationException("Entry state changed while refresh was in flight.");
                if (!ReferenceEquals(_uncertainWrite, uncertainty))
                    throw new InvalidOperationException("The write recovery state changed during refresh.");
                if (names.Length == 0) return true;
                var recovery = uncertainty is not null
                    && uncertainty.Attributes.All(name => requested.Contains(name, StringComparer.OrdinalIgnoreCase))
                    && (uncertainty.SecuritySections & ~readMasks) == 0;
                var ledgers = uncertainty?.Properties ?? Array.Empty<PropertyValueCollection>();
                var acquired = 0;
                try
                {
                    foreach (var property in ledgers) { Monitor.Enter(property.ChangeGate); acquired++; }
                    if (uncertainty is not null)
                    {
                        bool Discards(string name) => full || names.Contains(name, StringComparer.OrdinalIgnoreCase);
                        foreach (var property in _pendingPropertyChanges)
                        {
                            if (!Discards(property.PropertyName)) continue;
                            var index = Array.IndexOf(ledgers, property);
                            if (index < 0 || property.ChangeVersion != uncertainty.Versions[index])
                                throw new InvalidOperationException("Readback would discard unsent property edits. Retain them and reconcile the uncertain operation explicitly.");
                        }
                        if (Discards("nTSecurityDescriptor") && security is not null && security.PendingWriteSections != SecurityMasks.None
                            && (!ReferenceEquals(security, uncertainty.Security) || securityVersion != uncertainty.SecurityVersion))
                            throw new InvalidOperationException("Readback would discard unsent descriptor edits.");
                        if (recovery && ledgers.Where((property, i) => property.ChangeVersion != uncertainty.Versions[i]).Any())
                            throw new InvalidOperationException("A retained property changed after the uncertain request; recovery cannot acknowledge it.");
                    }
                    if (full)
                    {
                        var owned = new PropertyCollection(OnPropertyChanged, validateOwner: ThrowIfDisposed);
                        foreach (var property in (IEnumerable<PropertyValueCollection>)refreshed)
                            owned.ReplaceLoaded(property.PropertyName, property.Select(value => value!));
                        _pendingPropertyChanges.Clear(); _properties = owned;
                    }
                    else
                    {
                        var properties = _properties ?? new PropertyCollection(OnPropertyChanged, validateOwner: ThrowIfDisposed);
                        properties.MarkLoaded();
                        foreach (var name in names)
                        {
                            properties.RemoveCached(name);
                            _pendingPropertyChanges.RemoveWhere(p => p.PropertyName.Equals(name, StringComparison.OrdinalIgnoreCase));
                        }
                        foreach (var property in (IEnumerable<PropertyValueCollection>)refreshed)
                        {
                            if (HasRangeSpecifier(property.PropertyName) && names.Any(HasRangeSpecifier)) continue;
                            properties.ReplaceLoaded(property.PropertyName, property.Select(value => value!));
                        }
                        _properties = properties;
                    }
                    if (full || names.Contains("nTSecurityDescriptor", StringComparer.OrdinalIgnoreCase))
                    {
                        IdentityLifetime.Invalidate(); _objectSecurity = null;
                    }
                    if (recovery)
                    {
                        foreach (var property in ledgers) property.ResetChanged();
                        _uncertainWrite = null;
                    }
                    else if (uncertainty is not null)
                        _uncertainWrite = uncertainty with { Generation = IdentityLifetime.Capture(ThrowIfDisposed) };
                    _entryChangeVersion++;
                    return true;
                }
                finally { for (var i = acquired - 1; i >= 0; i--) Monitor.Exit(ledgers[i].ChangeGate); }
            }
        });
    }

    private ActiveDirectorySecurity GetPortableObjectSecurity()
    {
        ThrowIfDisposed();
        lock (_entryWriteGate) if (_objectSecurity is { } cached) return cached;
        if (_isNew) throw new InvalidOperationException("A new entry has no server security baseline. Assign an explicit complete creation descriptor or omit it for server defaults.");
        var generation = IdentityLifetime.Capture(ThrowIfDisposed);
        var resolver = DirectoryIdentityResolver.ForEntry(this);
        var masks = EffectiveSecurityMasks();
        var raw = ReadSecurityDescriptorImmediate(masks);
        return IdentityLifetime.Checked(generation, ThrowIfDisposed, () =>
        {
            var value = new ActiveDirectorySecurity(raw, masks);
            value.SetRawReadContext(masks, resolver);
            resolver.Bind(value);
            lock (_entryWriteGate) return _objectSecurity ??= value;
        });
    }

    private void AssignPortableObjectSecurity(ActiveDirectorySecurity value)
    {
        ArgumentNullException.ThrowIfNull(value); ThrowIfDisposed();
        bool same;
        lock (_entryWriteGate) same = ReferenceEquals(_objectSecurity, value);
        if (same) { CommitIfNotCaching(); return; }
        var generation = IdentityLifetime.Capture(ThrowIfDisposed);
        if (_isNew)
        {
            ActiveDirectorySecurity copy;
            lock (A.FacadeMutation.Gate)
            {
                var raw = value._securityDescriptor.MutationState.Descriptor.GetBinaryForm();
                A.RawSecurityWritePreparation.PrepareAdd(raw, value.RetrievedSections & value.RetrievedMasks);
                copy = new ActiveDirectorySecurity(raw, value.RetrievedMasks);
            }
            IdentityLifetime.Checked(generation, ThrowIfDisposed, () =>
            {
                lock (_entryWriteGate) { _objectSecurity = copy; _entryChangeVersion++; }
                return true;
            });
        }
        else
        {
            var destination = GetPortableObjectSecurity();
            var destinationRead = destination.CaptureIdentityRead();
            ActiveDirectorySecurity copy;
            lock (A.FacadeMutation.Gate)
            {
                var sections = value.AssignmentSections;
                if (sections == SecurityMasks.None || (sections & ~(value.RetrievedSections & value.RetrievedMasks)) != 0
                    || (sections & ~destination.RetrievedSections) != 0)
                    throw new InvalidOperationException("Detached assignment requires explicit section edits and a loaded destination baseline for every selected section.");
                copy = new ActiveDirectorySecurity(destination._securityDescriptor.CopyDetachedState(), destination.RetrievedMasks);
                copy.CopyDestinationReadState(destination);
                copy.SetSecurityDescriptorBinaryForm(value._securityDescriptor.MutationState.Descriptor.GetBinaryForm(), Sections(sections));
            }
            IdentityLifetime.Checked(generation, ThrowIfDisposed, () => destination.ValidateIdentityRead(destinationRead, () =>
            {
                lock (_entryWriteGate)
                {
                    if (!ReferenceEquals(_objectSecurity, destination)) throw new InvalidOperationException("The destination changed during assignment.");
                    DirectoryIdentityResolver.ForEntry(this).Bind(copy);
                    _objectSecurity = copy; _entryChangeVersion++;
                }
                return true;
            }));
        }
        CommitIfNotCaching();
    }

    private static AccessControlSections Sections(SecurityMasks mask) =>
        ((mask & SecurityMasks.Owner) != 0 ? AccessControlSections.Owner : 0)
        | ((mask & SecurityMasks.Group) != 0 ? AccessControlSections.Group : 0)
        | ((mask & SecurityMasks.Dacl) != 0 ? AccessControlSections.Access : 0)
        | ((mask & SecurityMasks.Sacl) != 0 ? AccessControlSections.Audit : 0);

    private void CommitPortableChanges()
    {
        if (_disposed) return; // retained clean/disposed SetInfo compatibility
        if (Interlocked.CompareExchange(ref _commitRunning, 1, 0) != 0)
            throw new InvalidOperationException("A commit is already in progress for this entry.");
        try
        {
            ThrowIfDisposed();
            if (_uncertainWrite is not null) throw new InvalidOperationException("The previous write has an uncertain local or server outcome. Refresh the entry before another commit; the server operation cannot be rolled back locally.");
            var generation = IdentityLifetime.Capture(ThrowIfDisposed);
            ActiveDirectorySecurity? security; PropertyValueCollection[] properties; long version; bool creating;
            lock (A.FacadeMutation.Gate)
            lock (_entryWriteGate)
            {
                security = _objectSecurity; creating = _isNew;
                if (!creating && _pendingPropertyChanges.Count == 0 && security is null && _connection is null) return;
                version = _entryChangeVersion;
                properties = creating ? Array.Empty<PropertyValueCollection>() : _pendingPropertyChanges.ToArray();
            }
            if (creating) properties = ((IEnumerable<PropertyValueCollection>)Properties).ToArray();
            var propertyVersions = properties.Select(p => p.ChangeVersion).ToArray();
            if (properties.Any(p => p.PropertyName.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase) && p.Changed))
                throw new InvalidOperationException("Security descriptor writes require ObjectSecurity's raw section-intent planner.");
            DirectoryRequest request;
            A.PreparedRawSecurityWrite? plan = null;
            A.ObjectSecurity.IdentityRead? securityRead = security?.CaptureIdentityRead();
            if (creating)
            {
                var add = new AddRequest(_path.DistinguishedName);
                foreach (var property in properties) if (property.Count != 0) add.Attributes.Add(ToAttribute(property));
                A.RawSecurityWritePreparation.AppendAdd(add, security?._securityDescriptor.MutationState.Descriptor.GetBinaryForm(), security is null ? SecurityMasks.None : security.RetrievedSections & security.RetrievedMasks);
                request = add;
            }
            else
            {
                var modify = new ModifyRequest(_path.DistinguishedName);
                foreach (var property in properties) if (property.Changed) AddModifications(modify, property);
                if (security is not null)
                {
                    plan = A.RawSecurityWritePreparation.PrepareModify(security, security.PendingWriteSections);
                    A.RawSecurityWritePreparation.AppendModify(security, plan, modify);
                }
                request = modify;
            }
            // Capture a connection for this generation, never silently use a later
            // rebind. No owner/facade lock is held during bind or SendRequest.
            var hasRequest = request is AddRequest || ((ModifyRequest)request).Modifications.Count != 0;
            var transport = WriteRequestOverride;
            var connection = hasRequest && transport is null ? GetConnection() : null;
            void CheckState()
            {
                if (_entryChangeVersion != version || !ReferenceEquals(_objectSecurity, security) || _isNew != creating
                    || properties.Where((p, i) => p.ChangeVersion != propertyVersions[i]).Any())
                    throw new InvalidOperationException("Entry state changed during request preparation or execution.");
            }
            T Checked<T>(Func<T> action) => IdentityLifetime.Checked(generation, ThrowIfDisposed, () =>
            {
                T Publish()
                {
                    lock (_entryWriteGate)
                    {
                        // Property callbacks acquire the entry gate only after releasing
                        // their change gate. Hold every captured ledger through validation
                        // and acknowledgement so a later delta cannot be erased.
                        var acquired = 0;
                        try
                        {
                            foreach (var property in properties) { Monitor.Enter(property.ChangeGate); acquired++; }
                            CheckState(); return action();
                        }
                        finally { for (var i = acquired - 1; i >= 0; i--) Monitor.Exit(properties[i].ChangeGate); }
                    }
                }
                return securityRead is null ? Publish() : security!.ValidateIdentityRead(securityRead, Publish);
            });
            Checked(() => true);
            var uncertain = new UncertainWrite(creating, generation,
                request is AddRequest addRequest ? addRequest.Attributes.Cast<DirectoryAttribute>().Select(a => a.Name).ToArray()
                    : ((ModifyRequest)request).Modifications.Cast<DirectoryAttributeModification>().Select(a => a.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                plan?.Sections ?? SecurityMasks.None, properties, propertyVersions, security, securityRead?.Version ?? 0);
            if (hasRequest)
            {
                ResultCode result;
                try
                {
                    // Preserve the protocol response until its delivery outcome is
                    // classified; the public exception translation remains unchanged.
                    result = transport is null ? connection!.SendRequest(request).ResultCode : transport(request);
                }
                catch (DirectoryOperationException error) when (error.Response is { ResultCode: not ResultCode.Success })
                { throw LdapExceptionTranslator.Translate(error); }
                catch (Exception error)
                {
                    // A missing response cannot prove the server rejected the write.
                    // Retain intent but require readback before sending it a second time.
                    lock (_entryWriteGate) _uncertainWrite = uncertain;
                    if (LdapExceptionTranslator.IsProtocolFailure(error)) throw LdapExceptionTranslator.Translate(error);
                    throw;
                }
                if (result != ResultCode.Success) throw LdapExceptionTranslator.Translate(result, $"The directory write failed with result {result}.");
            }
            try
            {
                Checked(() =>
                {
                    foreach (var property in properties) property.ResetChanged();
                    _pendingPropertyChanges.Clear(); _properties = null;
                    _objectSecurity = null;
                    _isNew = false; _entryChangeVersion++;
                    IdentityLifetime.Invalidate();
                    return true;
                });
            }
            catch
            {
                if (hasRequest) lock (_entryWriteGate) _uncertainWrite = uncertain;
                throw;
            }
        }
        finally { Interlocked.Exchange(ref _commitRunning, 0); }
    }
}
