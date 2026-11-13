using System.Reflection;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;

// Partial clone-side mirrors of source-pinned Windows Facts. Expected literals
// in HardcodedExpectations.g.cs come only from the supplied Microsoft run.
internal static class HardcodedMirrors
{
    private static string current = "";
    private static readonly Dictionary<string, int> seen = new();
    private static int checks;

    internal static int Run()
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux only");
        PrincipalContext_and_searcher_issue_11_surface_matches_microsoft();
        AuthenticablePrincipal_issue_8_surface_matches_microsoft();
        Principal_issue_7_surface_matches_microsoft();
        Extension_surface_matches_microsoft();
        Construction_and_configuration_are_an_offline_control();
        Empty_list_result_traversal_reset_and_disposal_match();
        Detached_sync_cookie_and_copy_are_independent_after_reset();
        Sort_option_validation_and_state_match_microsoft();
        Directory_synchronization_cookie_and_option_semantics_match_microsoft();
        Directory_searcher_extended_dn_validation_matches_microsoft();
        Directory_searcher_security_mask_validation_matches_microsoft();
        Virtual_list_view_validation_and_derived_values_match_microsoft();

        foreach (var pair in HardcodedExpectations.Values)
        {
            if (seen.GetValueOrDefault(pair.Key) != pair.Value.Length)
                throw new InvalidOperationException("Missing hardcoded observation: " + pair.Key);
        }

        if (checks != 78) throw new InvalidOperationException("Unexpected mirror coverage");
        return checks;
    }

    private static void Start(string type, string method) => current = type + "." + method;

    private static void Check(int line, object? actual)
    {
        var key = current + ":" + line;
        var index = seen.GetValueOrDefault(key);
        var values = HardcodedExpectations.Values[key];
        if (index >= values.Length) throw new InvalidOperationException("Extra observation: " + key);
        var expected = values[index];
        seen[key] = index + 1;
        checks++;
        if (!Equals(expected, actual))
            throw new InvalidOperationException($"{key}[{index}]: Microsoft={expected}; Linux={actual}");
    }

    private static void Error(Action action)
    {
        var error = MirrorExceptionCapture.Capture(action);
        Check(257, error?.GetType().FullName);
    }

    private static void PrincipalContext_and_searcher_issue_11_surface_matches_microsoft()
    {
        Start("PrincipalSurfaceComparisonTests", nameof(PrincipalContext_and_searcher_issue_11_surface_matches_microsoft));
        Check(37, typeof(AM.PrincipalContext).GetProperty("Options")!.CanWrite);
        var property = typeof(AM.PrincipalSearcher).GetProperty("Context")!;
        Check(45, property.CanRead);
        Check(46, property.CanWrite);
        // Enum names were not recorded, so their loop is not reconstructed by guessing.
    }

    private static void AuthenticablePrincipal_issue_8_surface_matches_microsoft()
    {
        Start("PrincipalSurfaceComparisonTests", nameof(AuthenticablePrincipal_issue_8_surface_matches_microsoft));
        foreach (var name in new[] { "AllowReversiblePasswordEncryption", "Certificates", "PermittedLogonTimes", "PermittedWorkstations", "SmartcardLogonRequired", "UserCannotChangePassword" })
        {
            var property = typeof(AM.AuthenticablePrincipal).GetProperty(name)!;
            Check(79, property.CanRead);
            Check(80, property.CanWrite);
            Check(81, property.PropertyType.IsArray);
            Check(82, property.PropertyType.IsGenericType);
        }
    }

    private static void Principal_issue_7_surface_matches_microsoft()
    {
        Start("PrincipalSurfaceComparisonTests", nameof(Principal_issue_7_surface_matches_microsoft));
        Public("FindByIdentity", typeof(AM.PrincipalContext), typeof(string));
        Public("FindByIdentity", typeof(AM.PrincipalContext), typeof(AM.IdentityType), typeof(string));
        Public("Save", typeof(AM.PrincipalContext));
        Public("GetGroups", typeof(AM.PrincipalContext));
        Public("IsMemberOf", typeof(AM.GroupPrincipal));
        Public("IsMemberOf", typeof(AM.PrincipalContext), typeof(AM.IdentityType), typeof(string));
        Protected("FindByIdentityWithType", typeof(AM.PrincipalContext), typeof(Type), typeof(string));
        Protected("FindByIdentityWithType", typeof(AM.PrincipalContext), typeof(Type), typeof(AM.IdentityType), typeof(string));
        Protected("ExtensionGet", typeof(string));
        Protected("ExtensionSet", typeof(string), typeof(object));
        Protected("CheckDisposedOrDeleted");
    }

    private static void Public(string name, params Type[] types)
    {
        var method = typeof(AM.Principal).GetMethod(name, types)!;
        Check(179, method.IsStatic);
        Check(180, method.IsPublic);
    }

    private static void Protected(string name, params Type[] types)
    {
        var method = typeof(AM.Principal).GetMethod(
            name, BindingFlags.Static | BindingFlags.Instance | BindingFlags.NonPublic, types)!;
        Check(194, method.IsStatic);
        Check(195, method.IsFamily);
    }

    private static void Extension_surface_matches_microsoft()
    {
        Start("CustomPrincipalExtensionComparisonTests", nameof(Extension_surface_matches_microsoft));
        var property = typeof(AM.Principal).GetProperty(
            "ContextRaw", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!;
        Check(88, property.CanRead);
        Check(89, property.CanWrite);
        Check(90, property.GetMethod!.IsFamilyOrAssembly);
        Check(92, property.SetMethod!.IsFamilyOrAssembly);
        Check(95, typeof(AM.Principal).GetMethod("GetAuthorizationGroups", Type.EmptyTypes) is not null);
    }

    private static void Construction_and_configuration_are_an_offline_control()
    {
        Start("PropertyCollectionBindingComparisonTests", nameof(Construction_and_configuration_are_an_offline_control));
        using var ours = new DS.DirectoryEntry(
            "LDAP://unused.example.test/DC=example,DC=test", null, null, DS.AuthenticationTypes.Signing);
        Check(51, ours.UsePropertyCache);
        Check(52, (int)ours.AuthenticationType);
    }

    private static void Empty_list_result_traversal_reset_and_disposal_match()
    {
        Start("PrincipalSearchResultPositionComparisonTests", nameof(Empty_list_result_traversal_reset_and_disposal_match));
        using var ours = new AM.PrincipalSearchResult<AM.Principal>(new List<AM.Principal>());
        using var actual = ours.GetEnumerator();
        actual.MoveNext();
        Check(56, actual.MoveNext());
        actual.Reset();
        Check(59, actual.MoveNext());
        actual.Dispose();
        // Tuple Current/error observations were opaque, not silently asserted.
    }

    private static void Detached_sync_cookie_and_copy_are_independent_after_reset()
    {
        Start("SearcherValidationContractComparisonTests", nameof(Detached_sync_cookie_and_copy_are_independent_after_reset));
        byte[] input = [0, 128, 255];
        var ours = new DS.DirectorySynchronization(DS.DirectorySynchronizationOptions.IncrementalValues, input);
        var copy = ours.Copy();
        input[0] = 42;
        ours.GetDirectorySynchronizationCookie()[1] = 42;
        ours.GetDirectorySynchronizationCookie();
        byte[] replacement = [4, 5];
        ours.ResetDirectorySynchronizationCookie(replacement);
        replacement[0] = 99;
        ours.GetDirectorySynchronizationCookie();
        ours.ResetDirectorySynchronizationCookie();
        ours.GetDirectorySynchronizationCookie();
        copy.GetDirectorySynchronizationCookie();
        Check(136, (long)copy.Option);
    }

    private static void Sort_option_validation_and_state_match_microsoft()
    {
        Start("DirectorySearchOptionsComparisonTests", nameof(Sort_option_validation_and_state_match_microsoft));
        var ours = new DS.SortOption("cn", DS.SortDirection.Descending);
        Error(() => ours.PropertyName = null!);
        Error(() => ours.Direction = (DS.SortDirection)int.MaxValue);
        Error(() => new DS.SortOption(null!, DS.SortDirection.Ascending));
        Error(() => new DS.SortOption("cn", (DS.SortDirection)(-1)));
    }

    private static void Directory_synchronization_cookie_and_option_semantics_match_microsoft()
    {
        Start("DirectorySearchOptionsComparisonTests", nameof(Directory_synchronization_cookie_and_option_semantics_match_microsoft));
        new DS.DirectorySynchronization((byte[]?)null).GetDirectorySynchronizationCookie();
        new DS.DirectorySynchronization((DS.DirectorySynchronization?)null).GetDirectorySynchronizationCookie();
        byte[] input = [1, 2, 3];
        var ours = new DS.DirectorySynchronization(input);
        input[0] = 9;
        var cookie = ours.GetDirectorySynchronizationCookie();
        cookie[1] = 8;
        ours.GetDirectorySynchronizationCookie();
        ours.GetDirectorySynchronizationCookie();
        ours.ResetDirectorySynchronizationCookie(null);
        ours.GetDirectorySynchronizationCookie();
        ours.Option = DS.DirectorySynchronizationOptions.ObjectSecurity;
        Error(() => ours.Option = (DS.DirectorySynchronizationOptions)(-1));
        Error(() => new DS.DirectorySynchronization((DS.DirectorySynchronizationOptions)0x400));
    }

    private static void Directory_searcher_extended_dn_validation_matches_microsoft()
    {
        Start("DirectorySearchOptionsComparisonTests", nameof(Directory_searcher_extended_dn_validation_matches_microsoft));
        using var ours = new DS.DirectorySearcher();
        foreach (var value in new[] { -1, 0, 1 }) ours.ExtendedDN = (DS.ExtendedDN)value;
        foreach (var value in new[] { int.MinValue, -2, 2, int.MaxValue })
            Error(() => ours.ExtendedDN = (DS.ExtendedDN)value);
    }

    private static void Directory_searcher_security_mask_validation_matches_microsoft()
    {
        Start("DirectorySearchOptionsComparisonTests", nameof(Directory_searcher_security_mask_validation_matches_microsoft));
        using var ours = new DS.DirectorySearcher();
        for (var value = 0; value <= 15; value++) ours.SecurityMasks = (DS.SecurityMasks)value;
        ours.SecurityMasks = (DS.SecurityMasks)(-1);
        foreach (var value in new[] { 16, int.MaxValue })
            Error(() => ours.SecurityMasks = (DS.SecurityMasks)value);
    }

    private static void Virtual_list_view_validation_and_derived_values_match_microsoft()
    {
        Start("DirectorySearchOptionsComparisonTests", nameof(Virtual_list_view_validation_and_derived_values_match_microsoft));
        Error(() => new DS.DirectoryVirtualListView(-1));
        Error(() => new DS.DirectoryVirtualListView(-1, 0, 0));
        Error(() => new DS.DirectoryVirtualListView(0, -1, 0));
        Error(() => new DS.DirectoryVirtualListView(0, 0, -1));
        var ours = new DS.DirectoryVirtualListView();
        Error(() => ours.ApproximateTotal = -1);
        Error(() => ours.TargetPercentage = -1);
        Error(() => ours.TargetPercentage = 101);
    }
}
