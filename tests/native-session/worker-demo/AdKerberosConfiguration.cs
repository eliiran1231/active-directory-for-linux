using System.Text.RegularExpressions;
using AdForLinux.DirectoryServices;

namespace AdForLinux.IntegrationTests;

// Runner-local test configuration, never serialized into the result report.
internal sealed record AdKerberosConfiguration(
    string DeploymentDirectory, string Realm, string ServiceHost, int ServicePort,
    string KdcHost, int KdcPort, string CacheA, string CacheB,
    string SearchBaseDn, string SearchFilter, string MarkerAttribute,
    string MarkerValueA, string MarkerValueB, string[] ExpectedDnsA, string[] ExpectedDnsB)
{
    internal void Validate()
    {
        foreach (var path in new[] { DeploymentDirectory, CacheA, CacheB })
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.Contains('\0'))
                throw new ArgumentException("configuration-path");
        if (CacheA == CacheB) throw new ArgumentException("distinct-snapshots-required");
        if (string.IsNullOrWhiteSpace(SearchBaseDn) || SearchBaseDn.Length > 8192 ||
            string.IsNullOrWhiteSpace(SearchFilter) || SearchFilter.Length > 8192 ||
            !Regex.IsMatch(MarkerAttribute ?? "", "^[A-Za-z][A-Za-z0-9-]{0,63}$") ||
            string.IsNullOrEmpty(MarkerValueA) || string.IsNullOrEmpty(MarkerValueB) || MarkerValueA == MarkerValueB)
            throw new ArgumentException("fixture-configuration");
        if (ExpectedDnsA is not { Length: 2 } || ExpectedDnsB is not { Length: 2 } ||
            ExpectedDnsA.Concat(ExpectedDnsB).Any(string.IsNullOrWhiteSpace) ||
            ExpectedDnsA.Concat(ExpectedDnsB).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4)
            throw new ArgumentException("disjoint-two-row-fixtures-required");
        // Validate through the actual selected public profile, not a parallel
        // test-only auth recipe. Construction is inert and does not read caches.
        _ = new RestrictedKerberosProfile(DeploymentDirectory, CacheA, Realm, ServiceHost, ServicePort, KdcHost, KdcPort);
    }

    internal RestrictedKerberosProfile Profile(KerberosCredentialContext owner)
        => new(DeploymentDirectory, owner, Realm, ServiceHost, ServicePort, KdcHost, KdcPort);
}
