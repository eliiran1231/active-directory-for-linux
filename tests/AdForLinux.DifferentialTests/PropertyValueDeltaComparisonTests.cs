using System.DirectoryServices.Protocols;
using System.Net;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyValueDeltaComparisonTests
{
    private const int RangedMemberCount = 1501;

    [Fact]
    public void Large_multi_valued_attribute_deltas_match_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var ouDn = $"OU=i40-{suffix},{DifferentialSettings.BaseDn}";
        var groupDn = $"CN=i40-g-{suffix},{ouDn}";
        var baselineMembers = Enumerable.Range(0, RangedMemberCount)
            .Select(index => $"CN=i40-{suffix}-{index:D4},{ouDn}")
            .ToArray();
        var lateMember = $"CN=i40-{suffix}-late,{ouDn}";
        var appendedMember = $"CN=i40-{suffix}-add,{ouDn}";

        try
        {
            using var connection = OpenProtocolConnection();
            AddEntry(connection, ouDn, "top", "organizationalUnit");
            foreach (var memberDn in baselineMembers.Append(lateMember).Append(appendedMember))
            {
                var accountName = memberDn.Split(',')[0][3..];
                AddEntry(
                    connection,
                    memberDn,
                    "top",
                    "person",
                    "organizationalPerson",
                    "user",
                    new DirectoryAttribute("sAMAccountName", accountName));
            }

            AddEntry(
                connection,
                groupDn,
                "top",
                "group",
                new DirectoryAttribute("sAMAccountName", $"i40g{suffix}"));

            ReplaceMembers(connection, groupDn, baselineMembers);
            var microsoft = ExerciseMicrosoft(
                connection,
                groupDn,
                baselineMembers,
                lateMember,
                appendedMember);

            ReplaceMembers(connection, groupDn, baselineMembers);
            var ours = ExerciseOurs(
                connection,
                groupDn,
                baselineMembers,
                lateMember,
                appendedMember);

            new Comparison("PropertyValueCollection ranged delta operations")
                .Check("downloaded count", microsoft.DownloadedCount, ours.DownloadedCount)
                .Check("add exception", microsoft.AddException, ours.AddException)
                .Check("remove exception", microsoft.RemoveException, ours.RemoveException)
                .Check("replace exception", microsoft.ReplaceException, ours.ReplaceException)
                .Check("clear exception", microsoft.ClearException, ours.ClearException)
                .CheckSet("after concurrent add/remove", microsoft.AfterDelta, ours.AfterDelta)
                .CheckSet("after replacement", microsoft.AfterReplace, ours.AfterReplace)
                .CheckSet("after clear", microsoft.AfterClear, ours.AfterClear)
                .Assert();

            Assert.True(microsoft.DownloadedCount < RangedMemberCount);
            Assert.Equal(
                baselineMembers[..^1].Append(lateMember).Append(appendedMember)
                    .Order(StringComparer.OrdinalIgnoreCase),
                ours.AfterDelta.Order(StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);
            Assert.Equal(
                baselineMembers[..2].Order(StringComparer.OrdinalIgnoreCase),
                ours.AfterReplace.Order(StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);
            Assert.Empty(ours.AfterClear);
        }
        finally
        {
            SafeDelete(ouDn);
        }
    }

    private static DeltaResult ExerciseMicrosoft(
        LdapConnection connection,
        string groupDn,
        string[] baselineMembers,
        string lateMember,
        string appendedMember)
    {
        using var entry = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(groupDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        entry.RefreshCache(new[] { "member" });
        var members = entry.Properties["member"];
        var downloadedCount = members.Count;

        AddMember(connection, groupDn, lateMember);
        var addError = Record.Exception(() =>
        {
            members.Add(appendedMember);
            entry.CommitChanges();
        });
        var removeError = Record.Exception(() =>
        {
            members.Remove(baselineMembers[^1]);
            entry.CommitChanges();
        });
        var afterDelta = ReadMembers(connection, groupDn);

        var replaceError = Record.Exception(() =>
        {
            members.Value = baselineMembers[..2];
            entry.CommitChanges();
        });
        var afterReplace = ReadMembers(connection, groupDn);

        var clearError = Record.Exception(() =>
        {
            members.Clear();
            entry.CommitChanges();
        });

        return new DeltaResult(
            downloadedCount,
            addError?.GetType().Name,
            removeError?.GetType().Name,
            replaceError?.GetType().Name,
            clearError?.GetType().Name,
            afterDelta,
            afterReplace,
            ReadMembers(connection, groupDn));
    }

    private static DeltaResult ExerciseOurs(
        LdapConnection connection,
        string groupDn,
        string[] baselineMembers,
        string lateMember,
        string appendedMember)
    {
        using var entry = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(groupDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        entry.RefreshCache(new[] { "member" });
        var members = entry.Properties["member"];
        var downloadedCount = members.Count;

        AddMember(connection, groupDn, lateMember);
        var addError = Record.Exception(() =>
        {
            members.Add(appendedMember);
            entry.CommitChanges();
        });
        var removeError = Record.Exception(() =>
        {
            members.Remove(baselineMembers[^1]);
            entry.CommitChanges();
        });
        var afterDelta = ReadMembers(connection, groupDn);

        var replaceError = Record.Exception(() =>
        {
            members.Value = baselineMembers[..2];
            entry.CommitChanges();
        });
        var afterReplace = ReadMembers(connection, groupDn);

        var clearError = Record.Exception(() =>
        {
            members.Clear();
            entry.CommitChanges();
        });

        return new DeltaResult(
            downloadedCount,
            addError?.GetType().Name,
            removeError?.GetType().Name,
            replaceError?.GetType().Name,
            clearError?.GetType().Name,
            afterDelta,
            afterReplace,
            ReadMembers(connection, groupDn));
    }

    private static LdapConnection OpenProtocolConnection()
    {
        var connection = new LdapConnection(
            new LdapDirectoryIdentifier(DifferentialSettings.Host, DifferentialSettings.Port),
            new NetworkCredential(DifferentialSettings.BindDn, DifferentialSettings.BindPassword),
            DifferentialSettings.UseTls ? AuthType.Basic : AuthType.Negotiate);
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = DifferentialSettings.UseTls;
        connection.Bind();
        return connection;
    }

    private static void AddEntry(
        LdapConnection connection,
        string dn,
        string firstObjectClass,
        string secondObjectClass,
        params DirectoryAttribute[] attributes) =>
        AddEntry(connection, dn, new[] { firstObjectClass, secondObjectClass }, attributes);

    private static void AddEntry(
        LdapConnection connection,
        string dn,
        string firstObjectClass,
        string secondObjectClass,
        string thirdObjectClass,
        string fourthObjectClass,
        params DirectoryAttribute[] attributes) =>
        AddEntry(
            connection,
            dn,
            new[] { firstObjectClass, secondObjectClass, thirdObjectClass, fourthObjectClass },
            attributes);

    private static void AddEntry(
        LdapConnection connection,
        string dn,
        string[] objectClasses,
        DirectoryAttribute[] attributes)
    {
        var request = new AddRequest(dn, new DirectoryAttribute("objectClass", objectClasses));
        foreach (var attribute in attributes)
        {
            request.Attributes.Add(attribute);
        }

        connection.SendRequest(request);
    }

    private static void ReplaceMembers(LdapConnection connection, string groupDn, IEnumerable<string> members)
    {
        var modification = new DirectoryAttributeModification
        {
            Name = "member",
            Operation = DirectoryAttributeOperation.Replace,
        };
        foreach (var member in members)
        {
            modification.Add(member);
        }

        var request = new ModifyRequest(groupDn);
        request.Modifications.Add(modification);
        connection.SendRequest(request);
    }

    private static void AddMember(LdapConnection connection, string groupDn, string member)
    {
        var modification = new DirectoryAttributeModification
        {
            Name = "member",
            Operation = DirectoryAttributeOperation.Add,
        };
        modification.Add(member);
        var request = new ModifyRequest(groupDn);
        request.Modifications.Add(modification);
        connection.SendRequest(request);
    }

    private static string[] ReadMembers(LdapConnection connection, string groupDn)
    {
        var values = new List<string>();
        for (var start = 0; ;)
        {
            var response = (SearchResponse)connection.SendRequest(new SearchRequest(
                groupDn,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Base,
                $"member;range={start}-*"));
            var entry = response.Entries[0];
            var returnedName = entry.Attributes.AttributeNames.Cast<string>()
                .SingleOrDefault(name => name.StartsWith("member", StringComparison.OrdinalIgnoreCase));
            if (returnedName is null)
            {
                return values.ToArray();
            }

            values.AddRange(entry.Attributes[returnedName].GetValues(typeof(string)).Cast<string>());
            var range = returnedName.Split(';')
                .FirstOrDefault(part => part.StartsWith("range=", StringComparison.OrdinalIgnoreCase));
            if (range is null || range.EndsWith("-*", StringComparison.Ordinal))
            {
                return values.ToArray();
            }

            start = int.Parse(range[(range.IndexOf('-') + 1)..]) + 1;
        }
    }

    private static void SafeDelete(string dn)
    {
        try
        {
            using var entry = new Ours.DirectoryEntry(
                DifferentialSettings.PathFor(dn),
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword,
                DifferentialSettings.OurAuthenticationTypes);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup after a failed live differential assertion.
        }
    }

    private sealed record DeltaResult(
        int DownloadedCount,
        string? AddException,
        string? RemoveException,
        string? ReplaceException,
        string? ClearException,
        string[] AfterDelta,
        string[] AfterReplace,
        string[] AfterClear);
}
