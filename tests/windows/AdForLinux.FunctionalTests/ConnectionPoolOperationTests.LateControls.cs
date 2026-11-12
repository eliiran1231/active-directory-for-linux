using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    public static IEnumerable<object[]> LateMalformedControlCases()
    {
        foreach (var oid in new[] { "1.2.840.113556.1.4.841", "2.16.840.1.113730.3.4.10",
            "1.2.840.113556.1.4.474", "1.2.840.113556.1.4.319", "1.2.840.113556.1.4.1504" })
            foreach (var absent in new[] { false, true })
                foreach (var virtualList in new[] { false, true })
                    yield return [oid, absent, virtualList];
    }

    [Theory]
    [MemberData(nameof(LateMalformedControlCases))]
    public void Late_malformed_control_preserves_previous_public_cookie_or_view_state(
        string malformedOid, bool absent, bool virtualList)
        => AssertLateControlStatePreserved(new(malformedOid, absent ? [] : [0x30, 0x00], false, !absent),
            virtualList, error => Assert.IsType<BerConversionException>(error));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Invalid_VLV_response_preserves_all_previously_published_view_state_regression(bool negativeCount)
        => AssertLateControlStatePreserved(new("2.16.840.1.113730.3.4.10", Convert.FromHexString(negativeCount
            ? "30090201030201FF0A0100" : "30090201FF02010A0A0100"), false),
            true, error => Assert.IsType<ArgumentException>(error), replaceVlv: true);

    [Theory]
    [InlineData("300D02010B02010A0A01000402AABB")]
    [InlineData("301002047FFFFFFF0201010A010004020102")]
    public void Invalid_VLV_percentage_preserves_state_and_next_request_before_healthy_recovery(string response)
        => AssertLateControlStatePreserved(new("2.16.840.1.113730.3.4.10", Convert.FromHexString(response), false),
            true, error => Assert.IsType<ArgumentException>(error), replaceVlv: true);

    [Theory]
    [InlineData(2, 3, 1, 66)]
    [InlineData(9, 10, 9, 90)]
    [InlineData(40, 0, 0, 0)]
    [InlineData(1001, 1000, 1000, 100)]
    public void Successful_VLV_update_preserves_percentage_rounding_and_copies_context(
        int position, int count, int expectedPosition, int expectedPercentage)
    {
        var view = new DirectoryVirtualListView(2, 3, "target") { ApproximateTotal = 10, Offset = 2 };
        byte[] context = [1, 2];
        view.Update(position, count, context);
        context[0] = 9;
        Assert.Equal(expectedPosition, view.Offset);
        Assert.Equal(expectedPercentage, view.TargetPercentage);
        Assert.Equal(count, view.ApproximateTotal);
        Assert.Equal(new byte[] { 1, 2 }, view.DirectoryVirtualListViewContext!.ContextId);
        Assert.Equal(2, view.BeforeCount);
        Assert.Equal(3, view.AfterCount);
        Assert.Equal("target", view.Target);
    }

    private static void AssertLateControlStatePreserved(LdapTransportControl malformed, bool virtualList,
        Action<Exception?> assertFailure, bool replaceVlv = false)
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        using var root = new DirectoryEntry("LDAP://offline.invalid/DC=example,DC=test");
        root.Options.Referral = ReferralChasingOption.None;
        var trace = new List<string>();
        var commands = new List<LdapSearchCommand>();
        var transports = new List<ConversationTransport>();
        var secondResponse = false;
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
            {
                var transport = new ConversationTransport(trace) { OnOpen = commands.Add };
                transport.Capabilities |= LdapTransportCapabilities.SearchControls;
                var controls = new List<LdapTransportControl>
                {
                    new("1.2.840.113556.1.4.841", Convert.FromHexString(secondResponse
                        ? "3009020101020102040109" : "300A020101020102040200FF"), false),
                    new("2.16.840.1.113730.3.4.10", Convert.FromHexString(secondResponse
                        ? "300C02010302010A0A0100040109" : "300D02010202010A0A0100040200FF"), false),
                };
                if (secondResponse)
                {
                    if (replaceVlv) controls[1] = malformed;
                    else controls.Add(malformed);
                }
                transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success) with
                    { Controls = controls.ToArray() }, false));
                transports.Add(transport);
                return new BoundLdapSession(transport, transport, options, new(options), referrals);
            }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        var sync = new DirectorySynchronization([42]);
        var view = new DirectoryVirtualListView(0, 0, 1);
        using var searcher = new DirectorySearcher(root)
        {
            DirectorySynchronization = virtualList ? null : sync,
            VirtualListView = virtualList ? view : null,
            ReferralChasing = ReferralChasingOption.None,
        };

        using (var results = searcher.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(virtualList ? new byte[] { 42 } : new byte[] { 0, 255 }, sync.GetDirectorySynchronizationCookie());
        var previousContext = view.DirectoryVirtualListViewContext;
        var previousPosition = view.Offset;
        var previousTotal = view.ApproximateTotal;
        var previousPercentage = view.TargetPercentage;
        secondResponse = true;

        assertFailure(Record.Exception(() =>
        {
            using var results = searcher.FindAll();
            Assert.Empty(results.Cast<SearchResult>());
        }));

        var rejectedContext = view.DirectoryVirtualListViewContext;
        var rejectedPosition = view.Offset;
        var rejectedTotal = view.ApproximateTotal;
        var rejectedPercentage = view.TargetPercentage;

        Assert.Equal(2, trace.Count(item => item == "open"));
        Assert.Equal(2, transports.Sum(transport => transport.Reads));
        Assert.Equal(0, transports.Sum(transport => transport.Pages));
        Assert.Equal(2, trace.Count(item => item == "cursor-close"));
        // The first search validates its root once with a buffered base read.
        Assert.Equal(1, trace.Count(item => item == "buffered-search"));
        Assert.Equal(virtualList ? 5 : 3, trace.Count(item => item == "session-close"));
        Assert.Equal(0, pool.Snapshot.Total);
        Assert.Equal(virtualList ? new byte[] { 42 } : new byte[] { 0, 255 }, sync.GetDirectorySynchronizationCookie());
        var nextOffset = previousPosition;
        if (replaceVlv)
        {
            // Observe the next actual public request, then a complete healthy
            // response on the same searcher/view before asserting rollback.
            secondResponse = false;
            using (var recovered = searcher.FindAll()) Assert.Empty(recovered.Cast<SearchResult>());
            var control = Assert.Single(commands[2].Controls.Where(item => item.Oid == "2.16.840.1.113730.3.4.9"));
            var reader = new AsnReader(control.Value, AsnEncodingRules.BER);
            var sequence = reader.ReadSequence();
            Assert.Equal(0, (int)sequence.ReadInteger()); // before count
            Assert.Equal(0, (int)sequence.ReadInteger()); // after count
            var target = sequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            nextOffset = (int)target.ReadInteger();
            Assert.Equal(previousTotal, (int)target.ReadInteger());
            target.ThrowIfNotEmpty();
            Assert.Equal(new byte[] { 0, 255 }, sequence.ReadOctetString());
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            Assert.Equal(previousPosition, view.Offset);
            Assert.Equal(previousTotal, view.ApproximateTotal);
            Assert.Equal(previousPercentage, view.TargetPercentage);
            Assert.Equal(3, commands.Count);
            Assert.Equal(3, trace.Count(item => item == "cursor-close"));
            Assert.Equal(7, trace.Count(item => item == "session-close"));
            Assert.Equal(0, pool.Snapshot.Total);
        }
        Assert.Same(previousContext, rejectedContext);
        Assert.Equal(previousPosition, nextOffset);
        Assert.Equal(previousPosition, rejectedPosition);
        Assert.Equal(previousTotal, rejectedTotal);
        Assert.Equal(previousPercentage, rejectedPercentage);
    }
}
