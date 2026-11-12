using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Neutral_materialization_checks_cancellation_or_deadline_between_values(bool cancel)
    {
        using var transport = new RecordingTransport { Reply = _ => new(ResultCode.Success, "", null, [], [], [], []) };
        using var cancellation = new CancellationTokenSource();
        var budget = TimeSpan.FromSeconds(1);
        var row = TransportRow("CN=entry", new() { ["displayName"] = ["first", "second"] });
        using var reader = SearchEntryReader.Read(row, transport, () => budget, cancellation.Token).GetEnumerator();

        Assert.True(reader.MoveNext());
        Assert.Equal(("displayName", (object)"first"), reader.Current);
        Assert.Equal(1, transport.Sends);
        if (cancel) cancellation.Cancel();
        else budget = TimeSpan.Zero;

        if (cancel) Assert.Throws<OperationCanceledException>(() => reader.MoveNext());
        else Assert.Throws<TimeoutException>(() => reader.MoveNext());
        Assert.Equal(1, transport.Sends);
        Assert.Equal(0, transport.Disposals); // the enclosing lease owns transport
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Neutral_materialization_refuses_expired_or_cancelled_work_before_schema_dispatch(bool cancel)
    {
        using var transport = new RecordingTransport();
        var row = TransportRow("CN=entry", new() { ["displayName"] = ["value"] });
        using var reader = SearchEntryReader.Read(row, transport,
            () => cancel ? TimeSpan.FromSeconds(1) : TimeSpan.Zero,
            new CancellationToken(cancel)).GetEnumerator();

        if (cancel) Assert.Throws<OperationCanceledException>(() => reader.MoveNext());
        else Assert.Throws<TimeoutException>(() => reader.MoveNext());
        Assert.Equal(0, transport.Sends);
        Assert.Equal(0, transport.Disposals);
    }

    [Theory]
    [InlineData("2.5.5.8", "1", "TRUE", "invalid", "FALSE")]
    [InlineData("2.5.5.9", "2", "42", "2147483648", "-42")]
    [InlineData("2.5.5.16", "65", "9223372036854775807", "9223372036854775808", "-1")]
    [InlineData("2.5.5.11", "24", "20240229010000Z", "20230229010000Z", "20240301010000Z")]
    public void Neutral_conversion_failure_remains_visible_and_does_not_poison_cached_schema(
        string syntax, string omSyntax, string first, string invalid, string replacement)
    {
        using var transport = new RecordingTransport();
        transport.Reply = command => new(ResultCode.Success, "", null,
            command.BaseDn == ""
                ? [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })]
                : [TransportRow("CN=field,CN=Schema", new() {
                    ["lDAPDisplayName"] = ["field"], ["attributeSyntax"] = [syntax], ["oMSyntax"] = [omSyntax] })],
            [], [], []);
        var row = TransportRow("CN=entry", new() { ["field;range=0-1"] = [first, invalid] });
        using (var reader = SearchEntryReader.Read(row, transport).GetEnumerator())
        {
            Assert.True(reader.MoveNext());
            Assert.Equal("field;range=0-1", reader.Current.Name);
            Assert.Equal(2, transport.Sends);
            var error = Record.Exception(() => reader.MoveNext());
            if (syntax is "2.5.5.9" or "2.5.5.16") Assert.IsType<OverflowException>(error);
            else Assert.IsType<FormatException>(error);
        }

        // Repair only the bad wire value. The same cached syntax must still
        // convert every value, preserving the range suffix for membership code.
        row.Attributes["field;range=0-1"][1] = Encoding.UTF8.GetBytes(replacement);
        var repaired = SearchEntryReader.Read(row, transport).ToArray();
        Assert.Equal(2, repaired.Length);
        Assert.All(repaired, value => Assert.Equal("field;range=0-1", value.Name));
        object[] expected = syntax switch
        {
            "2.5.5.8" => [true, false],
            "2.5.5.9" => [42, -42],
            "2.5.5.16" => [long.MaxValue, -1L],
            "2.5.5.11" => [new DateTime(2024, 2, 29, 1, 0, 0), new DateTime(2024, 3, 1, 1, 0, 0)],
            _ => throw new ArgumentOutOfRangeException(nameof(syntax)),
        };
        for (var index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index].GetType(), repaired[index].Value.GetType());
            Assert.Equal(expected[index], repaired[index].Value);
        }
        Assert.Equal(2, transport.Sends);
        Assert.Equal(0, transport.Disposals);
    }
}
