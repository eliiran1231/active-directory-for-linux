using System.Text;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData("unary")]
    [InlineData("left")]
    [InlineData("right")]
    public void Deep_condition_rendering_allocates_linearly_and_preserves_payload(string shape)
    {
        // Four times the depth distinguishes linear allocation from copying whole
        // subtrees. Measure the synchronous formatter only, after warming both sizes;
        // input construction and assertions must not contribute to the measurement.
        var small = Prepare(512);
        var large = Prepare(2048);
        _ = A.SddlConditionCodec.Format(small.Payload);
        _ = A.SddlConditionCodec.Format(large.Payload);
        var smallBytes = Measure(small.Payload, out var smallText);
        var largeBytes = Measure(large.Payload, out var largeText);

        Assert.Equal(small.Text, smallText);
        Assert.Equal(large.Text, largeText);
        Assert.Equal(small.Payload, A.SddlConditionCodec.Parse(smallText));
        Assert.Equal(large.Payload, A.SddlConditionCodec.Parse(largeText));
        Assert.Equal(large.Original, large.Payload);
        Assert.Equal(small.Original, small.Payload);
        // Allow runtime/buffer growth overhead without admitting quadratic growth.
        Assert.True(largeBytes <= smallBytes * 6 + 65_536,
            $"{shape}: depth 512 allocated {smallBytes:N0} bytes; depth 2048 allocated {largeBytes:N0} bytes.");

        (string Text, byte[] Payload, byte[] Original) Prepare(int depth)
        {
            var text = new StringBuilder();
            var prefix = shape switch { "unary" => "(!", "left" => "(", _ => "((a) && " };
            var suffix = shape == "left" ? " && (a))" : ")";
            for (var i = 0; i < depth; i++) text.Append(prefix);
            text.Append("(a)");
            for (var i = 0; i < depth; i++) text.Append(suffix);
            var expected = text.ToString();
            var payload = A.SddlConditionCodec.Parse(expected);
            return (expected, payload, (byte[])payload.Clone());
        }

        static long Measure(byte[] payload, out string text)
        {
            var before = GC.GetAllocatedBytesForCurrentThread();
            text = A.SddlConditionCodec.Format(payload);
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }
    }
}
