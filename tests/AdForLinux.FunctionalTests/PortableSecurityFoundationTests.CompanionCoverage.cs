using AdForLinux.DirectoryServices;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(15)]
    public void Companion_snapshot_coverage_never_promotes_AD_import_masks(int mask)
    {
        var raw = Build(U1, U1, Acl(4), Acl(4));
        var source = new ActiveDirectorySecurity(raw, (SecurityMasks)mask);
        var snapshot = source.CaptureInteropSnapshot();
        Assert.Equal((SecurityMasks)mask, snapshot.Retrieved);
        Assert.Equal(SecurityMasks.None, snapshot.Pending);
        Assert.Equal(raw, snapshot.Raw);
        var called = false;
        byte[] Construct(byte[] bytes, bool container, bool directory) { called = true; return bytes; }
        if (mask == 15) source.ExportInterop(Construct, bytes => bytes);
        else Assert.Throws<NotSupportedException>(() => source.ExportInterop(Construct, bytes => bytes));
        Assert.Equal(mask == 15, called);
        Assert.False(source.HasRawReadContext);
        Assert.Null(source.CaptureIdentityRead().Resolver);
    }
}
