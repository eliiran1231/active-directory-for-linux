using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public sealed class ForeignPrincipalResolutionTests
{
    [Fact]
    public void Account_sid_is_reduced_to_issuing_domain_sid()
    {
        var accountSid = SidCodec.Parse("S-1-5-21-111-222-333-1107");

        var domainSid = ForeignPrincipalResolver.TryGetAccountDomainSid(accountSid);

        Assert.NotNull(domainSid);
        Assert.Equal("S-1-5-21-111-222-333", SidCodec.Format(domainSid!));
    }

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    public void Non_account_sid_has_no_trusted_domain_sid(string value)
    {
        Assert.Null(ForeignPrincipalResolver.TryGetAccountDomainSid(SidCodec.Parse(value)));
    }

    [Theory]
    [InlineData("CN=User,OU=People,DC=child,DC=example,DC=com", "child.example.com")]
    [InlineData("CN=User,CN=Users", null)]
    [InlineData("CN=User,DC=example,OU=Invalid", null)]
    public void Domain_dns_name_is_derived_from_the_naming_context_suffix(
        string distinguishedName,
        string? expected)
    {
        Assert.Equal(expected, ForeignPrincipalResolver.TryGetDnsDomainName(distinguishedName));
    }

    [Fact]
    public void Foreign_domain_context_is_cached_and_owned_by_source_context()
    {
        var source = new PrincipalContext(
            ContextType.Domain,
            "dc.source.example",
            "DC=source,DC=example",
            ContextOptions.SimpleBind,
            "bind-user",
            "password");

        var first = source.GetForeignDomainContext("target.example");
        var second = source.GetForeignDomainContext("TARGET.EXAMPLE");

        Assert.Same(first, second);
        Assert.Equal("target.example", first.Name);
        Assert.Equal("bind-user", first.UserName);
        Assert.Equal(ContextOptions.SimpleBind, first.Options);

        source.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = first.Name);
    }
}
