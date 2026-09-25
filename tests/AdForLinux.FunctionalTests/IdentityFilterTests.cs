using System.ComponentModel;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class IdentityFilterTests
{
    [Theory]
    [InlineData(IdentityType.SamAccountName, "sAMAccountName")]
    [InlineData(IdentityType.Name, "cn")]
    [InlineData(IdentityType.UserPrincipalName, "userPrincipalName")]
    [InlineData(IdentityType.DistinguishedName, "distinguishedName")]
    public void Text_identity_is_a_literal_assertion(IdentityType type, string attribute)
    {
        // Include an injection-shaped value, a literal escape, NUL, and Unicode.
        const string value = "Jörg\\2a*)(objectClass=*)\0";

        Assert.Equal(
            $"({attribute}=Jörg\\5c2a\\2a\\29\\28objectClass=\\2a\\29\\00)",
            IdentityFilter.Build(type, value));
    }

    [Theory]
    [InlineData(IdentityType.Guid, "00112233-4455-6677-8899-aabbccddeeff",
        "(objectGUID=\\33\\22\\11\\00\\55\\44\\77\\66\\88\\99\\aa\\bb\\cc\\dd\\ee\\ff)")]
    [InlineData(IdentityType.Sid, "S-1-5-21-16909060-4294967295",
        "(objectSid=\\01\\03\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\04\\03\\02\\01\\ff\\ff\\ff\\ff)")]
    public void Binary_identity_uses_directory_byte_order_and_lookup_priority(
        IdentityType type, string value, string expectedAssertion)
    {
        Assert.Equal(expectedAssertion, IdentityFilter.Build(type, value));
        Assert.Equal(new[]
        {
            $"(sAMAccountName={value})",
            $"(userPrincipalName={value})",
            $"(distinguishedName={value})",
            expectedAssertion,
            $"(name={value})",
        }, IdentityFilter.BuildValueOnlyCandidates(value));
    }

    [Fact]
    public void Domain_qualified_lookup_strips_domain_only_for_sam_account_name()
    {
        Assert.Equal(new[]
        {
            "(sAMAccountName=alice\\2a)",
            "(userPrincipalName=DOMAIN\\5calice\\2a)",
            "(distinguishedName=DOMAIN\\5calice\\2a)",
            "(name=DOMAIN\\5calice\\2a)",
        }, IdentityFilter.BuildValueOnlyCandidates(@"DOMAIN\alice*"));
    }

    [Fact]
    public void Domain_without_account_does_not_search_for_an_empty_sam_account_name()
    {
        Assert.Equal(new[]
        {
            "(userPrincipalName=DOMAIN\\5c)",
            "(distinguishedName=DOMAIN\\5c)",
            "(name=DOMAIN\\5c)",
        }, IdentityFilter.BuildValueOnlyCandidates(@"DOMAIN\"));
    }

    [Theory]
    [InlineData(IdentityType.Guid, "00112233-4455-6677-8899-aabbccddeefg")]
    [InlineData(IdentityType.Sid, "S-1-5-4294967296")]
    [InlineData(IdentityType.Sid, "S-2-5-21")]
    [InlineData(IdentityType.Sid, "S-1-281474976710656-21")]
    public void Malformed_binary_identity_is_rejected_explicitly_but_remains_a_name_candidate(
        IdentityType type, string value)
    {
        Assert.Throws<ArgumentException>(() => IdentityFilter.Build(type, value));
        Assert.Equal(new[]
        {
            $"(sAMAccountName={value})",
            $"(userPrincipalName={value})",
            $"(distinguishedName={value})",
            $"(name={value})",
        }, IdentityFilter.BuildValueOnlyCandidates(value));
    }

    [Fact]
    public void Explicit_identity_requires_a_supported_identity_type()
    {
        Assert.Equal("identityType",
            Assert.Throws<ArgumentNullException>(() => IdentityFilter.Build(null, "alice")).ParamName);
        Assert.Equal("identityType",
            Assert.Throws<InvalidEnumArgumentException>(
                () => IdentityFilter.Build((IdentityType)int.MaxValue, "alice")).ParamName);
    }
}
