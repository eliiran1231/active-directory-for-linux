using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using static AdForLinux.DifferentialTests.NextBatchPrincipalStateComparisonTests;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityMembershipLifecycleLive")]
public sealed class MembershipLifecycleComparisonTests
{
    [Theory]
    [InlineData("contains")]
    [InlineData("remove")]
    [InlineData("add")]
    public void Pending_member_matches_reloaded_wrapper_after_member_save(string operation)
    {
        Ms.GroupPrincipal? expectedGroup = null;
        Ours.GroupPrincipal? actualGroup = null;
        try
        {
            CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, _, _) =>
            {
                using var expectedReloaded = Ms.UserPrincipal.FindByIdentity(
                    expected.Context, Ms.IdentityType.DistinguishedName, expected.DistinguishedName!);
                using var actualReloaded = Ours.UserPrincipal.FindByIdentity(
                    actual.Context, Ours.IdentityType.DistinguishedName, actual.DistinguishedName!);
                Assert.NotNull(expectedReloaded);
                Assert.NotNull(actualReloaded);
                Assert.NotSame(expected, expectedReloaded);
                Assert.NotSame(actual, actualReloaded);
                Assert.True(expected.Equals(expectedReloaded));
                Assert.True(actual.Equals(actualReloaded));
                bool? expectedResult = null, actualResult = null;
                var expectedError = Record.Exception(() =>
                {
                    switch (operation)
                    {
                        case "contains": expectedResult = expectedGroup!.Members.Contains(expectedReloaded); break;
                        case "remove": expectedResult = expectedGroup!.Members.Remove(expectedReloaded); break;
                        case "add": expectedGroup!.Members.Add(expectedReloaded); break;
                    }
                });
                var actualError = Record.Exception(() =>
                {
                    switch (operation)
                    {
                        case "contains": actualResult = actualGroup!.Members.Contains(actualReloaded); break;
                        case "remove": actualResult = actualGroup!.Members.Remove(actualReloaded); break;
                        case "add": actualGroup!.Members.Add(actualReloaded); break;
                    }
                });
                if (operation == "add") Assert.IsType<Ms.PrincipalExistsException>(expectedError);
                else
                {
                    Assert.Null(expectedError);
                    Assert.True(expectedResult);
                }
                new Comparison($"Pending member acquires identity: {operation}")
                    .Check("exception", Error(expectedError), Error(actualError))
                    .Check("result", expectedResult, actualResult)
                    .Check("count", expectedGroup!.Members.Count, actualGroup!.Members.Count)
                    .Check("original member still present", expectedGroup.Members.Contains(expected), actualGroup.Members.Contains(actual))
                    .Assert();
            }, beforeSave: (expected, actual) =>
            {
                // Stage real unsaved objects, then let the owned fixture Save
                // them normally. Neither group is ever saved to the directory.
                expectedGroup = new Ms.GroupPrincipal(expected.Context);
                actualGroup = new Ours.GroupPrincipal(actual.Context);
                Assert.Null(expected.DistinguishedName);
                Assert.Null(actual.DistinguishedName);
                expectedGroup.Members.Add(expected);
                actualGroup.Members.Add(actual);
            });
        }
        finally
        {
            expectedGroup?.Dispose();
            actualGroup?.Dispose();
        }
    }

    [Fact]
    public void Identity_added_member_remains_usable_after_group_disposal()
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, _, _) =>
        {
            using var expectedGroup = new Ms.GroupPrincipal(expected.Context);
            using var actualGroup = new Ours.GroupPrincipal(actual.Context);
            expectedGroup.Members.Add(expected.Context, Ms.IdentityType.DistinguishedName, expected.DistinguishedName!);
            actualGroup.Members.Add(actual.Context, Ours.IdentityType.DistinguishedName, actual.DistinguishedName!);
            using var expectedMember = Assert.Single(expectedGroup.Members);
            using var actualMember = Assert.Single(actualGroup.Members);
            Assert.Equal(expected.Guid, expectedMember.Guid);
            Assert.Equal(actual.Guid, actualMember.Guid);
            expectedGroup.Dispose();
            actualGroup.Dispose();
            bool? expectedMatches = null, actualMatches = null;
            var expectedError = Record.Exception(() => expectedMatches = expectedMember.SamAccountName == expected.SamAccountName);
            var actualError = Record.Exception(() => actualMatches = actualMember.SamAccountName == actual.SamAccountName);
            Assert.Null(expectedError);
            Assert.True(expectedMatches);
            new Comparison("Retained identity-added member after group disposal")
                .Check("exception", Error(expectedError), Error(actualError))
                .Check("member still readable", expectedMatches, actualMatches).Assert();
        });
    }
}
