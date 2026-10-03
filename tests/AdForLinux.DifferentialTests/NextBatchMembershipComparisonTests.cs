using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using static AdForLinux.DifferentialTests.NextBatchPrincipalStateComparisonTests;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityNextBatchLive")]
public sealed class NextBatchMembershipComparisonTests
{
    [Theory]
    [InlineData("contains")]
    [InlineData("add")]
    [InlineData("remove")]
    public void Unsaved_member_operations_do_not_require_a_directory_identity(string operation)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        using var expectedGroup = new Ms.GroupPrincipal(expectedContext);
        using var actualGroup = new Ours.GroupPrincipal(actualContext);
        using var expectedUser = new Ms.UserPrincipal(expectedContext) { SamAccountName = "unsaved-member" };
        using var actualUser = new Ours.UserPrincipal(actualContext) { SamAccountName = "unsaved-member" };
        bool? expectedResult = null, actualResult = null;
        var expectedError = Record.Exception(() =>
        {
            switch (operation)
            {
                case "contains": expectedResult = expectedGroup.Members.Contains(expectedUser); break;
                case "remove": expectedResult = expectedGroup.Members.Remove(expectedUser); break;
                case "add": expectedGroup.Members.Add(expectedUser); break;
            }
        });
        var actualError = Record.Exception(() =>
        {
            switch (operation)
            {
                case "contains": actualResult = actualGroup.Members.Contains(actualUser); break;
                case "remove": actualResult = actualGroup.Members.Remove(actualUser); break;
                case "add": actualGroup.Members.Add(actualUser); break;
            }
        });
        var comparison = new Comparison($"Unsaved member: {operation}")
            .Check("exception", Error(expectedError), Error(actualError))
            .Check("return value", expectedResult, actualResult)
            .Check("collection count", expectedGroup.Members.Count, actualGroup.Members.Count);
        // A successful insert must be observable and removable before either
        // object is saved. No Save occurs anywhere in this test.
        if (operation == "add" && expectedError is null && actualError is null)
        {
            comparison.Check("contains after add", expectedGroup.Members.Contains(expectedUser), actualGroup.Members.Contains(actualUser));
            comparison.Check("remove after add", expectedGroup.Members.Remove(expectedUser), actualGroup.Members.Remove(actualUser));
            comparison.Check("count after remove", expectedGroup.Members.Count, actualGroup.Members.Count);
        }
        comparison.Assert();
    }

    [Fact]
    public void Pending_membership_enumeration_retains_the_inserted_principal_instance()
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expectedUser, actualUser, _, _) =>
        {
            using var expectedGroup = new Ms.GroupPrincipal(expectedUser.Context);
            using var actualGroup = new Ours.GroupPrincipal(actualUser.Context);
            expectedGroup.Members.Add(expectedUser);
            actualGroup.Members.Add(actualUser);
            // The pending member itself can carry unsaved changes. Re-querying
            // its DN loses both object identity and those changes.
            expectedUser.DisplayName = actualUser.DisplayName = "pending-member-display";
            using var expectedCursor = expectedGroup.Members.GetEnumerator();
            using var actualCursor = actualGroup.Members.GetEnumerator();
            Assert.True(expectedCursor.MoveNext());
            Assert.True(actualCursor.MoveNext());
            var expectedMember = expectedCursor.Current;
            var actualMember = actualCursor.Current;
            try
            {
                Assert.Equal(expectedUser.Guid, expectedMember.Guid);
                Assert.Equal(actualUser.Guid, actualMember.Guid);
                Assert.Same(expectedUser, expectedMember);
                new Comparison("Pending member object retention")
                    .Check("same inserted instance", ReferenceEquals(expectedUser, expectedMember), ReferenceEquals(actualUser, actualMember))
                    .Check("staged member display name", expectedMember.DisplayName, actualMember.DisplayName).Assert();
            }
            finally
            {
                if (!ReferenceEquals(expectedUser, expectedMember)) expectedMember.Dispose();
                if (!ReferenceEquals(actualUser, actualMember)) actualMember.Dispose();
            }
        });
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void GetMembers_queries_persisted_membership_rather_than_pending_collection(bool recursive, bool stageMember)
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expectedUser, actualUser, _, _) =>
        {
            using var expectedGroup = new Ms.GroupPrincipal(expectedUser.Context);
            using var actualGroup = new Ours.GroupPrincipal(actualUser.Context);
            if (stageMember)
            {
                expectedGroup.Members.Add(expectedUser);
                actualGroup.Members.Add(actualUser);
            }
            Assert.Equal(stageMember ? 1 : 0, expectedGroup.Members.Count);
            Assert.Equal(expectedGroup.Members.Count, actualGroup.Members.Count);
            int? expectedCount = null, actualCount = null;
            var expectedError = Record.Exception(() =>
            {
                using var results = expectedGroup.GetMembers(recursive);
                var members = results.ToArray();
                try { expectedCount = members.Length; }
                finally { foreach (var member in members) if (!ReferenceEquals(member, expectedUser)) member.Dispose(); }
            });
            var actualError = Record.Exception(() =>
            {
                using var results = actualGroup.GetMembers(recursive);
                var members = results.ToArray();
                try { actualCount = members.Length; }
                finally { foreach (var member in members) if (!ReferenceEquals(member, actualUser)) member.Dispose(); }
            });
            Assert.Null(expectedError);
            Assert.Equal(0, expectedCount);
            new Comparison($"GetMembers recursive={recursive}, staged={stageMember}")
                .Check("exception", Error(expectedError), Error(actualError))
                .Check("query count", expectedCount, actualCount)
                .Check("pending collection unchanged", expectedGroup.Members.Count, actualGroup.Members.Count).Assert();
        });
    }
}
