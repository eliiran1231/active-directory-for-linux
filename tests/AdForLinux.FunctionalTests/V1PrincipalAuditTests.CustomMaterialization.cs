using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [DirectoryObjectClass("customAccount")]
    [DirectoryRdnPrefix("CN")]
    public sealed class MaterializedCustomUser : UserPrincipal
    {
        public MaterializedCustomUser(PrincipalContext context) : base(context) => ConstructorContext = context;
        public PrincipalContext ConstructorContext { get; }
        public object?[] ReadAttribute(string name) => ExtensionGet(name);
        public void WriteAttribute(string name, object? value) => ExtensionSet(name, value);
    }

    [Fact]
    public void Custom_principal_materialization_attaches_the_entry_after_running_its_context_constructor()
    {
        using var fixture = new Fixture();
        fixture.Server["objectClass"] = ["top", "user", "customAccount"];
        fixture.Server["department"] = ["research", "engineering"];
        var custom = Assert.IsType<MaterializedCustomUser>(Principal.Materialize(fixture.Context, typeof(MaterializedCustomUser), fixture.Entry));
        using (custom)
        {
            Assert.Same(fixture.Context, custom.ConstructorContext);
            Assert.Same(fixture.Context, custom.Context);
            Assert.Same(fixture.Entry, custom.GetUnderlyingObject());
            Assert.Equal(new object?[] { "research", "engineering" }, custom.ReadAttribute("department"));
            Assert.Empty(custom.ReadAttribute("attributeNotReturned"));
            Assert.Single(fixture.Reads);
            Assert.Empty(fixture.Writes);
        }
        Assert.True(fixture.Entry.IsDisposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Materialized_custom_extension_replace_or_clear_survives_rejection_and_is_acknowledged_once(bool clear)
    {
        using var fixture = new Fixture();
        fixture.Server["department"] = ["before"];
        using var custom = Assert.IsType<MaterializedCustomUser>(Principal.Materialize(fixture.Context, typeof(MaterializedCustomUser), fixture.Entry));
        custom.WriteAttribute("department", clear ? null : new object[] { "research", "engineering" });
        fixture.Fail = true;
        Assert.Throws<InvalidOperationException>(custom.Save);
        Assert.Equal(new object[] { "before" }, fixture.Server["department"]);
        Assert.Empty(fixture.Writes);
        fixture.Fail = false;
        custom.Save();
        Assert.Equal(clear ? Array.Empty<object>() : new object[] { "research", "engineering" }, fixture.Server["department"]);
        Assert.Single(fixture.Writes);

        fixture.Server["department"] = ["external"];
        custom.DisplayName = "unrelated change";
        custom.Save();
        Assert.Equal(new object[] { "external" }, fixture.Server["department"]);
        Assert.DoesNotContain(fixture.Writes[1].Modifications.Cast<System.DirectoryServices.Protocols.DirectoryAttributeModification>(),
            change => change.Name == "department");
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("empty")]
    [InlineData("zero")]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("text")]
    public void Materialized_principal_does_not_invent_a_guid_from_missing_or_unusable_directory_values(string shape)
    {
        using var fixture = new Fixture();
        fixture.Server.Remove("objectGUID");
        if (shape != "absent") fixture.Server["objectGUID"] = shape switch
        {
            "empty" => [], "zero" => [new byte[16]], "short" => [new byte[15]],
            "long" => [new byte[17]], "text" => ["cdfb5919-d564-4d6b-9ea2-29ea41ff72e8"],
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };
        using var custom = Principal.Materialize(fixture.Context, typeof(MaterializedCustomUser), fixture.Entry)!;
        Assert.Null(custom.Guid);
        Assert.True(custom.IsPersisted);
        Assert.Equal("CN=item,DC=example,DC=test", custom.DistinguishedName);
        Assert.Same(fixture.Entry, custom.GetUnderlyingObject());
        Assert.Single(fixture.Reads);
        Assert.Empty(fixture.Writes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Materialized_principal_reports_no_sid_when_attribute_is_absent_or_not_binary(bool text)
    {
        using var fixture = new Fixture();
        fixture.Server.Remove("objectSid");
        if (text) fixture.Server["objectSid"] = ["S-1-5-21-1-2-3-1001"];
        using var user = Principal.Materialize(fixture.Context, typeof(UserPrincipal), fixture.Entry)!;
        Assert.Null(user.Sid);
        Assert.Null(user.SidValue);
        Assert.NotNull(user.Guid);
        Assert.Single(fixture.Reads);
        Assert.Empty(fixture.Writes);
    }

    [Theory]
    [InlineData("revision")]
    [InlineData("count")]
    [InlineData("truncated")]
    public void Materialized_principal_rejects_malformed_binary_sid_without_losing_its_entry(string corruption)
    {
        using var fixture = new Fixture();
        var bytes = SecurityDescriptorFixtures.U1.ToArray();
        if (corruption == "revision") bytes[0] = 2;
        else if (corruption == "count") bytes[1] = 16;
        else bytes = bytes[..^1];
        fixture.Server["objectSid"] = [bytes];
        using var user = Principal.Materialize(fixture.Context, typeof(UserPrincipal), fixture.Entry)!;
        Assert.Throws<ArgumentException>(() => _ = user.Sid);
        Assert.Throws<ArgumentException>(() => _ = user.SidValue);
        Assert.Same(fixture.Entry, user.GetUnderlyingObject());
        Assert.NotNull(user.Guid);
        Assert.False(fixture.Entry.IsDisposed);
        Assert.Empty(fixture.Writes);
    }
}
