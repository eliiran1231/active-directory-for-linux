// Shared framework enums are values; replay executes portable managed security classes.
#pragma warning disable CA1416
using System.Text.Json;
using P = AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [MemberData(nameof(ClosureRecordings))]
    public void Recorded_detached_closure_contract(int caseId,string operation,string json)
    {
        using var document=JsonDocument.Parse(json);var row=document.RootElement;
        Assert.Equal(caseId,row.GetProperty("Case").GetInt32());
        object? outcome=null;
        var exception=Record.Exception(()=>outcome=ReplayClosure(operation,row.GetProperty("Arguments")));
        if(operation.StartsWith("Sddl",StringComparison.Ordinal) && AssertSddlDeferred(row,exception)) return;
        Assert.Equal(row.GetProperty("ExceptionType").GetString(),exception?.GetType().FullName);
        Assert.Equal(row.GetProperty("ParamName").GetString(),(exception as ArgumentException)?.ParamName);
        if(exception is null) Assert.Equal(JsonSerializer.Serialize(row.GetProperty("Outcome")),JsonSerializer.Serialize(outcome));
    }

    [Fact]
    public void Recorded_closure_observations_are_identical_across_runtimes()
    {
        using var firstStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Closure.net8.json")
            ?? throw new InvalidOperationException("Missing net8 closure recording.");
        using var secondStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Closure.net10.json")
            ?? throw new InvalidOperationException("Missing net10 closure recording.");
        using var first=JsonDocument.Parse(firstStream);using var second=JsonDocument.Parse(secondStream);
        Assert.Equal(2224,first.RootElement.GetProperty("Observations").GetArrayLength());
        Assert.Equal(JsonSerializer.Serialize(first.RootElement.GetProperty("Observations")),JsonSerializer.Serialize(second.RootElement.GetProperty("Observations")));
    }

    public static IEnumerable<object[]> ClosureRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource="AclOracle.Closure.net10.json";
#else
        const string resource="AclOracle.Closure.net8.json";
#endif
        using var stream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException("Missing embedded recorded Windows closure contracts.");
        using var document=JsonDocument.Parse(stream);
        foreach(var row in document.RootElement.GetProperty("Observations").EnumerateArray())
            yield return new object[] {row.GetProperty("Case").GetInt32(),row.GetProperty("Operation").GetString()!,row.GetRawText()};
    }

    private static object? ReplayClosure(string operation,JsonElement arguments)
    {
        if(operation.StartsWith("Acl",StringComparison.Ordinal)) return ReplayAclClosure(operation,arguments);
        if(operation.StartsWith("Descriptor",StringComparison.Ordinal)) return ReplayDescriptorClosure(operation,arguments);
        if(operation.StartsWith("Sddl",StringComparison.Ordinal)) return ReplaySddlClosure(operation,arguments);
        if(operation=="SidClosureAlias")
        {
            var sid=new P.SecurityIdentifier(arguments.GetProperty("Text").GetString()!);
            var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
            return new {sid.Value,Hex=Convert.ToHexString(bytes)};
        }
        var type=(System.Security.Principal.WellKnownSidType)arguments.GetProperty("Type").GetInt32();
        if(operation=="SidClosureIsWellKnownBinary") return new P.SecurityIdentifier(Convert.FromHexString(arguments.GetProperty("Hex").GetString()!),0).IsWellKnown(type);
        if(operation=="SidClosureIsWellKnown") return new P.SecurityIdentifier(arguments.GetProperty("Value").GetString()!).IsWellKnown(type);
        if(operation=="SidClosureConstruct")
        {
            var domain=arguments.GetProperty("Domain").GetString();
            var sid=new P.SecurityIdentifier(type,domain is null?null:new P.SecurityIdentifier(domain));
            var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
            return new {sid.Value,Hex=Convert.ToHexString(bytes),IsWellKnown=sid.IsWellKnown(type)};
        }
        throw new InvalidOperationException("Unrecognized recorded closure operation: "+operation);
    }
}
