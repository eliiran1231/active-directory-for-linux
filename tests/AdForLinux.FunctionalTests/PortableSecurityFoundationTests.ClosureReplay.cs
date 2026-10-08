// Shared framework enums are values; replay executes portable managed security classes.
#pragma warning disable CA1416
using System.Text.Json;
using System.Text.Json.Nodes;
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
        if(exception is null) AssertClosureOutcome(row,outcome);
    }

    [Fact]
    public void Recorded_closure_runtime_differences_are_limited_to_null_mapping_exception_messages()
    {
        using var firstStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Closure.net8.json")
            ?? throw new InvalidOperationException("Missing net8 closure recording.");
        using var secondStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Closure.net10.json")
            ?? throw new InvalidOperationException("Missing net10 closure recording.");
        using var first=JsonDocument.Parse(firstStream);using var second=JsonDocument.Parse(secondStream);
        var firstRows=first.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        var secondRows=second.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        Assert.Equal(2224,firstRows.Length); // Advance only when original native artifacts are imported.
        Assert.Equal(firstRows.Length,secondRows.Length);
        for(var i=0;i<firstRows.Length;i++)
        {
            var a=firstRows[i];var b=secondRows[i];
            var caseId=a.GetProperty("Case").GetInt32();
            Assert.Equal(caseId,b.GetProperty("Case").GetInt32());
            if(caseId is 2314 or 2317)
            {
                Assert.Equal("IdentityMappingException",a.GetProperty("Operation").GetString());
                Assert.Equal(caseId==2314?1:4,a.GetProperty("Arguments").GetProperty("Scenario").GetInt32());
                Assert.Equal(NativeGenericMappingMessage,a.GetProperty("Outcome").GetProperty("Message").GetString());
                Assert.Equal(TranslationMappingMessage,b.GetProperty("Outcome").GetProperty("Message").GetString());
                var left=JsonNode.Parse(a.GetRawText())!;var right=JsonNode.Parse(b.GetRawText())!;
                left["Outcome"]!.AsObject().Remove("Message");right["Outcome"]!.AsObject().Remove("Message");
                Assert.Equal(left.ToJsonString(),right.ToJsonString());
            }
            else Assert.Equal(JsonSerializer.Serialize(a),JsonSerializer.Serialize(b));
        }
    }

    private const string NativeGenericMappingMessage = "Exception of type 'System.Security.Principal.IdentityNotMappedException' was thrown.";
    private const string TranslationMappingMessage = "Some or all identity references could not be translated.";

    private static void AssertClosureOutcome(JsonElement row,object? outcome)
    {
        var actual=JsonSerializer.SerializeToElement(outcome);
        var expected=row.GetProperty("Outcome");
        var caseId=row.GetProperty("Case").GetInt32();
        if(caseId is 2314 or 2317)
        {
            Assert.Equal("IdentityMappingException",row.GetProperty("Operation").GetString());
            Assert.Equal(caseId==2314?1:4,row.GetProperty("Arguments").GetProperty("Scenario").GetInt32());
#if NET10_0_OR_GREATER
            Assert.Equal(TranslationMappingMessage,expected.GetProperty("Message").GetString());
            Assert.Equal(TranslationMappingMessage,actual.GetProperty("Message").GetString());
#else
            Assert.Equal(NativeGenericMappingMessage,expected.GetProperty("Message").GetString());
            Assert.Equal("Exception of type 'AdForLinux.Security.Principal.IdentityNotMappedException' was thrown.",actual.GetProperty("Message").GetString());
#endif
            // Only the approved portable namespace differs in the CLR-generated net8
            // message. Assert each message before comparing every other outcome field.
            var left=JsonNode.Parse(expected.GetRawText())!.AsObject();
            var right=JsonNode.Parse(actual.GetRawText())!.AsObject();
            left.Remove("Message");right.Remove("Message");
            Assert.Equal(left.ToJsonString(),right.ToJsonString());
        }
        else Assert.Equal(JsonSerializer.Serialize(expected),JsonSerializer.Serialize(actual));
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
        if(operation.StartsWith("Identity",StringComparison.Ordinal)) return PortableIdentityCollectionContracts.Execute(operation,arguments.GetProperty("Scenario").GetInt32());
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
