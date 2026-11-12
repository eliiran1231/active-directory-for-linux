// Framework security enums are portable values; executable security APIs below are our managed types.
#pragma warning disable CA1416
using System.Text.Json;
using E = System.Security.AccessControl;
using B = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [MemberData(nameof(FoundationRecordings))]
    public void Recorded_foundation_contract(int caseId, string operation, string json)
    {
        using var document=JsonDocument.Parse(json);var row=document.RootElement;
        Assert.Equal(caseId, row.GetProperty("Case").GetInt32());
        object? outcome=null;
        var exception=Record.Exception(()=>outcome=ReplayFoundation(operation,row.GetProperty("Arguments")));
        Assert.Equal(row.GetProperty("ExceptionType").GetString(),exception?.GetType().FullName);
        Assert.Equal(row.GetProperty("ParamName").GetString(),(exception as ArgumentException)?.ParamName);
        if(exception is null) Assert.Equal(JsonSerializer.Serialize(row.GetProperty("Outcome")),JsonSerializer.Serialize(outcome));
    }

    [Fact]
    public void Recorded_foundation_cross_runtime_differences_are_exactly_the_eight_null_domain_comparisons()
    {
        using var firstStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Foundation.net8.json")
            ?? throw new InvalidOperationException("Missing net8 foundation recording.");
        using var secondStream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Foundation.net10.json")
            ?? throw new InvalidOperationException("Missing net10 foundation recording.");
        using var first=JsonDocument.Parse(firstStream);using var second=JsonDocument.Parse(secondStream);
        var firstRows=first.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        var secondRows=second.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        Assert.Equal(firstRows.Length,secondRows.Length);
        var differences=0;
        for(var i=0;i<firstRows.Length;i++)
        {
            var a=firstRows[i];var b=secondRows[i];
            if(JsonSerializer.Serialize(a)==JsonSerializer.Serialize(b)) continue;
            differences++;
            Assert.Equal("SidCompare",a.GetProperty("Operation").GetString());
            Assert.Equal("SidCompare",b.GetProperty("Operation").GetString());
            Assert.Equal(JsonSerializer.Serialize(a.GetProperty("Arguments")),JsonSerializer.Serialize(b.GetProperty("Arguments")));
            Assert.Equal(JsonValueKind.Null,a.GetProperty("Arguments").GetProperty("Second").ValueKind);
            Assert.Equal("System.ArgumentNullException",a.GetProperty("ExceptionType").GetString());
            Assert.Equal("sid",a.GetProperty("ParamName").GetString());
            Assert.Equal(JsonValueKind.Null,a.GetProperty("Outcome").ValueKind);
            Assert.Equal(JsonValueKind.Null,b.GetProperty("ExceptionType").ValueKind);
            Assert.Equal(JsonValueKind.Null,b.GetProperty("ParamName").ValueKind);
            Assert.Equal(1,b.GetProperty("Outcome").GetProperty("Compare").GetInt32());
            Assert.False(b.GetProperty("Outcome").GetProperty("Equal").GetBoolean());
            Assert.False(b.GetProperty("Outcome").GetProperty("DomainEqual").GetBoolean());
        }
        Assert.Equal(8,differences);
    }

    public static IEnumerable<object[]> FoundationRecordings()
    {
#if NET10_0_OR_GREATER
        const string resource="AclOracle.Foundation.net10.json";
#else
        const string resource="AclOracle.Foundation.net8.json";
#endif
        using var stream=typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException("Missing embedded recorded Windows foundation contracts.");
        using var document=JsonDocument.Parse(stream);
        foreach(var row in document.RootElement.GetProperty("Observations").EnumerateArray())
            yield return new object[] {row.GetProperty("Case").GetInt32(),row.GetProperty("Operation").GetString()!,row.GetRawText()};
    }

    private static object? ReplayFoundation(string operation,JsonElement a)
    {
        string? S(string key)=>a.GetProperty(key).GetString();
        int I(string key)=>a.GetProperty(key).GetInt32();
        switch(operation)
        {
            case "SidString": return ReplaySid(new B.SecurityIdentifier(S("Text")!));
            case "SidDomainIdentity":
                var domainSource = new B.SecurityIdentifier(S("Text")!);
                if (a.GetProperty("Warm").GetBoolean()) _ = domainSource.IsAccountSid();
                var firstDomain = domainSource.AccountDomainSid;
                var secondDomain = domainSource.AccountDomainSid;
                return new { Value=firstDomain?.Value, SameReference=ReferenceEquals(firstDomain,secondDomain),
                    SameAsInput=ReferenceEquals(domainSource,firstDomain), IsAccountSid=domainSource.IsAccountSid() };
            case "SidBinary": return ReplaySid(new B.SecurityIdentifier(S("Hex") is { } hex?Convert.FromHexString(hex):null!,I("Offset")));
            case "SidCompare":
                var sidA=new B.SecurityIdentifier(S("First")!);var sidB=S("Second") is { } second?new B.SecurityIdentifier(second):null;
                return new {Compare=Math.Sign(sidA.CompareTo(sidB)),Equal=sidA.Equals(sidB),DomainEqual=sidA.IsEqualDomainSid(sidB!)};
            case "SidWrite":
                var sid=new B.SecurityIdentifier("S-1-5-21-1-2-3-1001");var length=I("Length");byte[]? buffer=length<0?null:new byte[length];
                sid.GetBinaryForm(buffer!,I("Offset"));return Convert.ToHexString(buffer!);
            case "AccountString": return new B.NTAccount(S("Text")!).Value;
            case "AccountParts": return new B.NTAccount(S("Domain")!,S("Name")!).Value;
            case "AccountEquals": return new B.NTAccount(S("First")!).Equals(S("Second") is { } account?new B.NTAccount(account):null);
            case "IdentityTarget":
                var kind=S("IdentityKind");B.IdentityReference identity=kind=="sid"?new B.SecurityIdentifier("S-1-1-0"):new B.NTAccount("DOMAIN","user");
                Type? type=S("Target") switch {"sid"=>typeof(B.SecurityIdentifier),"account"=>typeof(B.NTAccount),"string"=>typeof(string),"identity"=>typeof(B.IdentityReference),_=>null};
                var valid=identity.IsValidTargetType(type!);var translated=S("Target")==kind?identity.Translate(type!).Value:null;
                return new {Valid=valid,Translated=translated};
            case "Rule":
                B.IdentityReference? ruleIdentity=S("Identity") switch {"sid"=>new B.SecurityIdentifier("S-1-5-21-1-2-3-1001"),"account"=>new B.NTAccount("DOMAIN","user"),_=>null};
                var m=I("Mask");var inherited=a.GetProperty("Inherited").GetBoolean();var f=(E.InheritanceFlags)I("Inheritance");var p=(E.PropagationFlags)I("Propagation");var q=I("Qualifier");
                var ot=a.GetProperty("ObjectType").GetGuid();var it=a.GetProperty("InheritedObjectType").GetGuid();
                A.AuthorizationRule rule=S("Kind") switch {
                    "Authorization"=>new FoundationAuthorization(ruleIdentity!,m,inherited,f,p),
                    "Access"=>new FoundationAccess(ruleIdentity!,m,inherited,f,p,(E.AccessControlType)q),
                    "Audit"=>new FoundationAudit(ruleIdentity!,m,inherited,f,p,(E.AuditFlags)q),
                    "ObjectAccess"=>new FoundationObjectAccess(ruleIdentity!,m,inherited,f,p,ot,it,(E.AccessControlType)q),
                    _=>new FoundationObjectAudit(ruleIdentity!,m,inherited,f,p,ot,it,(E.AuditFlags)q),
                };
                return ReplayRuleSnapshot(rule);
            case "RuleCollectionCopy":
                var collection=new A.AuthorizationRuleCollection();
                collection.AddRule(a.GetProperty("Audit").GetBoolean()
                    ?new FoundationObjectAudit(new B.SecurityIdentifier("S-1-5-21-1-2-3-1001"),16,false,0,0,Guid.Empty,Guid.Empty,E.AuditFlags.Success)
                    :new FoundationObjectAccess(new B.SecurityIdentifier("S-1-5-21-1-2-3-1001"),16,false,0,0,Guid.Empty,Guid.Empty,E.AccessControlType.Allow));
                var destination=new A.AuthorizationRule[I("Length")];collection.CopyTo(destination,I("Offset"));
                return new {collection.Count,IsSynchronized=((System.Collections.ICollection)collection).IsSynchronized,Values=destination.Select(r=>r is null?null:ReplayRuleSnapshot(r)).ToArray()};
            default: return ReplayAceFoundation(operation,a);
        }
    }

    private static object ReplaySid(B.SecurityIdentifier sid)
    {
        var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
        return new {sid.Value,sid.BinaryLength,Hex=Convert.ToHexString(bytes),AccountDomainSid=sid.AccountDomainSid?.Value,IsAccountSid=sid.IsAccountSid()};
    }
    private static object ReplayRuleSnapshot(A.AuthorizationRule rule)=>new {Identity=rule.IdentityReference.Value,IdentityKind=rule.IdentityReference.GetType().Name,Mask=((IFoundationRuleMask)rule).Mask,rule.IsInherited,Inheritance=(int)rule.InheritanceFlags,Propagation=(int)rule.PropagationFlags,
        Qualifier=rule is A.AccessRule access?(int)access.AccessControlType:rule is A.AuditRule audit?(int)audit.AuditFlags:(int?)null,
        ObjectFlags=rule is A.ObjectAccessRule oa?(int)oa.ObjectFlags:rule is A.ObjectAuditRule ou?(int)ou.ObjectFlags:(int?)null,
        ObjectType=rule is A.ObjectAccessRule ob?ob.ObjectType:rule is A.ObjectAuditRule ov?ov.ObjectType:(Guid?)null,
        InheritedObjectType=rule is A.ObjectAccessRule oc?oc.InheritedObjectType:rule is A.ObjectAuditRule ow?ow.InheritedObjectType:(Guid?)null};
}
