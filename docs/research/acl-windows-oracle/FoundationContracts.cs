// Pure detached Windows contracts: no Translate, DirectoryEntry, LDAP, Persist or privileges.
using System.Runtime.InteropServices;
using System.Text.Json;
using E = System.Security.AccessControl;
using B = System.Security.Principal;
using M = System.DirectoryServices;

internal static class FoundationContracts
{
    internal static void Write(string path)
    {
        var rows = new List<object>();
        void Record(string operation, object arguments, Func<object?> body)
        {
            object? outcome = null; string? exception = null, param = null;
            try { outcome = body(); }
            catch (Exception ex) { exception = ex.GetType().FullName; param = (ex as ArgumentException)?.ParamName; }
            rows.Add(new { Case = rows.Count, Operation = operation, Arguments = arguments, Outcome = outcome, ExceptionType = exception, ParamName = param });
        }
        foreach (var text in new string?[] { null, "", "S-1-1-0", "s-1-5-32-544", "S-1-0x112233445566-7", "S-1-5", "S-1-5-0", "S-1-5-4294967295", "S-1-5-4294967296", "S-2-5-1", "S-1-281474976710655-1", " S-1-1-0", "S-1-1-0 ", "S-1-5--1", "S-1-5-+1", "BA", "WD", "garbage", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3", "S-1-5-" + string.Join("-", Enumerable.Range(1,15)), "S-1-5-" + string.Join("-", Enumerable.Range(1,16)) })
            Record("SidString", new { Text = text }, () => Sid(new B.SecurityIdentifier(text!)));
        var valid = Sd.U1;
        foreach (var bytes in new byte[]?[] { null, Array.Empty<byte>(), new byte[7], valid, new byte[3].Concat(valid).ToArray(), valid[..^1], new byte[] { 2 }.Concat(valid.Skip(1)).ToArray() })
        foreach (var offset in new[] { int.MinValue, -1, 0, 1, 3, 100, int.MaxValue })
            Record("SidBinary", new { Hex = bytes is null ? null : Convert.ToHexString(bytes), Offset = offset }, () => Sid(new B.SecurityIdentifier(bytes!, offset)));
        foreach (var first in new[] { "S-1-1-0", "S-1-5-32-544", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-4-1001", "S-1-5-2147483647", "S-1-5-4294967295", "S-1-5-2147483648" })
        foreach (var second in new string?[] { null, "S-1-1-0", "S-1-5-32-544", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-4294967295", "S-1-5-2147483648" })
            Record("SidCompare", new { First = first, Second = second }, () => {
                var a = new B.SecurityIdentifier(first); var b = second is null ? null : new B.SecurityIdentifier(second);
                return new { Compare = Math.Sign(a.CompareTo(b)), Equal = a.Equals(b!), DomainEqual = a.IsEqualDomainSid(b!) };
            });
        foreach (var text in new string?[] { null, "", "user", "DOMAIN\\user", "domain\\USER", " user ", new string('a', 257) })
            Record("AccountString", new { Text = text }, () => new B.NTAccount(text!).Value);
        foreach (var domain in new string?[] { null, "", "DOMAIN", new string('d',256) })
        foreach (var name in new string?[] { null, "", "user", new string('u',257) })
            Record("AccountParts", new { Domain = domain, Name = name }, () => new B.NTAccount(domain!, name!).Value);
        foreach (var first in new[] { "DOMAIN\\user", "user", " user " })
        foreach (var second in new string?[] { null, "domain\\USER", "USER", " user " })
            Record("AccountEquals", new { First = first, Second = second }, () => new B.NTAccount(first).Equals(second is null ? null : new B.NTAccount(second)));

        foreach (var sidText in new[] { "S-1-5", "S-1-4294967295-0", "S-1-4294967296-0", "S-1-281474976710655-4294967295" })
            Record("SidString", new { Text=sidText }, () => Sid(new B.SecurityIdentifier(sidText)));
        foreach (var offset in new[] { int.MinValue,-1,0,1,28,int.MaxValue })
        foreach (var length in new[] { -1,0,27,28,29 })
            Record("SidWrite", new { Offset=offset,Length=length }, () => {
                var sid=new B.SecurityIdentifier("S-1-5-21-1-2-3-1001");
                byte[]? bytes=length<0?null:new byte[length]; sid.GetBinaryForm(bytes!,offset); return Convert.ToHexString(bytes!);
            });
        foreach (var identityKind in new[] { "sid", "account" })
        foreach (var target in new[] { "null", "sid", "account", "string", "identity" })
            Record("IdentityTarget", new { IdentityKind=identityKind,Target=target }, () => {
                B.IdentityReference identity=identityKind=="sid"?new B.SecurityIdentifier("S-1-1-0"):new B.NTAccount("DOMAIN","user");
                Type? type=target switch { "sid"=>typeof(B.SecurityIdentifier),"account"=>typeof(B.NTAccount),"string"=>typeof(string),"identity"=>typeof(B.IdentityReference),_=>null };
                // Never translate SID/account across kinds: that could resolve against the OS.
                var valid=identity.IsValidTargetType(type!);
                var translated=target==identityKind?identity.Translate(type!).Value:null;
                return new { Valid=valid,Translated=translated };
            });

        // Directed independent invalid values and combinations expose validation precedence.
        var args = new List<(string? Identity,int Mask,bool Inherited,int Inheritance,int Propagation,int Qualifier,Guid Ot,Guid It)>();
        foreach (var kind in new[] { "Authorization", "Access", "Audit", "ObjectAccess", "ObjectAudit" })
        {
            args.Clear();
            foreach (var identity in new string?[] { null, "sid", "account" })
            foreach (var mask in new[] { 0, 0x10, -1 })
            foreach (var inheritance in new[] { 0, 1, 2, 3, 4, -1 })
            foreach (var propagation in new[] { 0, 1, 2, 3, 4, -1 })
                args.Add((identity,mask,false,inheritance,propagation,0,Guid.Empty,Guid.Empty));
            foreach (var qualifier in new[] { -1, 0, 1, 2, 3, 4 })
            foreach (var mask in new[] { 0, 0x10 })
                args.Add(("sid",mask,true,1,2,qualifier,Sd.G1,Sd.G2));
            foreach (var mask in new[] { 4, 8, 0x10, 0x14, 0x20, 0x100, -1 })
            foreach (var inheritance in new[] { 0, 1, 2, 3 })
            foreach (var ot in new[] { Guid.Empty, Sd.G1 })
            foreach (var it in new[] { Guid.Empty, Sd.G2 })
                args.Add(("sid",mask,true,inheritance,2,1,ot,it));
            foreach (var a in args)
            {
                Record("Rule", new { Kind=kind,a.Identity,a.Mask,a.Inherited,a.Inheritance,a.Propagation,a.Qualifier,ObjectType=a.Ot,InheritedObjectType=a.It }, () => {
                    B.IdentityReference? identity = a.Identity switch { "sid" => new B.SecurityIdentifier("S-1-5-21-1-2-3-1001"), "account" => new B.NTAccount("DOMAIN", "user"), _ => null };
                    return kind switch {
                        "Authorization" => new AuthorizationProbe(identity!,a.Mask,a.Inherited,(E.InheritanceFlags)a.Inheritance,(E.PropagationFlags)a.Propagation).Snapshot(),
                        "Access" => new AccessProbe(identity!,a.Mask,a.Inherited,(E.InheritanceFlags)a.Inheritance,(E.PropagationFlags)a.Propagation,(E.AccessControlType)a.Qualifier).Snapshot(),
                        "Audit" => new AuditProbe(identity!,a.Mask,a.Inherited,(E.InheritanceFlags)a.Inheritance,(E.PropagationFlags)a.Propagation,(E.AuditFlags)a.Qualifier).Snapshot(),
                        "ObjectAccess" => new ObjectAccessProbe(identity!,a.Mask,a.Inherited,(E.InheritanceFlags)a.Inheritance,(E.PropagationFlags)a.Propagation,(E.AccessControlType)a.Qualifier,a.Ot,a.It).Snapshot(),
                        _ => new ObjectAuditProbe(identity!,a.Mask,a.Inherited,(E.InheritanceFlags)a.Inheritance,(E.PropagationFlags)a.Propagation,(E.AuditFlags)a.Qualifier,a.Ot,a.It).Snapshot(),
                    };
                });
            }
        }
        foreach (var audit in new[] { false, true })
        foreach (var offset in new[] { -1, 0, 1, 2 })
        foreach (var length in new[] { 0, 1, 2, 3 })
            Record("RuleCollectionCopy", new { Audit=audit,Offset=offset,Length=length }, () => {
                var sd = new M.ActiveDirectorySecurity();
                sd.SetSecurityDescriptorBinaryForm(Sd.Build(Sd.Admins,Sd.Admins,Sd.Acl(4,Sd.Ace(0,0,16,Sd.U1)),sacl:Sd.Acl(4,Sd.Ace(2,0x40,16,Sd.U1))));
                var collection = audit ? sd.GetAuditRules(true,true,typeof(B.SecurityIdentifier)) : sd.GetAccessRules(true,true,typeof(B.SecurityIdentifier));
                var destination = new E.AuthorizationRule[length]; collection.CopyTo(destination,offset);
                return new { collection.Count,IsSynchronized=((System.Collections.ICollection)collection).IsSynchronized, Values=destination.Select(r => r is null ? null : Snapshot(r,16)).ToArray() };
            });
        AceFoundationContracts.Record(Record);
        // Domain-prefix and numeric parser boundaries, still entirely detached.
        foreach (var text in new[] {
            "S-1-5-21", "S-1-5-21-1", "S-1-5-21-1-2", "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-4", "S-1-5-21-1-2-3-4-5",
            "S-1-5-32", "S-1-5-32-544", "S-1-5-32-544-1", "S-1-4-21-1-2-3-4", "S-1-5-80-1", "S-1-5-18", "S-1-5", "S-1-0",
            "S-1-5-", "S-1--5-1", "S-1-5-1--2", "S-0-5-1", "S-256-5-1", "S-4294967296-5-1", "S-01-005-0001",
            "S-1-5-0x10", "S-0x1-0x5-0x10", "S-1-5-18446744073709551615", "S-1-5-18446744073709551616",
            "S-1-281474976710656-1", "S-1-18446744073709551615-1", "S-1-18446744073709551616-1", "S-1-0x1000000000000-1" })
            Record("SidString", new {Text=text},()=>Sid(new B.SecurityIdentifier(text)));
        Record("SidBinary",new {Hex="0100000000000005",Offset=0},()=>Sid(new B.SecurityIdentifier(Convert.FromHexString("0100000000000005"),0)));
        var domainCases=new[] {"S-1-5-21-1-2","S-1-5-21-1-2-3","S-1-5-21-1-2-3-4","S-1-5-21-1-2-3-4-5",
            "S-1-5-32","S-1-5-32-544","S-1-5-32-544-1","S-1-4-21-1-2-3-4","S-1-5-80-1","S-1-5-18"};
        foreach(var first in domainCases)
        foreach(var second in domainCases)
            Record("SidCompare",new {First=first,Second=second},()=>{
                var a=new B.SecurityIdentifier(first);var b=new B.SecurityIdentifier(second);
                return new {Compare=Math.Sign(a.CompareTo(b)),Equal=a.Equals(b),DomainEqual=a.IsEqualDomainSid(b)};
            });

        var recording = new { SchemaVersion=1, Runtime=RuntimeInformation.FrameworkDescription, OS=RuntimeInformation.OSDescription,
            MicrosoftAssembly=typeof(M.ActiveDirectorySecurity).Assembly.FullName, Scope="Detached constructors, numeric identities, local account comparisons and rule collections only. No translation or directory I/O.", Observations=rows };
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path,JsonSerializer.Serialize(recording,new JsonSerializerOptions { WriteIndented=true }));
        Console.WriteLine("FOUNDATION_JSON=" + JsonSerializer.Serialize(recording));
    }

    private static object Sid(B.SecurityIdentifier sid) { var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);return new { sid.Value,sid.BinaryLength,Hex=Convert.ToHexString(bytes),AccountDomainSid=sid.AccountDomainSid?.Value,IsAccountSid=sid.IsAccountSid() }; }
    private static object Snapshot(E.AuthorizationRule rule,int mask) => new { Identity=rule.IdentityReference.Value,IdentityKind=rule.IdentityReference.GetType().Name,Mask=mask,rule.IsInherited,Inheritance=(int)rule.InheritanceFlags,Propagation=(int)rule.PropagationFlags,
        Qualifier=rule is E.AccessRule access ? (int)access.AccessControlType : rule is E.AuditRule audit ? (int)audit.AuditFlags : (int?)null,
        ObjectFlags=rule is E.ObjectAccessRule oa ? (int)oa.ObjectFlags : rule is E.ObjectAuditRule ou ? (int)ou.ObjectFlags : (int?)null,
        ObjectType=rule is E.ObjectAccessRule ob ? ob.ObjectType : rule is E.ObjectAuditRule ov ? ov.ObjectType : (Guid?)null,
        InheritedObjectType=rule is E.ObjectAccessRule oc ? oc.InheritedObjectType : rule is E.ObjectAuditRule ow ? ow.InheritedObjectType : (Guid?)null };
    private sealed class AuthorizationProbe(B.IdentityReference i,int m,bool b,E.InheritanceFlags f,E.PropagationFlags p):E.AuthorizationRule(i,m,b,f,p) { public object Snapshot()=>FoundationContracts.Snapshot(this,AccessMask); }
    private sealed class AccessProbe(B.IdentityReference i,int m,bool b,E.InheritanceFlags f,E.PropagationFlags p,E.AccessControlType q):E.AccessRule(i,m,b,f,p,q) { public object Snapshot()=>FoundationContracts.Snapshot(this,AccessMask); }
    private sealed class AuditProbe(B.IdentityReference i,int m,bool b,E.InheritanceFlags f,E.PropagationFlags p,E.AuditFlags q):E.AuditRule(i,m,b,f,p,q) { public object Snapshot()=>FoundationContracts.Snapshot(this,AccessMask); }
    private sealed class ObjectAccessProbe(B.IdentityReference i,int m,bool b,E.InheritanceFlags f,E.PropagationFlags p,E.AccessControlType q,Guid o,Guid t):E.ObjectAccessRule(i,m,b,f,p,o,t,q) { public object Snapshot()=>FoundationContracts.Snapshot(this,AccessMask); }
    private sealed class ObjectAuditProbe(B.IdentityReference i,int m,bool b,E.InheritanceFlags f,E.PropagationFlags p,E.AuditFlags q,Guid o,Guid t):E.ObjectAuditRule(i,m,b,f,p,o,t,q) { public object Snapshot()=>FoundationContracts.Snapshot(this,AccessMask); }
}
