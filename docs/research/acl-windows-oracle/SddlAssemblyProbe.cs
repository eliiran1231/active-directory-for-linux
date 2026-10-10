using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Eight directed, isolated witnesses. No ACL is applied to an object or token.
internal static class SddlAssemblyProbe
{
    internal const int Count = 8;
    private const int Capacity = 65532; // largest DWORD-aligned value representable by AclSize
    private const string Ordinary = "(A;;RP;;;WD)";
    private const string LongSid = "(A;;RP;;;S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15)";
    private sealed record Witness(int Length, int Before, int After, bool LongFollower = false);
    private static readonly Witness[] Cases = [new(32702,0,0), new(32702,0,1), new(32702,1,0),
        new(32702,0,4), new(32702,0,1,true), new(32690,0,2), new(32700,0,2), new(8,0,1)];

    internal static void Write(string path, int index)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if ((uint)index >= Count) throw new ArgumentOutOfRangeException(nameof(index));
        var input = Cases[index];
        var condition = $"(@User.A == \"{new string('x', input.Length)}\")";
        var large = $"(XA;;RP;;;WD;{condition})";
        var text = "D:" + string.Concat(Enumerable.Repeat(Ordinary,input.Before)) + large
            + string.Concat(Enumerable.Repeat(input.LongFollower ? LongSid : Ordinary,input.After));
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { AutoFlush = true };
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
        Emit(new { Kind="Attempt", Case=index, input.Length, input.Before, input.After, input.LongFollower,
            Capacity, InputUtf16Hex=SddlBoundaryInputs.Utf16Hex(text), Runtime=RuntimeInformation.FrameworkDescription,
            OS=RuntimeInformation.OSDescription });
        var full = Convert(text);
        // Existing native evidence establishes this sibling succeeds at 32702. The
        // other lengths use their observed successful single-ACE representation.
        var siblingText = "D:" + large + (input.Length == 32702 ? Ordinary : "");
        var sibling = Convert(siblingText);
        var ordinary = Convert("D:" + Ordinary);
        var follower = input.LongFollower ? Convert("D:" + LongSid) : ordinary;
        Emit(new { Kind="Native", Case=index, Full=full, SiblingInputUtf16Hex=SddlBoundaryInputs.Utf16Hex(siblingText),
            Sibling=sibling, Ordinary=ordinary, Follower=follower });
        var largeAce = ExtractDescriptorAce(sibling,9);
        var ordinaryAce = ExtractDescriptorAce(ordinary,0);
        var followerAce = ExtractDescriptorAce(follower,0);
        if (largeAce is null || ordinaryAce is null || followerAce is null)
            throw new InvalidOperationException("A native source ACE was unavailable; no fabricated replay bytes are substituted.");
        var compiled = Assemble(true,input,condition,largeAce,ordinaryAce,followerAce);
        var replayed = Assemble(false,input,condition,largeAce,ordinaryAce,followerAce);
        Emit(new { Kind="Compile", Case=index, Steps=compiled });
        Emit(new { Kind="Replay", Case=index, Steps=replayed });
        if (index == 7 && compiled.Concat(replayed).Any(step => !JsonSerializer.SerializeToElement(step).GetProperty("Success").GetBoolean()))
            throw new InvalidOperationException("The short control failed; inspect the API invocation before interpreting large inputs.");
    }

    private static object[] Assemble(bool compile, Witness input, string condition, byte[] large, byte[] ordinary, byte[] follower)
    {
        var allocation = Marshal.AllocHGlobal(Capacity + 32);
        try
        {
            var initial = new byte[Capacity + 32];
            initial.AsSpan(0,16).Fill(0xA5); initial.AsSpan(Capacity + 16,16).Fill(0xA5);
            Marshal.Copy(initial,0,allocation,initial.Length);
            var acl = IntPtr.Add(allocation,16);
            var steps = new List<object>();
            Marshal.SetLastPInvokeError(0);
            var initialized = InitializeAcl(acl,Capacity,4);
            var initializeError = Marshal.GetLastPInvokeError();
            steps.Add(new { Step="InitializeAcl", Success=initialized, LastError=initializeError, Post=Inspect(acl,allocation) });
            if (!initialized) return steps.ToArray();
            bool Append(string name, byte[]? ace)
            {
                var pre = Inspect(acl,allocation);
                var sid = System.Convert.FromHexString("010100000000000100000000");
                var sourceCopy = ace?.ToArray();
                uint returned = 0;
                Marshal.SetLastPInvokeError(0);
                var success = ace is null
                    ? AddConditionalAce(acl,4,0,9,16,sid,condition,out returned)
                    : AddAce(acl,4,uint.MaxValue,ace,(uint)ace.Length);
                var error = Marshal.GetLastPInvokeError(); // before any inspection/P/Invoke
                var post = Inspect(acl,allocation);
                var bytes = ExtractAclAce(post.Bytes,9);
                steps.Add(new { Step=name, Success=success, LastError=error,
                    RawReturnLength=ace is null ? (uint?)returned : null,
                    ReturnLengthMeaningful=ace is null && (success || error == 122), Pre=pre, Post=post,
                    MatchesNativeLargeAce=bytes is null ? (bool?)null : bytes.AsSpan().SequenceEqual(large),
                    SourceAceUnchanged=ace is null ? (bool?)null : ace.AsSpan().SequenceEqual(sourceCopy) });
                return success;
            }
            for (var i=0;i<input.Before;i++) if (!Append("AddAce predecessor " + i,ordinary)) return steps.ToArray();
            if (!Append(compile ? "AddConditionalAce" : "AddAce native large",compile ? null : large)) return steps.ToArray();
            for (var i=0;i<input.After;i++) if (!Append("AddAce follower " + i,follower)) break;
            return steps.ToArray();
        }
        finally { Marshal.FreeHGlobal(allocation); }
    }

    private sealed record AclImage(string HeaderHex, uint? AceCount, uint? BytesInUse, uint? BytesFree,
        bool InformationSuccess, int InformationError, string Hex, string Sha256, bool GuardsIntact)
    {
        [System.Text.Json.Serialization.JsonIgnore] internal byte[] Bytes => System.Convert.FromHexString(Hex);
    }
    private static AclImage Inspect(IntPtr acl, IntPtr allocation)
    {
        var bytes = new byte[Capacity]; Marshal.Copy(acl,bytes,0,bytes.Length);
        var guard = new byte[16]; Marshal.Copy(allocation,guard,0,16); var intact=guard.All(b=>b==0xA5);
        Marshal.Copy(IntPtr.Add(acl,Capacity),guard,0,16); intact &= guard.All(b=>b==0xA5);
        if (!intact) throw new InvalidOperationException("Native API crossed the bounded caller allocation.");
        var size=BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(2));
        var valid = size is >=8 and <=Capacity;
        var info=new SizeInformation(); var ok=false; var error=0;
        if (valid)
        {
            Marshal.SetLastPInvokeError(0); ok=GetAclInformation(acl,out info,12,2); error=Marshal.GetLastPInvokeError();
            if (ok && (info.BytesInUse > Capacity || info.BytesFree > Capacity || info.BytesInUse + info.BytesFree != size))
                throw new InvalidOperationException("Native ACL size accounting exceeds the declared allocation.");
        }
        return new(System.Convert.ToHexString(bytes.AsSpan(0,8)),ok?info.AceCount:null,ok?info.BytesInUse:null,
            ok?info.BytesFree:null,ok,error,System.Convert.ToHexString(bytes),System.Convert.ToHexString(SHA256.HashData(bytes)),intact);
    }

    private sealed record NativeImage(bool Success,int LastError,uint ReturnedSize,ulong? LocalSize,string? Hex,bool? LocalFreeSucceeded);
    private static NativeImage Convert(string text)
    {
        Marshal.SetLastPInvokeError(0);
        var success=ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,out var allocation,out var returned);
        var error=Marshal.GetLastPInvokeError(); ulong? size=null; byte[]? bytes=null;
        try
        {
            if (success)
            {
                if (allocation.IsInvalid) throw new InvalidOperationException("Native success returned no allocation.");
                size=(ulong)LocalSize(allocation);
                if (returned>1024*1024 || returned>size || size==0) throw new InvalidOperationException("Native descriptor exceeds inspected allocation.");
                bytes=new byte[returned]; Marshal.Copy(allocation.DangerousGetHandle(),bytes,0,bytes.Length);
            }
        }
        finally { allocation.Dispose(); }
        if (allocation.FreeSucceeded==false) throw new InvalidOperationException("LocalFree failed.");
        return new(success,error,returned,size,bytes is null?null:System.Convert.ToHexString(bytes),allocation.FreeSucceeded);
    }
    private static byte[]? ExtractDescriptorAce(NativeImage result, byte type)
    {
        if (!result.Success || result.Hex is null) return null;
        var bytes=System.Convert.FromHexString(result.Hex);
        if (bytes.Length<20) throw new InvalidOperationException("Short native descriptor.");
        var offset=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16));
        if (offset<20 || offset>bytes.Length-8) throw new InvalidOperationException("Native DACL offset out of bounds.");
        return ExtractAclAce(bytes.AsSpan((int)offset),type);
    }
    private static byte[]? ExtractAclAce(ReadOnlySpan<byte> bytes, byte type)
    {
        if (bytes.Length<8) return null;
        var size=BinaryPrimitives.ReadUInt16LittleEndian(bytes[2..]);
        var count=BinaryPrimitives.ReadUInt16LittleEndian(bytes[4..]);
        if (size<8 || size>bytes.Length) return null;
        var cursor=8;
        for(var i=0;i<count;i++)
        {
            if (cursor>size-4) return null;
            var length=BinaryPrimitives.ReadUInt16LittleEndian(bytes[(cursor+2)..]);
            if(length<4 || length>size-cursor) return null;
            if(bytes[cursor]==type) return bytes.Slice(cursor,length).ToArray();
            cursor+=length;
        }
        return null;
    }
    [StructLayout(LayoutKind.Sequential)] private struct SizeInformation { internal uint AceCount,BytesInUse,BytesFree; }
    private sealed class LocalAllocation:SafeHandleZeroOrMinusOneIsInvalid
    { public LocalAllocation():base(true){} internal bool? FreeSucceeded{get;private set;} protected override bool ReleaseHandle(){FreeSucceeded=LocalFree(handle)==IntPtr.Zero;return FreeSucceeded.Value;} }
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeAcl(IntPtr acl,uint length,uint revision);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddConditionalAce(IntPtr acl,uint revision,uint flags,byte type,uint mask,[In]byte[] sid,string condition,out uint returned);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddAce(IntPtr acl,uint revision,uint index,[In]byte[] aces,uint length);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(IntPtr acl,out SizeInformation info,uint length,int informationClass);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out LocalAllocation descriptor,out uint size);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern nuint LocalSize(LocalAllocation allocation);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern IntPtr LocalFree(IntPtr allocation);
}
