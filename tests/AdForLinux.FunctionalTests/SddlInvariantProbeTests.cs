#pragma warning disable CA1416 // Portable operations; shared framework enums only.
using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.AccessControl;
using System.Text.Json;
using AdForLinux.DirectoryServices;
using Xunit;
using Xunit.Abstractions;
using A = AdForLinux.Security.AccessControl;
using C = AdForLinux.DirectoryServices.Security.Core;
using P = AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

// Potentially malformed/deep input runs only in the separately resource-limited worker.
public sealed class BoundedInvariantFactAttribute : FactAttribute
{
    public BoundedInvariantFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("ADFL_BOUNDED_INVARIANT_WORKER") != "1")
            Skip = "Opt-in bounded local investigation; use tests/run-bounded-invariants.py.";
    }
}

public sealed class SddlInvariantProbeTests(ITestOutputHelper output)
{
    private const int Seed = 2261010;
    private static readonly int[] SeedCases = { 2369, 2402, 2418, 2540, 3751, 3883, 4164, 4302 };
    private static (string Text, byte[] Bytes)[] Seeds()
    {
        return PortableSecurityFoundationTests.ClosureRecordings()
            .Where(row => SeedCases.Contains((int)row[0])).Select(row =>
            {
                using var d = JsonDocument.Parse((string)row[2]);
                var item = d.RootElement;
                Assert.Equal(JsonValueKind.Null, item.GetProperty("ExceptionType").ValueKind);
                Assert.Equal("SddlParse", item.GetProperty("Operation").GetString());
                return (item.GetProperty("Arguments").GetProperty("Text").GetString()!,
                    Convert.FromHexString(item.GetProperty("Outcome").GetProperty("Hex").GetString()!));
            }).ToArray();
    }
    private void Report(string group, object result) => output.WriteLine(JsonSerializer.Serialize(new { Group = group, Seed, Result = result }));
    private static byte[] Bytes(A.RawSecurityDescriptor raw) { var b = new byte[raw.BinaryLength]; raw.GetBinaryForm(b, 0); return b; }
    private static void ManagedRefusal(Exception e, string context) => Assert.True(
        e is ArgumentException or InvalidOperationException or NotSupportedException or Win32Exception,
        $"{context}: unexpected implementation exception {e}");

    private static byte[] Mutate(byte[] source, Random random, int iteration)
    {
        var bytes = (byte[])source.Clone();
        switch (iteration % 4)
        {
            case 0: bytes[random.Next(bytes.Length)] ^= (byte)(1 << random.Next(8)); break;
            case 1: Array.Resize(ref bytes, random.Next(bytes.Length + 1)); break;
            case 2:
                var count = random.Next(1, 9); var old = bytes.Length; Array.Resize(ref bytes, old + count);
                random.NextBytes(bytes.AsSpan(old)); break;
            default:
                for (var j = 0; j < 3; j++) bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
                break;
        }
        return bytes;
    }

    [BoundedInvariantFact]
    public void Recorded_raw_mutations_roundtrip_or_refuse_without_changing_buffers()
    {
        var random = new Random(Seed); var seeds = Seeds(); var accepted = 0; var refused = 0;
        for (var i = 0; i < 1024; i++)
        {
            var input = Mutate(seeds[i % seeds.Length].Bytes, random, i); var before = (byte[])input.Clone();
            C.SecurityDescriptor? parsed = null;
            var error = Record.Exception(() => parsed = C.SecurityDescriptor.Parse(input, (SecurityMasks)15));
            Assert.Equal(before, input);
            if (error is not null) { Assert.IsType<ArgumentException>(error); refused++; continue; }
            accepted++;
            Assert.Equal(before, parsed!.GetBinaryForm());
            Array.Fill(input, (byte)0xff); var returned = parsed.GetBinaryForm(); Array.Fill(returned, (byte)0);
            Assert.Equal(before, parsed.GetBinaryForm());
        }
        Assert.True(accepted > 0 && refused > 0); Report("raw", new { Iterations = 1024, accepted, refused });
    }

    [BoundedInvariantFact]
    public void Recorded_text_mutations_preserve_successful_binary_and_failed_exports()
    {
        var random = new Random(Seed + 1); var seeds = Seeds(); var parsedCount = 0; var refused = 0; var formatted = 0;
        var characters = new[] { '\0', '\ud800', '\udc00', '%', '"', '(', ')', ';', ',', '0', 'A', 'é', '\uffff' };
        for (var i = 0; i < 512; i++)
        {
            var text = seeds[i % seeds.Length].Text; var at = random.Next(text.Length);
            text = (i % 4) switch
            {
                0 => text.Remove(at, 1), 1 => text.Insert(at, characters[random.Next(characters.Length)].ToString()),
                2 => text[..at] + characters[random.Next(characters.Length)] + text[(at + 1)..],
                _ => text + new string(characters[random.Next(characters.Length)], random.Next(1, 5))
            };
            A.RawSecurityDescriptor? raw = null;
            var error = Record.Exception(() => raw = new A.RawSecurityDescriptor(text));
            if (error is not null) { ManagedRefusal(error, $"text mutation {i}"); refused++; continue; }
            parsedCount++; var before = Bytes(raw!);
            Assert.Equal(before, Bytes(new A.RawSecurityDescriptor(before, 0)));
            string? result = null; error = Record.Exception(() => result = raw!.GetSddlForm(AccessControlSections.All));
            Assert.Equal(before, Bytes(raw!));
            if (error is not null) { ManagedRefusal(error, $"export mutation {i}"); continue; }
            formatted++; Assert.Equal(before, Bytes(new A.RawSecurityDescriptor(result!)));
        }
        Assert.True(parsedCount > 0 && refused > 0 && formatted > 0);
        Report("text", new { Iterations = 512, parsedCount, refused, formatted });
    }

    [BoundedInvariantFact]
    public void Conditional_payload_mutations_never_silently_lose_bytes()
    {
        var random = new Random(Seed + 2);
        var seed = new A.RawSecurityDescriptor(Seeds()[0].Text);
        var original = ((A.QualifiedAce)seed.DiscretionaryAcl![0]).GetOpaque()!;
        var formatted = 0; var refused = 0;
        for (var i = 0; i < 1024; i++)
        {
            var data = Mutate(original, random, i); var before = (byte[])data.Clone();
            string? text = null; var error = Record.Exception(() => text = A.SddlConditionCodec.Format(data));
            Assert.Equal(before, data);
            if (error is not null) { ManagedRefusal(error, $"payload {i}"); refused++; continue; }
            formatted++; Assert.Equal(before, A.SddlConditionCodec.Parse(text!));
        }
        Assert.True(formatted > 0 && refused > 0); Report("payload", new { Iterations = 1024, formatted, refused });
    }

    [BoundedInvariantFact]
    public void Generated_edit_back_keeps_snapshots_and_rolls_back_every_failed_publication()
    {
        var random = new Random(Seed + 3); var accepted = 0; var refused = 0;
        for (var i = 0; i < 256; i++)
        {
            var source = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U2)), Acl(4, Ace(2, 0x40, 16, U1)));
            var descriptor = new A.CommonSecurityDescriptor(true, true, source, 0);
            var wrapper = new FacadeContracts.Wrapper(descriptor); var peer = new FacadeContracts.Wrapper(descriptor);
            wrapper.SetOwner(new P.SecurityIdentifier(U2, 0)); // Preserve pre-existing intent through failures.
            var export = wrapper.ExportInterop((bytes, container, ds) => A.FacadeMutation.Bytes(new A.CommonSecurityDescriptor(container, ds, bytes, 0)), bytes => bytes);
            var snapshot = export.Provenance.Snapshot;
            var savedRaw = snapshot.Raw; var savedOriginal = snapshot.Original; var savedLive = snapshot.Observable; var savedBaseline = export.Provenance.Binary;
            var state = descriptor.MutationState; var version = descriptor.MutationVersion; var flags = wrapper.Flags(); var peerFlags = peer.Flags();
            var pending = wrapper.PendingWriteSections; var before = wrapper.GetSecurityDescriptorBinaryForm();
            byte[] candidate;
            if (i % 4 == 0) candidate = Mutate(export.Value, random, i / 4);
            else
            {
                var raw = new A.RawSecurityDescriptor(export.Value, 0);
                ((A.KnownAce)raw.SystemAcl![0]).AccessMask = 1 << random.Next(1, 16);
                if (i % 4 == 2) raw.Owner = new P.SecurityIdentifier(U1, 0);
                if (i % 4 == 3) raw.DiscretionaryAcl![0] = new A.CustomAce((AceType)21, AceFlags.None, new byte[16]);
                candidate = Bytes(raw);
            }
            var input = (byte[])candidate.Clone(); var error = Record.Exception(() => wrapper.ReconcileInterop(export.Provenance, candidate));
            Assert.Equal(input, candidate);
            if (error is not null)
            {
                ManagedRefusal(error, $"edit-back {i}"); refused++;
                Assert.Same(state, descriptor.MutationState); Assert.Equal(version, descriptor.MutationVersion);
                Assert.Equal(flags, wrapper.Flags()); Assert.Equal(peerFlags, peer.Flags()); Assert.Equal(pending, wrapper.PendingWriteSections);
                Assert.Equal(before, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(before, peer.GetSecurityDescriptorBinaryForm());
                Assert.Equal(SecurityMasks.None, wrapper.ReconcileInterop(export.Provenance, export.Value));
            }
            else
            {
                accepted++; Assert.Equal(Bytes(new A.RawSecurityDescriptor(candidate, 0)), wrapper.GetSecurityDescriptorBinaryForm());
                Assert.Equal(wrapper.GetSecurityDescriptorBinaryForm(), peer.GetSecurityDescriptorBinaryForm());
            }
            Array.Fill(snapshot.Raw, (byte)0); Array.Fill(snapshot.Original, (byte)0); Array.Fill(snapshot.Observable, (byte)0); Array.Fill(export.Provenance.Binary, (byte)0);
            Assert.Equal(savedRaw, snapshot.Raw); Assert.Equal(savedOriginal, snapshot.Original); Assert.Equal(savedLive, snapshot.Observable); Assert.Equal(savedBaseline, export.Provenance.Binary);
        }
        Assert.True(accepted > 0 && refused > 0); Report("edit-back", new { Iterations = 256, accepted, refused });
    }

    [BoundedInvariantFact]
    public void Deep_and_malformed_expressions_stay_inside_local_allocation_budget()
    {
        _ = A.SddlConditionCodec.Parse("(a)");
        var measurements = new List<object>();
        foreach (var depth in new[] { 256, 2048, 8192 })
        foreach (var malformed in new[] { false, true })
        {
            var text = string.Concat(Enumerable.Repeat("(!", depth)) + "(a)" + new string(')', malformed ? depth - 1 : depth);
            var before = GC.GetAllocatedBytesForCurrentThread(); byte[]? payload = null;
            var error = Record.Exception(() => payload = A.SddlConditionCodec.Parse(text));
            if (error is null)
            {
                var original = (byte[])payload!.Clone(); var rendered = A.SddlConditionCodec.Format(payload);
                Assert.Equal(original, payload); Assert.Equal(original, A.SddlConditionCodec.Parse(rendered));
            }
            else ManagedRefusal(error, $"depth {depth}, malformed {malformed}");
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.True(allocated < 64L * 1024 * 1024, $"depth {depth}: allocated {allocated}");
            measurements.Add(new { depth, malformed, allocated, Refused = error is not null });
        }
        Report("deep", measurements);
    }
}
