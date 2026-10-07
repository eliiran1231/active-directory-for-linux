using System.Text.Json;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;

namespace AdForLinux.FunctionalTests;

public partial class AclMutationReplayTests
{
    // Each case begins with the actual serialized Microsoft input of that step, so a
    // failure identifies one operation independently of earlier portable mutations.
    [Theory]
    [MemberData(nameof(RecordedSeededSteps))]
    public void Seeded_Microsoft_step_matches_recorded_outcome(string sequence, int index, string json)
    {
        Assert.False(string.IsNullOrEmpty(sequence));
        Assert.True(index >= 0);
        using var document = JsonDocument.Parse(json);
        var step = document.RootElement;
        var original = Convert.FromHexString(step.GetProperty("InputHex").GetString()!);
        var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
        if (step.GetProperty("Operation").GetString() == "Import")
        {
            var raw = SecurityDescriptor.Parse(original, All);
            Assert.Equal(expected, MicrosoftObservableProjector.Project(raw).GetBinaryForm());
            Assert.Equal(original, raw.GetBinaryForm());
            var detached = new AclMutationEngine(raw);
            Assert.Equal(SecurityMasks.None, detached.WriteIntent);
            return;
        }
        var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
        var operation = step.GetProperty("Operation").GetString()!;
        var engine = new AclMutationEngine(SecurityDescriptor.Parse(original, All));
        AclMutationResult? result = null;
        var exception = Record.Exception(() =>
        {
            result = ApplyRecordedStep(engine, step);
        });
        Assert.Equal(step.GetProperty("ExceptionType").GetString(), exception?.GetType().FullName);
        Assert.Equal(original, engine.Descriptor.GetBinaryForm());
        Assert.Equal(original, engine.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, engine.WriteIntent);
        if (exception is not null)
        {
            Assert.Null(result);
            Assert.Equal(original, expected); // Recorded failures must also be atomic.
            return;
        }
        Assert.NotNull(result);
        Assert.Equal(expected, result.Engine.Descriptor.GetBinaryForm());
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
        if (step.GetProperty("ReturnValue").ValueKind != JsonValueKind.Null)
            Assert.Equal(step.GetProperty("ReturnValue").GetBoolean(), result.ReturnValue);
        if (step.GetProperty("Modified").ValueKind != JsonValueKind.Null)
            Assert.Equal(step.GetProperty("Modified").GetBoolean(), result.Modified);
        var target = operation switch
        {
            "Owner" => SecurityMasks.Owner,
            "Group" => SecurityMasks.Group,
            _ => section,
        };
        Assert.Equal(original.SequenceEqual(expected) ? SecurityMasks.None : target, result.Engine.WriteIntent);
    }

    [Fact]
    public void Recorded_sequences_replay_end_to_end_with_accumulated_intent()
    {
        using var recording = ReadSeededRecording("net8");
        foreach (var sequence in recording.RootElement.GetProperty("Observations").EnumerateArray()
            .Where(step => step.GetProperty("Operation").GetString() != "Import")
            .GroupBy(step => step.GetProperty("Sequence").GetString()))
        {
            var first = Convert.FromHexString(sequence.First().GetProperty("InputHex").GetString()!);
            var engine = new AclMutationEngine(SecurityDescriptor.Parse(first, All));
            var intent = SecurityMasks.None;
            foreach (var step in sequence.OrderBy(step => step.GetProperty("Index").GetInt32()))
            {
                var input = Convert.FromHexString(step.GetProperty("InputHex").GetString()!);
                var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
                Assert.Equal(input, engine.Descriptor.GetBinaryForm());
                var previous = engine;
                AclMutationResult? result = null;
                var exception = Record.Exception(() => result = ApplyRecordedStep(engine, step));
                Assert.Equal(step.GetProperty("ExceptionType").GetString(), exception?.GetType().FullName);
                if (exception is null)
                {
                    Assert.NotNull(result);
                    engine = result.Engine;
                    if (!input.SequenceEqual(expected))
                        intent |= step.GetProperty("Operation").GetString() switch
                        {
                            "Owner" => SecurityMasks.Owner,
                            "Group" => SecurityMasks.Group,
                            _ => Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!),
                        };
                    else Assert.Same(previous, engine);
                }
                Assert.Equal(input, previous.Descriptor.GetBinaryForm());
                Assert.Equal(expected, engine.Descriptor.GetBinaryForm());
                Assert.Equal(first, engine.OriginalDescriptor.GetBinaryForm());
                Assert.Equal(intent, engine.WriteIntent);
            }
        }
    }

    [Fact]
    public void Requested_raw_import_projection_preserves_origin_without_changing_live_replay()
    {
        using var recording = ReadSeededRecording("net8");
        var changedImports = 0;
        foreach (var step in recording.RootElement.GetProperty("Observations").EnumerateArray())
        {
            if (!step.TryGetProperty("RequestedDescriptorHex", out var requested)
                || requested.ValueKind != JsonValueKind.String) continue;
            var raw = Convert.FromHexString(requested.GetString()!);
            var imported = Convert.FromHexString(step.GetProperty(step.GetProperty("Operation").GetString() == "Import" ? "OutputHex" : "InputHex").GetString()!);
            if (raw.SequenceEqual(imported)) continue;
            changedImports++;
            var descriptor = SecurityDescriptor.Parse(raw, All);
            Assert.Equal(imported, MicrosoftObservableProjector.Project(descriptor).GetBinaryForm());
            Assert.Equal(raw, descriptor.GetBinaryForm());
            var engine = new AclMutationEngine(descriptor);
            Assert.Equal(SecurityMasks.None, engine.WriteIntent);
            Assert.Equal(raw, engine.OriginalDescriptor.GetBinaryForm());
        }
        Assert.True(changedImports > 1);
    }

    [Theory]
    [MemberData(nameof(RecordedProjectedSteps))]
    public void Projected_rule_reconciles_recorded_raw_import(string sequence, string json)
    {
        using var document = JsonDocument.Parse(json);
        var step = document.RootElement;
        var original = Convert.FromHexString(step.GetProperty("RequestedDescriptorHex").GetString()!);
        var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
        var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
        var operation = Enum.Parse<AclModification>(step.GetProperty("Operation").GetString()!);
        var engine = new AclMutationEngine(SecurityDescriptor.Parse(original, All));
        var rule = CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!));
        // Eight recorded deletions shift the one-pass pairing boundary into an
        // unchanged group. Matching Microsoft would require altering that group or
        // inventing a redundant contributor. Neither is authorized by this policy.
        if ((sequence.StartsWith("projected-reconcile-triple-", StringComparison.Ordinal)
                || sequence.StartsWith("projected-reconcile-four-", StringComparison.Ordinal))
            && sequence.EndsWith("-Remove-subset", StringComparison.Ordinal))
        {
            var staged = engine.SetGroup(Sid.Parse("S-1-5-21-1-2-3-1002")).Engine;
            var before = staged.Descriptor.GetBinaryForm();
            var failure = Assert.Throws<InvalidOperationException>(() => staged.ModifyProjected(section, operation, rule));
            Assert.Contains("across contributor groups", failure.Message);
            Assert.Equal(before, staged.Descriptor.GetBinaryForm());
            Assert.Equal(original, staged.OriginalDescriptor.GetBinaryForm());
            Assert.Equal(SecurityMasks.Group, staged.WriteIntent);
            return;
        }
        var result = engine.ModifyProjected(section, operation, rule);
        Assert.Equal(step.GetProperty("ReturnValue").GetBoolean(), result.ReturnValue);
        Assert.Equal(step.GetProperty("Modified").GetBoolean(), result.Modified);
        Assert.Equal(expected, MicrosoftObservableProjector.Project(result.Engine.Descriptor).GetBinaryForm());
        Assert.Equal(original, engine.Descriptor.GetBinaryForm());
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
        var originalAcl = section == SecurityMasks.Dacl ? engine.Descriptor.Dacl! : engine.Descriptor.Sacl!;
        var resultAcl = section == SecurityMasks.Dacl ? result.Engine.Descriptor.Dacl! : result.Engine.Descriptor.Sacl!;
        var sid = CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!)).Sid!;
        Assert.Equal(originalAcl.Aces.Where(ace => !ace.Sid!.Equals(sid)).Select(ace => Convert.ToHexString(ace.RawBytes)).Order().ToArray(),
            resultAcl.Aces.Where(ace => !ace.Sid!.Equals(sid)).Select(ace => Convert.ToHexString(ace.RawBytes)).Order().ToArray());
    }

    public static IEnumerable<object[]> RecordedProjectedSteps()
    {
        using var recording = ReadSeededRecording("net8");
        foreach (var step in recording.RootElement.GetProperty("Observations").EnumerateArray())
        {
            var sequence = step.GetProperty("Sequence").GetString()!;
            if (sequence.StartsWith("projected-reconcile-", StringComparison.Ordinal))
                yield return new object[] { sequence, step.GetRawText() };
        }
    }

    private static AclMutationResult ApplyRecordedStep(AclMutationEngine engine, JsonElement step)
    {
        var sid = Sid.Parse(step.GetProperty("Sid").GetString()!);
        var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
        return step.GetProperty("Operation").GetString() switch
        {
            "Owner" => engine.SetOwner(sid),
            "Group" => engine.SetGroup(sid),
            "Purge" => engine.Purge(section, sid),
            "RemoveAll" => section == SecurityMasks.Sacl ? engine.RemoveAudit(sid)
                : engine.RemoveAccess(sid, Convert.FromHexString(step.GetProperty("RuleHex").GetString()!)[0] is 1 or 6),
            "Protect" => engine.SetProtection(section, true, true),
            "ProtectDrop" => engine.SetProtection(section, true, false),
            "Unprotect" => engine.SetProtection(section, false, true),
            var operation => section == SecurityMasks.Dacl
                ? engine.ModifyAccessRule(Enum.Parse<AclModification>(operation!), CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!)))
                : engine.ModifyAuditRule(Enum.Parse<AclModification>(operation!), CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!))),
        };
    }

    [Fact]
    public void Seeded_net8_and_net10_recordings_have_identical_observations()
    {
        using var net8 = ReadSeededRecording("net8");
        using var net10 = ReadSeededRecording("net10");
        Assert.Equal(net8.RootElement.GetProperty("Seed").GetInt32(), net10.RootElement.GetProperty("Seed").GetInt32());
        Assert.Equal(net8.RootElement.GetProperty("MicrosoftAssembly").GetString(), net10.RootElement.GetProperty("MicrosoftAssembly").GetString());
        Assert.Equal(net8.RootElement.GetProperty("Observations").GetRawText(), net10.RootElement.GetProperty("Observations").GetRawText());
    }

    public static IEnumerable<object[]> RecordedSeededSteps()
    {
        using var recording = ReadSeededRecording("net8");
        Assert.Equal(1, recording.RootElement.GetProperty("SchemaVersion").GetInt32());
        foreach (var step in recording.RootElement.GetProperty("Observations").EnumerateArray())
            yield return new object[] { step.GetProperty("Sequence").GetString()!, step.GetProperty("Index").GetInt32(), step.GetRawText() };
    }

    private static JsonDocument ReadSeededRecording(string framework)
    {
        using var stream = typeof(AclMutationReplayTests).Assembly.GetManifestResourceStream($"AclOracle.Seeded.{framework}.json")
            ?? throw new InvalidOperationException("Missing embedded Microsoft oracle recording.");
        return JsonDocument.Parse(stream);
    }
}
