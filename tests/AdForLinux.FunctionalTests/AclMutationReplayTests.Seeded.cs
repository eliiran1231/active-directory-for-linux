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
