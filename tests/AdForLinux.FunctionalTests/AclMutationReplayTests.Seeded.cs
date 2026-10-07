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
        Assert.StartsWith("projected-reconcile-", sequence);
        using var document = JsonDocument.Parse(json);
        var step = document.RootElement;
        var original = Convert.FromHexString(step.GetProperty("RequestedDescriptorHex").GetString()!);
        var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
        var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
        var operation = Enum.Parse<AclModification>(step.GetProperty("Operation").GetString()!);
        var engine = new AclMutationEngine(SecurityDescriptor.Parse(original, All));
        var rule = CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!));
        var result = engine.ModifyProjected(section, operation, rule);
        Assert.Equal(step.GetProperty("ReturnValue").GetBoolean(), result.ReturnValue);
        Assert.Equal(step.GetProperty("Modified").GetBoolean(), result.Modified);
        Assert.Equal(expected, result.Engine.GetObservableDescriptor().GetBinaryForm());
        if (step.GetProperty("InputHex").GetString() == step.GetProperty("OutputHex").GetString())
        {
            Assert.Same(engine, result.Engine);
            Assert.Equal(original, result.Engine.Descriptor.GetBinaryForm());
            Assert.Equal(SecurityMasks.None, result.Engine.WriteIntent);
        }
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

    [Fact]
    public void Projected_live_sequences_retain_raw_view_provenance_and_prior_snapshots()
    {
        using var recording = ReadSeededRecording("net8");
        var sequences = recording.RootElement.GetProperty("Observations").EnumerateArray()
            .Where(step => step.GetProperty("Sequence").GetString()!.StartsWith("projected-live-", StringComparison.Ordinal))
            .GroupBy(step => step.GetProperty("Sequence").GetString()).ToArray();
        Assert.Equal(8, sequences.Length);
        foreach (var sequence in sequences)
        {
            var original = Convert.FromHexString(sequence.First().GetProperty("RequestedDescriptorHex").GetString()!);
            var engine = new AclMutationEngine(SecurityDescriptor.Parse(original, All));
            var snapshots = new List<(AclMutationEngine Engine, byte[] Raw, byte[] Live, SecurityMasks Intent)>();
            foreach (var step in sequence.OrderBy(step => step.GetProperty("Index").GetInt32()))
            {
                var input = Convert.FromHexString(step.GetProperty("InputHex").GetString()!);
                var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
                var before = engine;
                var raw = before.Descriptor.GetBinaryForm();
                Assert.Equal(input, before.GetObservableDescriptor().GetBinaryForm());
                snapshots.Add((before, raw, input, before.WriteIntent));
                var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
                var sid = Sid.Parse(step.GetProperty("Sid").GetString()!);
                var operation = step.GetProperty("Operation").GetString()!;
                AclMutationResult result = operation switch
                {
                    "Get" => new(before, true, false),
                    "Owner" => before.SetOwner(sid),
                    "Group" => before.SetGroup(sid),
                    "Purge" => before.PurgeProjected(section, sid),
                    "Protect" => before.SetProtectionProjected(section, true, true),
                    "ProtectDrop" => before.SetProtectionProjected(section, true, false),
                    "Unprotect" => before.SetProtectionProjected(section, false, true),
                    _ => before.ModifyProjected(section, Enum.Parse<AclModification>(operation),
                        CoreAce.Read(Convert.FromHexString(step.GetProperty("RuleHex").GetString()!))),
                };
                Assert.Null(step.GetProperty("ExceptionType").GetString());
                engine = result.Engine;
                if (step.GetProperty("ReturnValue").ValueKind != JsonValueKind.Null)
                    Assert.Equal(step.GetProperty("ReturnValue").GetBoolean(), result.ReturnValue);
                if (step.GetProperty("Modified").ValueKind != JsonValueKind.Null)
                    Assert.Equal(step.GetProperty("Modified").GetBoolean(), result.Modified);
                Assert.Equal(expected, engine.GetObservableDescriptor().GetBinaryForm());
                Assert.Equal(expected, engine.GetObservableDescriptor().GetBinaryForm());
                if (input.SequenceEqual(expected))
                {
                    Assert.Same(before, engine);
                    Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
                    Assert.Equal(before.WriteIntent, engine.WriteIntent);
                }
                else Assert.Equal(before.WriteIntent | section, engine.WriteIntent);
                Assert.Equal(original, engine.OriginalDescriptor.GetBinaryForm());
                foreach (var snapshot in snapshots)
                {
                    Assert.Equal(snapshot.Raw, snapshot.Engine.Descriptor.GetBinaryForm());
                    Assert.Equal(snapshot.Live, snapshot.Engine.GetObservableDescriptor().GetBinaryForm());
                    Assert.Equal(snapshot.Intent, snapshot.Engine.WriteIntent);
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(RecordedLayoutEdits))]
    public void Recorded_layout_edits_preserve_original_unreferenced_bytes_or_refuse(string sequence, string json)
    {
        using var document = JsonDocument.Parse(json);
        var step = document.RootElement;
        var original = Convert.FromHexString(step.GetProperty("RequestedDescriptorHex").GetString()!);
        var expected = Convert.FromHexString(step.GetProperty("OutputHex").GetString()!);
        var engine = new AclMutationEngine(SecurityDescriptor.Parse(original, All));
        var operation = step.GetProperty("Operation").GetString()!;
        var refused = (sequence.StartsWith("layout-trailing-", StringComparison.Ordinal)
                && operation is "Add" or "RemoveSpecific" or "RemoveAll")
            || (sequence.StartsWith("layout-null-sections-", StringComparison.Ordinal)
                && operation is not ("Owner" or "Group"));
        if (refused)
        {
            Assert.Throws<InvalidOperationException>(() => ApplyRecordedStep(engine, step));
            Assert.Equal(original, engine.Descriptor.GetBinaryForm());
            Assert.Equal(SecurityMasks.None, engine.WriteIntent);
            return;
        }
        var result = ApplyRecordedStep(engine, step);
        Assert.Equal(expected, result.Engine.GetObservableDescriptor().GetBinaryForm());
        Assert.Equal(original, engine.Descriptor.GetBinaryForm());
        Assert.Equal(original, result.Engine.OriginalDescriptor.GetBinaryForm());
        Assert.False(result.Engine.Descriptor.HasOverlappingComponents);
        if (step.GetProperty("ReturnValue").ValueKind != JsonValueKind.Null)
            Assert.Equal(step.GetProperty("ReturnValue").GetBoolean(), result.ReturnValue);
        if (step.GetProperty("Modified").ValueKind != JsonValueKind.Null)
            Assert.Equal(step.GetProperty("Modified").GetBoolean(), result.Modified);
        var covered = new bool[original.Length];
        Array.Fill(covered, true, 0, 20);
        foreach (var field in new[] { 4, 8, 12, 16 })
        {
            var offset = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(field));
            if (offset == 0) continue;
            var length = field < 12 ? 8 + original[offset + 1] * 4
                : System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(original.AsSpan(offset + 2));
            Array.Fill(covered, true, offset, length);
        }
        var actual = result.Engine.Descriptor.GetBinaryForm();
        for (var i = 20; i < original.Length; i++)
            if (!covered[i]) { Assert.True(i < actual.Length); Assert.Equal(original[i], actual[i]); }
    }

    public static IEnumerable<object[]> RecordedLayoutEdits()
    {
        using var recording = ReadSeededRecording("net8");
        foreach (var step in recording.RootElement.GetProperty("Observations").EnumerateArray())
        {
            var sequence = step.GetProperty("Sequence").GetString()!;
            if (sequence.StartsWith("layout-", StringComparison.Ordinal) && step.GetProperty("Operation").GetString() != "Import")
                yield return new object[] { sequence, step.GetRawText() };
        }
    }

    [Fact]
    public void Portable_layout_candidates_equal_bytes_independently_imported_on_windows()
    {
        using var recording = ReadSeededRecording("net8");
        var observations = recording.RootElement.GetProperty("Observations").EnumerateArray().ToArray();
        var candidates = observations.Where(step => step.GetProperty("Sequence").GetString()!.StartsWith("layout-candidate-", StringComparison.Ordinal)).ToArray();
        Assert.Equal(11, candidates.Length);
        foreach (var candidate in candidates)
        {
            var name = candidate.GetProperty("Sequence").GetString()!["layout-candidate-".Length..];
            var operation = name.EndsWith("-setmask", StringComparison.Ordinal) ? "Set"
                : name.EndsWith("-grow", StringComparison.Ordinal) ? "Add"
                : name.EndsWith("-shrink", StringComparison.Ordinal) ? "RemoveAll"
                : name.Contains("group", StringComparison.Ordinal) ? "Group" : "Owner";
            var fixture = name.StartsWith("shared-", StringComparison.Ordinal) ? "shared-owner-group-with-orphan"
                : name == "same-size-owner-offset-patch" ? "leading-A5"
                : name[..name.LastIndexOf('-')];
            var source = observations.Single(step => step.GetProperty("Sequence").GetString() == $"layout-{fixture}-{operation}");
            var raw = Convert.FromHexString(source.GetProperty("RequestedDescriptorHex").GetString()!);
            var engine = new AclMutationEngine(SecurityDescriptor.Parse(raw, All));
            var result = ApplyRecordedStep(engine, source);
            Assert.Equal(Convert.FromHexString(candidate.GetProperty("InputHex").GetString()!), result.Engine.Descriptor.GetBinaryForm());
            Assert.Equal(Convert.FromHexString(candidate.GetProperty("OutputHex").GetString()!), result.Engine.GetObservableDescriptor().GetBinaryForm());
            Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        }
    }

    private static AclMutationResult ApplyRecordedStep(AclMutationEngine engine, JsonElement step)
    {
        var sid = Sid.Parse(step.GetProperty("Sid").GetString()!);
        var section = Enum.Parse<SecurityMasks>(step.GetProperty("Section").GetString()!);
        return step.GetProperty("Operation").GetString() switch
        {
            "Get" => new AclMutationResult(engine, true, false),
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
