using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit.Sdk;

[assembly: AdForLinux.DifferentialTests.SuiteCaptureAttribute]

namespace AdForLinux.DifferentialTests;

// Output-only instrumentation. Never call ToString, enumerate, reflect over an
// observed object, or read additional library properties here. Opt-in has no
// effect on fixture selection, offline guards, assertions or authentication.
internal static class SuiteCapture
{
    private static readonly AsyncLocal<Session?> Current = new();
    internal const string DirectoryVariable = "ADFL_SUITE_CAPTURE_DIRECTORY";
    internal const string ModeVariable = "ADFL_SUITE_CAPTURE_MODE";
    internal const string ReviewFileVariable = "ADFL_SUITE_CAPTURE_REVIEW_FILE";
    internal const string LiveScalarPolicy = "reviewed-live-lab-scalars-v1";

    internal sealed record LiveScalarReview(int SchemaVersion, string CapturePolicy,
        string PrivacyScope, string SourceTreeSha256, string AssemblySha256);

    internal sealed class Session
    {
        internal required string Path { get; init; }
        internal required string Test { get; init; }
        internal required string Execution { get; init; }
        internal int Sequence;
        internal bool LinkedOutput;
        internal LiveScalarReview? Review;
        internal readonly object Gate = new();
    }

    internal static void Begin(MethodInfo method)
    {
        Current.Value = null;
        var directory = Environment.GetEnvironmentVariable(DirectoryVariable);
        if (string.IsNullOrEmpty(directory))
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(ModeVariable)) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(ReviewFileVariable)))
                throw new InvalidOperationException("Suite capture mode requires a capture directory.");
            return;
        }
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Fresh Microsoft suite capture requires Windows.");
        // Use a pre-created private local directory, never shared CI output.
        // Directory access controls are the operator's responsibility.
        if (!System.IO.Path.IsPathFullyQualified(directory) || !Directory.Exists(directory) ||
            (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Suite capture requires an existing absolute, non-symlink private directory.");
        var assembly = typeof(SuiteCapture).Assembly;
        var review = ReadReview(Environment.GetEnvironmentVariable(ModeVariable),
            Environment.GetEnvironmentVariable(ReviewFileVariable), FileHash(assembly.Location));
        var execution = Guid.NewGuid().ToString("N");
        var path = System.IO.Path.Combine(directory, execution + ".jsonl");
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { }
        var session = new Session { Path = path, Execution = execution, Review = review,
            Test = $"{method.DeclaringType!.FullName}.{method.Name}" };
        Current.Value = session;
        Write(session, new { kind = "begin", schemaVersion = 1, execution,
            testMethod = session.Test, source = "existing-windows-differential-suite",
            provenance = new { os = RuntimeInformation.OSDescription,
                architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                runtime = RuntimeInformation.FrameworkDescription,
                target = assembly.GetCustomAttribute<System.Runtime.Versioning.TargetFrameworkAttribute>()?.FrameworkName,
                sdk = assembly.GetCustomAttributes<AssemblyMetadataAttribute>().SingleOrDefault(a => a.Key == "BuildSdkVersion")?.Value,
                commit = Commit(assembly),
                assemblySha256 = FileHash(assembly.Location),
                microsoftDirectoryServices = typeof(System.DirectoryServices.DirectoryEntry).Assembly.GetName().Version?.ToString(),
                microsoftAccountManagement = typeof(System.DirectoryServices.AccountManagement.Principal).Assembly.GetName().Version?.ToString(),
                offlineGuard = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_OFFLINE_TESTS")),
                capturePolicy = review is null ? "redacted-scalars-v2" : LiveScalarPolicy } });
        if (review is not null)
            Write(session, new { kind = "live-scalar-review", schemaVersion = 1, execution,
                capturePolicy = review.CapturePolicy, privacyScope = review.PrivacyScope,
                sourceTreeSha256 = review.SourceTreeSha256, assemblySha256 = review.AssemblySha256,
                sourcePinVerification = "wrapper-attested-not-runtime-source-verification",
                replayEligibility = "unverified-no-automatic-promotion" });
    }

    // This file is an explicit wrapper attestation, not an authorization/security
    // boundary. The wrapper must verify reviewed source pins and lab/privacy scope.
    // No environment flag alone enables the expanded privacy policy.
    internal static LiveScalarReview? ReadReview(string? mode, string? path, string assemblySha256)
    {
        if (string.IsNullOrEmpty(mode) || mode == "redacted-scalars-v2")
        {
            if (!string.IsNullOrEmpty(path)) throw new InvalidOperationException("Unexpected suite scalar review document.");
            return null;
        }
        if (mode != LiveScalarPolicy || string.IsNullOrEmpty(path) ||
            !System.IO.Path.IsPathFullyQualified(path) || !File.Exists(path) ||
            !PlainLocalPath(path))
            throw new InvalidOperationException("Invalid suite scalar review configuration.");
        LiveScalarReview? review;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[4097];
            var length = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            if (length > 4096) throw new InvalidOperationException("Suite scalar review document is too large.");
            using var document = JsonDocument.Parse(buffer.AsMemory(0, length));
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                document.RootElement.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != 5 ||
                document.RootElement.EnumerateObject().Count() != 5)
                throw new InvalidOperationException("Invalid suite scalar review fields.");
            review = document.RootElement.Deserialize<LiveScalarReview>(
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow });
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("Invalid suite scalar review document.");
        }
        if (review is null || review.SchemaVersion != 1 || review.CapturePolicy != LiveScalarPolicy ||
            review.PrivacyScope != "isolated-lab-scalar-values-reviewed" ||
            !IsHash(review.SourceTreeSha256) || !IsHash(review.AssemblySha256) ||
            review.AssemblySha256 != assemblySha256)
            throw new InvalidOperationException("Suite scalar review does not match this capture.");
        return review;
    }

    private static bool PlainLocalPath(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        for (var current = new FileInfo(path) as FileSystemInfo; current is not null;
            current = current is FileInfo file ? file.Directory : ((DirectoryInfo)current).Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) return false;
        return true;
    }

    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string? Commit(Assembly assembly)
    {
        // Build provenance only: GITHUB_SHA may describe a different checkout.
        var candidate = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+').Last();
        return candidate is { Length: 40 } && candidate.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
            ? candidate.ToLowerInvariant() : null;
    }

    private static string FileHash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    // The three detached smoke classes call this at test-body entry. This
    // marker binds a private execution file to its exact xUnit theory/TRX row.
    // It is absent when capture is disabled and contains no observed values.
    internal static void LinkOutput(Xunit.Abstractions.ITestOutputHelper output)
    {
        var session = Current.Value;
        if (session is null) return;
        lock (session.Gate)
        {
            if (session.LinkedOutput)
                throw new InvalidOperationException("Suite capture execution linked twice.");
            output.WriteLine("ADFL_SUITE_EXECUTION_V1: " + session.Execution);
            session.LinkedOutput = true;
        }
    }

    internal static void End()
    {
        var session = Current.Value;
        if (session is null) return;
        Write(session, new { kind = "end", schemaVersion = 1, execution = session.Execution,
            observations = session.Sequence, status = "body-finished-outcome-unverified" });
        Current.Value = null;
    }

    // Return exactly the same value and static type: original xUnit overloads,
    // assertion order and exception behavior remain in place. This is an
    // assertion operand, NOT proof it originated from the Microsoft library.
    internal static T Expected<T>(T value, string role, int sourceLine,
        [CallerFilePath] string file = "", [CallerMemberName] string member = "")
    {
        Observe(role, file, member, sourceLine, value, null, false);
        return value;
    }

    internal static void Comparison(string semantics, object? microsoft, object? ours,
        string file, string member, int line) => Observe(semantics, file, member, line, microsoft, ours, true);

    private static void Observe(string role, string file, string member, int line,
        object? value, object? other, bool pair)
    {
        var session = Current.Value;
        if (session is null) return;
        lock (session.Gate)
        {
            Write(session, new { kind = "observation", schemaVersion = 1,
                execution = session.Execution, sequence = ++session.Sequence,
                sourceFile = System.IO.Path.GetFileName(file), sourceMember = member, sourceLine = line,
                role, origin = pair ? "explicit-microsoft-comparison" : "assertion-operand-unverified",
                value = Snapshot(value, NumericAdmitted(session, file, line)),
                other = pair ? Snapshot(other, NumericAdmitted(session, file, line)) : null });
        }
    }

    // Privacy admission only. These reviewed sites use detached constructors,
    // synthetic controls and setter/getter state; no directory values. Unknown
    // sites (including new lines/methods) redact numeric/boolean observations.
    private static bool NumericAdmitted(Session session, string file, int line) =>
        session.Review is not null || NumericSites.Contains((session.Test, System.IO.Path.GetFileName(file), line));

    private static readonly HashSet<(string TestMethod, string SourceFile, int SourceLine)> NumericSites = new()
    {
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft", "CompatibilitySearcherStateComparisonTests.cs", 51),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft", "CompatibilitySearcherStateComparisonTests.cs", 56),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 81),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 82),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 83),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 84),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 85),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 86),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 87),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft", "CompatibilitySearcherStateComparisonTests.cs", 129),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 129),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft", "CompatibilitySearcherStateComparisonTests.cs", 130),
        ("AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset", "CompatibilitySearcherStateComparisonTests.cs", 130),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter", "CompatibilitySynchronizationComparisonTests.cs", 54),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations", "CompatibilitySynchronizationComparisonTests.cs", 75),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter", "CompatibilitySynchronizationComparisonTests.cs", 143),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations", "CompatibilitySynchronizationComparisonTests.cs", 143),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers", "CompatibilitySynchronizationComparisonTests.cs", 143),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter", "CompatibilitySynchronizationComparisonTests.cs", 144),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations", "CompatibilitySynchronizationComparisonTests.cs", 144),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers", "CompatibilitySynchronizationComparisonTests.cs", 144),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter", "CompatibilitySynchronizationComparisonTests.cs", 149),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations", "CompatibilitySynchronizationComparisonTests.cs", 149),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers", "CompatibilitySynchronizationComparisonTests.cs", 149),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter", "CompatibilitySynchronizationComparisonTests.cs", 150),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations", "CompatibilitySynchronizationComparisonTests.cs", 150),
        ("AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers", "CompatibilitySynchronizationComparisonTests.cs", 150),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 113),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 124),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 124),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 124),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 125),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 125),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 125),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 130),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 130),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 130),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 131),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 131),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 131),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 132),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 132),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 132),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 133),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 133),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 133),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 134),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 134),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 134),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 135),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 135),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 135),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft", "CompatibilityVlvStateComparisonTests.cs", 136),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 136),
        ("AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft", "CompatibilityVlvStateComparisonTests.cs", 136),
    };

    // Opaque values are deliberately unusable as portable expected values. Do
    // not hash identifiers: hashes still expose low-entropy credentials/data.
    private static object Snapshot(object? value, bool allowNumeric) => value switch
    {
        null => new { type = "null", value = (object?)null, replayable = true },
        bool v when allowNumeric => Scalar("boolean", v),
        byte v when allowNumeric => Scalar("uint8", v), sbyte v when allowNumeric => Scalar("int8", v),
        short v when allowNumeric => Scalar("int16", v), ushort v when allowNumeric => Scalar("uint16", v),
        int v when allowNumeric => Scalar("int32", v), uint v when allowNumeric => Scalar("uint32", v),
        long v when allowNumeric => Scalar("int64", v), ulong v when allowNumeric => Scalar("uint64", v),
        // No arbitrary strings, bytes, dates, GUIDs, SID values, exception
        // messages, property labels, subjects, arguments or object type names.
        Type v when ExceptionNames.Contains(v.FullName ?? "") =>
            Scalar("exception-type", v.FullName!),
        string v when ExceptionNames.Contains(v) => Scalar("exception-type", v),
        Enum v when allowNumeric => EnumSnapshot(v),
        _ => new { type = "redacted", value = (object?)null, replayable = false },
    };

    private static object EnumSnapshot(Enum value)
    {
        // Enum.GetTypeCode and the numeric conversions are runtime enum operations,
        // not user-defined IConvertible/ToString or reflected property access.
        return value.GetTypeCode() == TypeCode.UInt64
            ? Scalar("enum-uint64", Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture))
            : Scalar("enum-int64", Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture));
    }

    private static object Scalar(string type, object value) => new { type, value, replayable = true };
    // Finite known identifiers, not a regex that could admit arbitrary data.
    private static readonly HashSet<string> ExceptionNames = new(StringComparer.Ordinal)
    {
        typeof(ArgumentException).FullName!, typeof(ArgumentNullException).FullName!,
        typeof(ArgumentOutOfRangeException).FullName!, typeof(InvalidOperationException).FullName!,
        typeof(ObjectDisposedException).FullName!, typeof(NotSupportedException).FullName!,
        typeof(NotImplementedException).FullName!, typeof(NullReferenceException).FullName!,
        typeof(IndexOutOfRangeException).FullName!, typeof(InvalidCastException).FullName!,
        typeof(FormatException).FullName!, typeof(OverflowException).FullName!,
        typeof(System.ComponentModel.InvalidEnumArgumentException).FullName!,
        typeof(System.Runtime.InteropServices.COMException).FullName!, typeof(Exception).FullName!,
        "System.DirectoryServices.DirectoryServicesCOMException",
        "System.DirectoryServices.AccountManagement.PrincipalOperationException",
        "System.DirectoryServices.AccountManagement.PrincipalServerDownException",
        "System.DirectoryServices.AccountManagement.MultipleMatchesException",
        "System.DirectoryServices.AccountManagement.NoMatchingPrincipalException",
        "System.DirectoryServices.AccountManagement.PasswordException",
    };

    static SuiteCapture()
    {
        // Tests commonly project GetType().Name rather than FullName. Admit
        // only the short forms of this same finite, known exception list.
        foreach (var name in ExceptionNames.ToArray())
            ExceptionNames.Add(name[(name.LastIndexOf('.') + 1)..]);
    }

    private static void Write(Session session, object record)
    {
        // Capture errors are explicit failures, not silently missing evidence.
        // Values never appear in diagnostics from this sink.
        File.AppendAllText(session.Path, JsonSerializer.Serialize(record) + "\n");
    }
}

public sealed class SuiteCaptureAttribute : BeforeAfterTestAttribute
{
    public override void Before(MethodInfo methodUnderTest) => SuiteCapture.Begin(methodUnderTest);
    public override void After(MethodInfo methodUnderTest) => SuiteCapture.End();
}
