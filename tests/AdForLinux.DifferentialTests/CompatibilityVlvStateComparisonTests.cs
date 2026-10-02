using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public class CompatibilityVlvStateComparisonTests
{
    [Theory]
    [InlineData(0, 50, 0)]
    [InlineData(1, 100, 1)]
    [InlineData(3, 33, 2)]
    [InlineData(13, 15, 2)]
    [InlineData(101, 99, 100)]
    [InlineData(100, 100, 101)]
    [InlineData(21474836, 100, 21474836)]
    [InlineData(21474837, 100, 21474837)]
    [InlineData(int.MaxValue, 99, int.MaxValue)]
    [InlineData(1, 50, int.MaxValue)]
    public void Percentage_offset_and_total_transitions_match_microsoft(int total, int percentage, int offset)
    {
        var microsoft = new Ms.DirectoryVirtualListView(2, 3, "seed");
        var ours = new Ours.DirectoryVirtualListView(2, 3, "seed");
        var comparison = new Comparison($"VLV total={total}, percentage={percentage}, offset={offset}");

        Step("total", () => microsoft.ApproximateTotal = total, () => ours.ApproximateTotal = total);
        Step("percentage", () => microsoft.TargetPercentage = percentage, () => ours.TargetPercentage = percentage);
        Step("offset", () => microsoft.Offset = offset, () => ours.Offset = offset);
        // Changing the estimate and setting it to zero can expose stale or
        // recomputed derived state. Compare each step, not only the final state.
        Step("changed estimate", () => microsoft.ApproximateTotal = 7, () => ours.ApproximateTotal = 7);
        Step("zero estimate", () => microsoft.ApproximateTotal = 0, () => ours.ApproximateTotal = 0);
        Step("offset without estimate", () => microsoft.Offset = offset, () => ours.Offset = offset);
        Step("percentage without estimate", () => microsoft.TargetPercentage = percentage, () => ours.TargetPercentage = percentage);
        comparison.Assert();

        void Step(string label, Action expected, Action actual)
        {
            Exceptions(comparison, label, expected, actual);
            State(comparison, label, microsoft, ours);
        }
    }

    [Theory]
    [InlineData("BeforeCount", -1)]
    [InlineData("BeforeCount", int.MinValue)]
    [InlineData("AfterCount", -1)]
    [InlineData("AfterCount", int.MinValue)]
    [InlineData("Offset", int.MinValue)]
    [InlineData("ApproximateTotal", int.MinValue)]
    [InlineData("TargetPercentage", int.MinValue)]
    [InlineData("TargetPercentage", int.MaxValue)]
    public void Rejected_setter_preserves_all_existing_state_like_microsoft(string property, int value)
    {
        var microsoft = new Ms.DirectoryVirtualListView(2, 3, "seed") { ApproximateTotal = 101, TargetPercentage = 67 };
        var ours = new Ours.DirectoryVirtualListView(2, 3, "seed") { ApproximateTotal = 101, TargetPercentage = 67 };
        var comparison = new Comparison($"VLV {property}={value}");
        Exceptions(comparison, "invalid assignment", () => SetMicrosoft(), () => SetOurs());
        State(comparison, "after assignment", microsoft, ours);
        // The object must remain usable after the rejected update.
        Exceptions(comparison, "recovery", () => microsoft.Offset = 9, () => ours.Offset = 9);
        State(comparison, "after recovery", microsoft, ours);
        comparison.Assert();

        void SetMicrosoft()
        {
            switch (property)
            {
                case "BeforeCount": microsoft.BeforeCount = value; break;
                case "AfterCount": microsoft.AfterCount = value; break;
                case "Offset": microsoft.Offset = value; break;
                case "ApproximateTotal": microsoft.ApproximateTotal = value; break;
                case "TargetPercentage": microsoft.TargetPercentage = value; break;
                default: throw new InvalidOperationException(property);
            }
        }
        void SetOurs()
        {
            switch (property)
            {
                case "BeforeCount": ours.BeforeCount = value; break;
                case "AfterCount": ours.AfterCount = value; break;
                case "Offset": ours.Offset = value; break;
                case "ApproximateTotal": ours.ApproximateTotal = value; break;
                case "TargetPercentage": ours.TargetPercentage = value; break;
                default: throw new InvalidOperationException(property);
            }
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  é\0target  ")]
    public void Target_changes_preserve_position_and_context_like_microsoft(string? target)
    {
        var microsoftContext = new Ms.DirectoryVirtualListViewContext();
        var ourContext = new Ours.DirectoryVirtualListViewContext();
        var microsoft = new Ms.DirectoryVirtualListView(2, 3, 11, microsoftContext) { ApproximateTotal = 17 };
        var ours = new Ours.DirectoryVirtualListView(2, 3, 11, ourContext) { ApproximateTotal = 17 };
        var comparison = new Comparison($"VLV target transition: {target ?? "<null>"}");
        Exceptions(comparison, "target", () => microsoft.Target = target, () => ours.Target = target);
        State(comparison, "target set", microsoft, ours);
        comparison.Check("context retains identity", ReferenceEquals(microsoftContext, microsoft.DirectoryVirtualListViewContext),
            ReferenceEquals(ourContext, ours.DirectoryVirtualListViewContext));
        Exceptions(comparison, "position", () => microsoft.Offset = 7, () => ours.Offset = 7);
        State(comparison, "position set", microsoft, ours);
        comparison.Assert();
    }

    private static void Exceptions(Comparison comparison, string label, Action expected, Action actual)
    {
        var left = Record.Exception(expected);
        var right = Record.Exception(actual);
        comparison.Check($"{label}: exception", left?.GetType().FullName, right?.GetType().FullName)
            .Check($"{label}: parameter", (left as ArgumentException)?.ParamName, (right as ArgumentException)?.ParamName);
    }

    private static void State(Comparison comparison, string label, Ms.DirectoryVirtualListView expected, Ours.DirectoryVirtualListView actual)
    {
        comparison.Check($"{label}: BeforeCount", expected.BeforeCount, actual.BeforeCount)
            .Check($"{label}: AfterCount", expected.AfterCount, actual.AfterCount)
            .Check($"{label}: Offset", expected.Offset, actual.Offset)
            .Check($"{label}: ApproximateTotal", expected.ApproximateTotal, actual.ApproximateTotal)
            .Check($"{label}: TargetPercentage", expected.TargetPercentage, actual.TargetPercentage)
            .Check($"{label}: Target", expected.Target, actual.Target)
            .Check($"{label}: context null", expected.DirectoryVirtualListViewContext is null, actual.DirectoryVirtualListViewContext is null);
    }
}
