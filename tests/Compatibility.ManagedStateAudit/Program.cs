using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

// Source-audited whitelist: no SearchRoot getter, Find*, entry, or native handle.
var properties = new[] { "SearchScope", "AttributeScopeQuery", "CacheResults", "PageSize", "SizeLimit", "Filter", "SecurityMasks", "ExtendedDN", "DerefAlias", "ReferralChasing", "Asynchronous", "Tombstone", "PropertyNamesOnly", "ClientTimeout", "ServerTimeLimit", "ServerPageTimeLimit" };
var random = new Random(1032026);
int differences = 0, operations = 0, checks = 0;
for (int trial = 0; trial < 2000; trial++)
{
    using var left = new Ms.DirectorySearcher();
    using var right = new Ours.DirectorySearcher();
    var trace = new List<string>();
    for (int step = 0; step < 60; step++)
    {
        int choice = random.Next(properties.Length + 4);
        string action; Exception? a, b;
        if (choice == properties.Length)
        {
            bool clear = random.Next(2) == 0;
            action = "VirtualListView=" + (clear ? "null" : "new");
            a = Capture(() => left.VirtualListView = clear ? null : new Ms.DirectoryVirtualListView());
            b = Capture(() => right.VirtualListView = clear ? null : new Ours.DirectoryVirtualListView());
        }
        else if (choice == properties.Length + 1)
        {
            bool clear = random.Next(2) == 0;
            action = "DirectorySynchronization=" + (clear ? "null" : "new");
            a = Capture(() => left.DirectorySynchronization = clear ? null : new Ms.DirectorySynchronization());
            b = Capture(() => right.DirectorySynchronization = clear ? null : new Ours.DirectorySynchronization());
        }
        else if (choice == properties.Length + 2)
        {
            action = "Dispose";
            a = Capture(left.Dispose); b = Capture(right.Dispose);
        }
        else if (choice == properties.Length + 3)
        {
            bool clear = random.Next(2) == 0;
            action = "Sort=" + (clear ? "null" : "new");
            a = Capture(() => left.Sort = clear ? null! : new Ms.SortOption());
            b = Capture(() => right.Sort = clear ? null! : new Ours.SortOption());
        }
        else
        {
            string name = properties[choice];
            var lp = left.GetType().GetProperty(name)!; var rp = right.GetType().GetProperty(name)!;
            object? value;
            if (lp.PropertyType == typeof(string)) value = new string?[] { null, "", "member", "(cn=Alice)", " " }[random.Next(5)];
            else if (lp.PropertyType == typeof(bool)) value = random.Next(2) == 0;
            else if (lp.PropertyType == typeof(TimeSpan)) value = TimeSpan.FromTicks(new long[] { -10000001, -10000000, -1, 0, 1, 15000000, 21474836470000000, 21474836480000000, long.MaxValue }[random.Next(9)]);
            else value = new[] { -1, 0, 1, 2, 3, 7, 15, 32, 64, 96, int.MaxValue }[random.Next(11)];
            action = name + "=" + (value?.ToString() ?? "null");
            a = Capture(() => lp.SetValue(left, lp.PropertyType.IsEnum ? Enum.ToObject(lp.PropertyType, value!) : value));
            b = Capture(() => rp.SetValue(right, rp.PropertyType.IsEnum ? Enum.ToObject(rp.PropertyType, value!) : value));
        }
        operations++; trace.Add(action);
        Compare("exception", Describe(a), Describe(b));
        foreach (var property in properties)
            Compare(property, Normalize(left.GetType().GetProperty(property)!.GetValue(left)), Normalize(right.GetType().GetProperty(property)!.GetValue(right)));
        Compare("vlv", left.VirtualListView is not null, right.VirtualListView is not null);
        Compare("sync", left.DirectorySynchronization is not null, right.DirectorySynchronization is not null);
        Compare("sort", left.Sort.PropertyName, right.Sort.PropertyName);

        void Compare(string label, object? expected, object? actual)
        {
            checks++;
            if (Equals(expected, actual)) return;
            differences++;
            if (differences <= 10) Console.WriteLine($"DIFF trial={trial} step={step} {label}: {expected} != {actual}; sequence: {string.Join(";",trace)}");
        }
    }
}
Console.WriteLine($"seed=1032026 sequences=2000 operations={operations} comparisons={checks} differences={differences}; microsoft={typeof(Ms.DirectorySearcher).Assembly.Location} version={typeof(Ms.DirectorySearcher).Assembly.GetName().Version}");
Console.WriteLine($"runtime={RuntimeInformation.FrameworkDescription}; os={RuntimeInformation.OSDescription}; architecture={RuntimeInformation.ProcessArchitecture}");
Console.WriteLine($"microsoft-sha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(Ms.DirectorySearcher).Assembly.Location))).ToLowerInvariant()}");
Environment.ExitCode = differences == 0 ? 0 : 1;
static object? Normalize(object? value) => value is Enum ? Convert.ToInt64(value) : value;
static Exception? Capture(Action action) { try { action(); return null; } catch (TargetInvocationException e) { return e.InnerException; } catch (Exception e) { return e; } }
static string Describe(Exception? e) => e is null ? "accepted" : e.GetType().FullName + ":" + (e as ArgumentException)?.ParamName;
