// Detached ACL/descriptor/SDDL closure only. Never resolves identities or persists permissions.
using System.Runtime.InteropServices;
using System.Text.Json;
using M = System.DirectoryServices;

internal static class ClosureContracts
{
    internal static void Write(string path)
    {
        var rows = new List<object>();
        void Record(string operation, object arguments, Func<object?> body)
        {
            object? outcome = null;
            string? exception = null, parameter = null;
            try { outcome = body(); }
            catch (Exception ex)
            {
                exception = ex.GetType().FullName;
                parameter = (ex as ArgumentException)?.ParamName;
            }
            rows.Add(new { Case = rows.Count, Operation = operation, Arguments = arguments,
                Outcome = outcome, ExceptionType = exception, ParamName = parameter });
        }
        AclClosureContracts.Record(Record);
        DescriptorClosureContracts.Record(Record);
        SddlContracts.Record(Record);
        SidClosureContracts.Record(Record);
        IdentityCollectionContracts.Record(Record);
        SddlPayloadContracts.Record(Record);
        var recording = new { SchemaVersion = 1, Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, MicrosoftAssembly = typeof(M.ActiveDirectorySecurity).Assembly.FullName,
            Scope = "Detached ACL, descriptor, SDDL and identity collection contracts only. No directory I/O, identity lookup, persistence or privilege changes.",
            Observations = rows };
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, JsonSerializer.Serialize(recording, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("CLOSURE_JSON=" + JsonSerializer.Serialize(recording));
    }
}
