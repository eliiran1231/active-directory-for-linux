// Synthetic harness only. No real directory APIs or runner.
namespace Xunit.Sdk
{
    [System.AttributeUsage(System.AttributeTargets.Assembly)]
    public abstract class BeforeAfterTestAttribute : System.Attribute
    {
        public virtual void Before(System.Reflection.MethodInfo method) { }
        public virtual void After(System.Reflection.MethodInfo method) { }
    }
}
namespace Xunit.Abstractions { public interface ITestOutputHelper { void WriteLine(string text); } }
namespace System.DirectoryServices { public sealed class DirectoryEntry { } }
namespace System.DirectoryServices.AccountManagement { public sealed class Principal { } }
