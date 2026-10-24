namespace AdForLinux.FunctionalTests;

// Fixed category bits and numeric HResults only; never exception messages/paths.
internal sealed class WindowsDiagnosticCleanup
{
    internal int Mask { get; private set; }
    internal int LeaseCode, KeyCode, OtherCode, SourceCode, TargetCode, PoolDelta;
    internal void Attempt(int bit, Action operation)
    {
        try { operation(); }
        catch (Exception error)
        {
            Mask |= bit;
            switch (bit)
            {
                case 1: LeaseCode = error.HResult; break;
                case 2: KeyCode = error.HResult; break;
                case 4: OtherCode = error.HResult; break;
                case 8: SourceCode = error.HResult; break;
                case 16: TargetCode = error.HResult; break;
                default: throw new ArgumentOutOfRangeException(nameof(bit));
            }
        }
    }
    internal void CheckPool(int initial, int final)
    { PoolDelta = final - initial; if (PoolDelta != 0) Mask |= 32; }
}
