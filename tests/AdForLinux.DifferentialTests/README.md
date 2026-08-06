# Differential tests (run on Windows)

These tests compare **the real Microsoft library** with **our Linux clone**.

They cannot run on Linux, because `System.DirectoryServices` and
`System.DirectoryServices.AccountManagement` only work on Windows. So this
project is **not** part of the Linux/Docker build. You run it yourself on a
Windows machine.

## What they do

Each test runs the *same* operation twice:

1. once with Microsoft's `System.DirectoryServices.AccountManagement`
2. once with our `AdForLinux.DirectoryServices.AccountManagement`

Then it checks both give the same answer. Because the two libraries use
different namespaces, we can reference both at the same time with no clash.

## How to run

1. Use a Windows machine that can reach a Windows Server AD (or the smblds
   test server).
2. Set these environment variables (PowerShell):

   ```powershell
   $env:AD_HOST     = "your-dc.example.com"
   $env:AD_PORT     = "636"
   $env:AD_USE_TLS  = "true"
   $env:AD_BIND_DN  = "administrator@example.com"
   $env:AD_BIND_PW  = "yourPassword"
   $env:AD_BASE_DN  = "DC=example,DC=com"
   ```

3. Run:

   ```powershell
   dotnet test tests/AdForLinux.DifferentialTests -f net8.0-windows
   dotnet test tests/AdForLinux.DifferentialTests -f net10.0-windows
   ```

The tests are filled in at step 12.
