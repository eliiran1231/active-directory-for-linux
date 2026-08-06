# Build/test image with BOTH .NET 10 and .NET 8 so we can run tests on each.
FROM mcr.microsoft.com/dotnet/sdk:10.0

# Add the .NET 8 runtime next to the .NET 10 SDK so `dotnet test -f net8.0` runs.
# The SDK can compile net8.0 by itself; it only needs the runtime to execute.
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 8.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh

WORKDIR /src
