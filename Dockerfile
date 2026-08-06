# Build/test image with BOTH .NET 10 and .NET 8 so we can run tests on each.
FROM mcr.microsoft.com/dotnet/sdk:10.0

# System.DirectoryServices.Protocols on Linux is a thin wrapper over the native
# OpenLDAP client. Without it, LdapConnection throws DllNotFoundException.
#
# The .NET runtime hardcodes the name "libldap-2.5.so.0", but Ubuntu 24.04 (the
# base of this SDK image) ships OpenLDAP 2.6 as "libldap.so.2". So we install
# the client and add compatibility symlinks with the name .NET looks for.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libldap2 libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH_DIR="$(dirname "$(readlink -f "$(ldconfig -p | grep 'libldap.so.2' | awk '{print $NF}' | head -1)")")" \
    && ln -sf "$ARCH_DIR/libldap.so.2" "$ARCH_DIR/libldap-2.5.so.0" \
    && ln -sf "$ARCH_DIR/liblber.so.2" "$ARCH_DIR/liblber-2.5.so.0" \
    && ldconfig

# Add the .NET 8 runtime next to the .NET 10 SDK so `dotnet test -f net8.0` runs.
# The SDK can compile net8.0 by itself; it only needs the runtime to execute.
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 8.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh

WORKDIR /src
