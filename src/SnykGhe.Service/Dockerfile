# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY nuget.config ./
# Copy every referenced project file before restore so the layer caches on dependency changes only.
COPY src/Snyk.Client/Snyk.Client.csproj src/Snyk.Client/
COPY src/SnykGhe.Contracts/SnykGhe.Contracts.csproj src/SnykGhe.Contracts/
COPY src/SnykGhe.Core/SnykGhe.Core.csproj src/SnykGhe.Core/
COPY src/SnykGhe.Service/SnykGhe.Service.csproj src/SnykGhe.Service/
RUN dotnet restore src/SnykGhe.Service/SnykGhe.Service.csproj
COPY . .
RUN dotnet publish src/SnykGhe.Service/SnykGhe.Service.csproj -c Release -o /app --no-restore

# Runtime stage
# Uses the SDK image (not aspnet) because Snyk needs the toolchain present to resolve dependencies
# for the manifest ecosystem being scanned (e.g. `dotnet restore` for NuGet projects).
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS runtime
WORKDIR /app

# git is required to check out pull request heads; curl to fetch the Snyk CLI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Snyk standalone CLI (no Node.js runtime required).
RUN curl -fsSL -o /usr/local/bin/snyk https://downloads.snyk.io/cli/stable/snyk-linux \
    && chmod +x /usr/local/bin/snyk

# Ecosystem toolchains: the .NET SDK above covers NuGet. Add others your orgs use, e.g.:
#   Node/npm:   apt-get install -y nodejs npm
#   Java/Maven: apt-get install -y default-jdk maven
#   Python/pip: apt-get install -y python3 python3-pip
#   Go:         apt-get install -y golang

COPY --from=build /app ./
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "SnykGhe.Service.dll"]
