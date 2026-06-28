using SnykGhe.WebhookService.Fix;

namespace SnykGhe.WebhookService.Tests
{
    public class NuGetManifestPatcherTests : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patch-{Guid.NewGuid():N}");

        public NuGetManifestPatcherTests() => Directory.CreateDirectory(_dir);

        public void Dispose() => Directory.Delete(_dir, recursive: true);

        private static FixPlan PlanFor(string package, string from, string to) =>
            new() { Upgrades = [new PackageUpgrade(package, from, to, ["SNYK-1"])] };

        [Fact]
        public void Apply_SdkStylePackageReferenceAttribute_BumpsVersion()
        {
            var path = Path.Combine(_dir, "App.csproj");
            File.WriteAllText(path, """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
          </ItemGroup>
        </Project>
        """);

            var patched = new NuGetManifestPatcher().Apply(_dir, PlanFor("Newtonsoft.Json", "9.0.1", "13.0.1"));

            var file = Assert.Single(patched);
            Assert.Equal("App.csproj", file.RelativePath);
            Assert.Contains("Version=\"13.0.1\"", file.NewContent);
            Assert.DoesNotContain("9.0.1", file.NewContent);
        }

        [Fact]
        public void Apply_CentralPackageManagement_BumpsPackageVersion()
        {
            var path = Path.Combine(_dir, "Directory.Packages.props");
            File.WriteAllText(path, """
        <Project>
          <ItemGroup>
            <PackageVersion Include="Newtonsoft.Json" Version="9.0.1" />
          </ItemGroup>
        </Project>
        """);

            var patched = new NuGetManifestPatcher().Apply(_dir, PlanFor("Newtonsoft.Json", "9.0.1", "13.0.1"));

            Assert.Single(patched);
            Assert.Contains("Version=\"13.0.1\"", patched[0].NewContent);
        }

        [Fact]
        public void Apply_PackagesConfig_BumpsVersionAttribute()
        {
            var path = Path.Combine(_dir, "packages.config");
            File.WriteAllText(path, """
        <?xml version="1.0" encoding="utf-8"?>
        <packages>
          <package id="Newtonsoft.Json" version="9.0.1" targetFramework="net48" />
        </packages>
        """);

            var patched = new NuGetManifestPatcher().Apply(_dir, PlanFor("Newtonsoft.Json", "9.0.1", "13.0.1"));

            Assert.Single(patched);
            Assert.Contains("version=\"13.0.1\"", patched[0].NewContent);
        }

        [Fact]
        public void Apply_UnrelatedPackage_LeavesFileUnchanged()
        {
            var path = Path.Combine(_dir, "App.csproj");
            File.WriteAllText(path, """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Serilog" Version="2.0.0" />
          </ItemGroup>
        </Project>
        """);

            var patched = new NuGetManifestPatcher().Apply(_dir, PlanFor("Newtonsoft.Json", "9.0.1", "13.0.1"));

            Assert.Empty(patched);
        }
    }
}
