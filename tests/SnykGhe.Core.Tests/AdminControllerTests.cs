using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Json;
using SnykGhe.Core.Storage;
using SnykGhe.Service.Controllers;

namespace SnykGhe.Core.Tests
{
    public class AdminControllerTests
    {
        private const string AdminKey = "secret-admin-key";

        private sealed class CapturingRegistry : IGitHubInstallationRegistry
        {
            public GitHubInstallationRecord? OrgRecord { get; set; }
            public RepoScanConfig? RepoConfig { get; set; }

            public OrgPolicyOverlay? WrittenOverlay { get; private set; }
            public IReadOnlyList<string>? WrittenRepoExcludes { get; private set; }
            public bool RepoRemoved { get; private set; }

            public Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken) =>
                Task.FromResult(OrgRecord);

            public Task<RepoScanConfig?> FindRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken) =>
                Task.FromResult(RepoConfig);

            public Task SetOrgPolicyAsync(string gitHubOrg, OrgPolicyOverlay overlay, CancellationToken cancellationToken)
            {
                WrittenOverlay = overlay;
                return Task.CompletedTask;
            }

            public Task SetRepoConfigAsync(string gitHubOrg, string repo, IReadOnlyList<string> excludeDirs, CancellationToken cancellationToken)
            {
                WrittenRepoExcludes = excludeDirs;
                return Task.CompletedTask;
            }

            public Task RemoveRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken)
            {
                RepoRemoved = true;
                return Task.CompletedTask;
            }

            public Task EnsureCreatedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken) => Task.CompletedTask;
        }

        private static AdminController Build(CapturingRegistry registry, bool authorized = true)
        {
            var controller = new AdminController(
                registry,
                Options.Create(new StorageOptions { AdminApiKey = AdminKey }),
                NullLogger<AdminController>.Instance);

            var httpContext = new DefaultHttpContext();
            if (authorized)
            {
                httpContext.Request.Headers["X-Admin-Key"] = AdminKey;
            }

            controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
            return controller;
        }

        [Fact]
        public async Task PutOrg_MissingKey_Unauthorized()
        {
            var registry = new CapturingRegistry();
            var result = await Build(registry, authorized: false)
                .PutOrg("acme", new OrgPolicyPutRequest { SnykOrgId = "snyk-1" }, CancellationToken.None);

            Assert.IsType<UnauthorizedResult>(result);
            Assert.Null(registry.WrittenOverlay);
        }

        [Fact]
        public async Task PutOrg_AbsentFields_ResetToDefaults()
        {
            var registry = new CapturingRegistry
            {
                OrgRecord = new GitHubInstallationRecord { GitHubOrg = "acme", SnykOrgId = "old", SeverityThreshold = "critical" },
            };

            var result = await Build(registry).PutOrg("acme", new OrgPolicyPutRequest { ExcludeDirs = ["obj"] }, CancellationToken.None);

            Assert.IsType<OkObjectResult>(result);
            Assert.NotNull(registry.WrittenOverlay);
            Assert.Null(registry.WrittenOverlay!.SnykOrgId);
            Assert.Null(registry.WrittenOverlay.SeverityThreshold);
            Assert.False(registry.WrittenOverlay.Suspended);
            Assert.Equal(["obj"], registry.WrittenOverlay.ExcludeDirs);
        }

        [Fact]
        public async Task PutOrg_PathLikeExclude_BadRequest_NoWrite()
        {
            var registry = new CapturingRegistry();

            var result = await Build(registry).PutOrg("acme", new OrgPolicyPutRequest { ExcludeDirs = ["src/nested"] }, CancellationToken.None);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(registry.WrittenOverlay);
        }

        [Fact]
        public async Task PatchOrg_MissingRecord_NotFound()
        {
            var registry = new CapturingRegistry { OrgRecord = null };

            var result = await Build(registry).PatchOrg("acme", new OrgPolicyPatchRequest(), CancellationToken.None);

            Assert.IsType<NotFoundResult>(result);
            Assert.Null(registry.WrittenOverlay);
        }

        [Fact]
        public async Task PatchOrg_AbsentPreserved_ExplicitNullClears()
        {
            var registry = new CapturingRegistry
            {
                OrgRecord = new GitHubInstallationRecord
                {
                    GitHubOrg = "acme",
                    SnykOrgId = "keep-me",
                    SeverityThreshold = "critical",
                    Ecosystem = "npm",
                    ExcludeDirs = ["obj"],
                },
            };

            // Clear severity, leave everything else absent (unchanged).
            var body = new OrgPolicyPatchRequest { SeverityThreshold = new Optional<string?>(null) };
            var result = await Build(registry).PatchOrg("acme", body, CancellationToken.None);

            Assert.IsType<OkObjectResult>(result);
            var overlay = registry.WrittenOverlay!;
            Assert.Equal("keep-me", overlay.SnykOrgId);   // absent → unchanged
            Assert.Null(overlay.SeverityThreshold);        // explicit null → cleared
            Assert.Equal("npm", overlay.Ecosystem);        // absent → unchanged
            Assert.Equal(["obj"], overlay.ExcludeDirs);    // absent → unchanged
        }

        [Fact]
        public async Task PatchOrg_ExcludeDirsSpecified_ReplacesList()
        {
            var registry = new CapturingRegistry
            {
                OrgRecord = new GitHubInstallationRecord { GitHubOrg = "acme", ExcludeDirs = ["obj"] },
            };

            var body = new OrgPolicyPatchRequest { ExcludeDirs = new Optional<List<string>?>(["docling-sidecar", "obj", "obj"]) };
            await Build(registry).PatchOrg("acme", body, CancellationToken.None);

            Assert.Equal(["docling-sidecar", "obj"], registry.WrittenOverlay!.ExcludeDirs);
        }

        [Fact]
        public async Task PutRepo_WritesSanitizedList()
        {
            var registry = new CapturingRegistry();

            var result = await Build(registry).PutRepo("acme", "atlas",
                new RepoConfigPutRequest { ExcludeDirs = ["  docling-sidecar  ", "docling-sidecar"] }, CancellationToken.None);

            Assert.IsType<OkObjectResult>(result);
            Assert.Equal(["docling-sidecar"], registry.WrittenRepoExcludes);
        }

        [Fact]
        public async Task PatchRepo_MissingConfig_NotFound()
        {
            var registry = new CapturingRegistry { RepoConfig = null };

            var result = await Build(registry).PatchRepo("acme", "atlas",
                new RepoConfigPatchRequest { ExcludeDirs = new Optional<List<string>?>(["obj"]) }, CancellationToken.None);

            Assert.IsType<NotFoundResult>(result);
            Assert.Null(registry.WrittenRepoExcludes);
        }

        [Fact]
        public async Task PatchRepo_PathLikeExclude_BadRequest_NoWrite()
        {
            var registry = new CapturingRegistry { RepoConfig = new RepoScanConfig { Repo = "atlas", ExcludeDirs = ["obj"] } };

            var result = await Build(registry).PatchRepo("acme", "atlas",
                new RepoConfigPatchRequest { ExcludeDirs = new Optional<List<string>?>(["a/b"]) }, CancellationToken.None);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(registry.WrittenRepoExcludes);
        }

        [Fact]
        public void UnknownField_IsRejected_ProducingA400()
        {
            // The controller relies on [JsonUnmappedMemberHandling(Disallow)] so a typo'd field is a JsonException
            // (surfaced by the input formatter as a 400) rather than being silently ignored.
            Assert.ThrowsAny<System.Text.Json.JsonException>(() =>
                System.Text.Json.JsonSerializer.Deserialize<OrgPolicyPutRequest>(
                    """{ "excludDirs": ["obj"] }""", System.Text.Json.JsonSerializerOptions.Web));
        }

        [Fact]
        public async Task DeleteRepo_RemovesConfig()
        {
            var registry = new CapturingRegistry();

            var result = await Build(registry).DeleteRepo("acme", "atlas", CancellationToken.None);

            Assert.IsType<NoContentResult>(result);
            Assert.True(registry.RepoRemoved);
        }
    }
}
