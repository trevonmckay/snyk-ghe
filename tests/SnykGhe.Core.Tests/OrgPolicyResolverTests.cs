using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Snyk;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Tests
{
    public class OrgPolicyResolverTests
    {
        private sealed class FakeRegistry : IGitHubInstallationRegistry
        {
            private readonly GitHubInstallationRecord? _record;
            private readonly RepoScanConfig? _repoConfig;

            public FakeRegistry(GitHubInstallationRecord? record, RepoScanConfig? repoConfig = null)
            {
                _record = record;
                _repoConfig = repoConfig;
            }

            public string? RepoRequestedFor { get; private set; }

            public Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken) =>
                Task.FromResult(_record);

            public Task<RepoScanConfig?> FindRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken)
            {
                RepoRequestedFor = repo;
                return Task.FromResult(_repoConfig);
            }

            public Task EnsureCreatedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetOrgPolicyAsync(string gitHubOrg, OrgPolicyOverlay overlay, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetRepoConfigAsync(string gitHubOrg, string repo, IReadOnlyList<string> excludeDirs, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task RemoveRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken) => Task.CompletedTask;
        }

        private static OrgPolicyResolver Build(
            GitHubInstallationRecord? record,
            RepoScanConfig? repoConfig = null,
            List<string>? defaultExcludeDirs = null) => new(
            new FakeRegistry(record, repoConfig),
            Options.Create(new SnykOptions
            {
                DefaultSnykOrgId = "default-org",
                DefaultSeverityThreshold = "high",
                DefaultEcosystem = "nuget",
                DefaultExcludeDirs = defaultExcludeDirs ?? [],
            }),
            NullLogger<OrgPolicyResolver>.Instance);

        [Fact]
        public async Task Resolve_MappedOrg_UsesRegistryOverrides()
        {
            var record = new GitHubInstallationRecord
            {
                GitHubOrg = "Payments",
                SnykOrgId = "payments-snyk-org",
                SeverityThreshold = "critical",
                Ecosystem = "npm",
            };

            var policy = await Build(record).ResolveAsync("Payments", repo: null, CancellationToken.None);

            Assert.Equal("payments-snyk-org", policy.SnykOrgId);
            Assert.Equal("critical", policy.SeverityThreshold);
            Assert.Equal("npm", policy.Ecosystem);
        }

        [Fact]
        public async Task Resolve_UnmappedOrg_FallsBackToDefaults()
        {
            var policy = await Build(record: null).ResolveAsync("brand-new-org", repo: null, CancellationToken.None);

            Assert.Equal("default-org", policy.SnykOrgId);
            Assert.Equal("high", policy.SeverityThreshold);
            Assert.Equal(SnykSeverity.High, policy.Threshold);
            Assert.False(policy.Suspended);
            Assert.Empty(policy.ExcludeDirs);
        }

        [Fact]
        public async Task Resolve_SeededButUnmappedOrg_UsesDefaultSnykOrg()
        {
            // Seeded by the installation webhook but no explicit Snyk mapping yet.
            var record = new GitHubInstallationRecord { GitHubOrg = "Fresh", SnykOrgId = null };

            var policy = await Build(record).ResolveAsync("Fresh", repo: null, CancellationToken.None);

            Assert.Equal("default-org", policy.SnykOrgId);
        }

        [Fact]
        public async Task Resolve_NullRepo_DoesNotQueryRepoConfigAndUsesOrgExcludes()
        {
            var record = new GitHubInstallationRecord { GitHubOrg = "Acme", ExcludeDirs = ["obj", "bin"] };
            var registry = new FakeRegistry(record, new RepoScanConfig { ExcludeDirs = ["should-not-appear"] });
            var resolver = new OrgPolicyResolver(
                registry,
                Options.Create(new SnykOptions { DefaultSeverityThreshold = "high", DefaultEcosystem = "nuget" }),
                NullLogger<OrgPolicyResolver>.Instance);

            var policy = await resolver.ResolveAsync("Acme", repo: null, CancellationToken.None);

            Assert.Null(registry.RepoRequestedFor);
            Assert.Equal(["obj", "bin"], policy.ExcludeDirs);
        }

        [Fact]
        public async Task Resolve_WithRepo_UnionsDefaultOrgAndRepoExcludes_DedupedAndSanitized()
        {
            var record = new GitHubInstallationRecord { GitHubOrg = "Acme", ExcludeDirs = ["obj", "shared"] };
            var repoConfig = new RepoScanConfig
            {
                // "docling-sidecar" is the real motivating case; "shared" duplicates the org entry;
                // "src/nested" is path-like and must be dropped; whitespace must be trimmed.
                ExcludeDirs = ["docling-sidecar", "shared", "src/nested", "  spaced  "],
            };

            var policy = await Build(record, repoConfig, defaultExcludeDirs: ["node_modules"])
                .ResolveAsync("Acme", "atlas", CancellationToken.None);

            Assert.Equal(["node_modules", "obj", "shared", "docling-sidecar", "spaced"], policy.ExcludeDirs);
        }
    }
}
