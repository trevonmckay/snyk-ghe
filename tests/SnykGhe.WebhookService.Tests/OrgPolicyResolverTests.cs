using Microsoft.Extensions.Options;
using SnykGhe.WebhookService.Configuration;
using SnykGhe.WebhookService.Snyk;
using SnykGhe.WebhookService.Storage;

namespace SnykGhe.WebhookService.Tests
{
    public class OrgPolicyResolverTests
    {
        private sealed class FakeRegistry(GitHubInstallationRecord? record) : IGitHubInstallationRegistry
        {
            public Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken) =>
                Task.FromResult(record);

            public Task EnsureCreatedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetMappingAsync(string gitHubOrg, string snykOrgId, string? severityThreshold, string? ecosystem, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken) => Task.CompletedTask;
            public Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken) => Task.CompletedTask;
        }

        private static OrgPolicyResolver Build(GitHubInstallationRecord? record) => new(
            new FakeRegistry(record),
            Options.Create(new SnykOptions
            {
                DefaultSnykOrgId = "default-org",
                DefaultSeverityThreshold = "high",
                DefaultEcosystem = "nuget",
            }));

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

            var policy = await Build(record).ResolveAsync("Payments", CancellationToken.None);

            Assert.Equal("payments-snyk-org", policy.SnykOrgId);
            Assert.Equal("critical", policy.SeverityThreshold);
            Assert.Equal("npm", policy.Ecosystem);
        }

        [Fact]
        public async Task Resolve_UnmappedOrg_FallsBackToDefaults()
        {
            var policy = await Build(record: null).ResolveAsync("brand-new-org", CancellationToken.None);

            Assert.Equal("default-org", policy.SnykOrgId);
            Assert.Equal("high", policy.SeverityThreshold);
            Assert.Equal(SnykSeverity.High, policy.Threshold);
            Assert.False(policy.Suspended);
        }

        [Fact]
        public async Task Resolve_SeededButUnmappedOrg_UsesDefaultSnykOrg()
        {
            // Seeded by the installation webhook but no explicit Snyk mapping yet.
            var record = new GitHubInstallationRecord { GitHubOrg = "Fresh", SnykOrgId = null };

            var policy = await Build(record).ResolveAsync("Fresh", CancellationToken.None);

            Assert.Equal("default-org", policy.SnykOrgId);
        }
    }
}
