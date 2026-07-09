using SnykGhe.Core.GitHub;

namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// Persists GitHub App installations and their explicit Snyk org mappings in Azure Table Storage.
    /// Seeding (from webhooks) and mapping (from the admin endpoint) are kept separate so re-installs
    /// never clobber an existing Snyk mapping.
    /// </summary>
    public interface IGitHubInstallationRegistry
    {
        /// <summary>Ensures the backing table exists. Called once at startup.</summary>
        Task EnsureCreatedAsync(CancellationToken cancellationToken);

        /// <summary>Upserts GitHub-known install details without overwriting an existing Snyk mapping or policy.</summary>
        Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken);

        /// <summary>Sets or updates the explicit Snyk mapping and optional policy overrides for an org.</summary>
        Task SetMappingAsync(string gitHubOrg, string snykOrgId, string? severityThreshold, string? ecosystem, CancellationToken cancellationToken);

        Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken);

        Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken);

        Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken);
    }
}
