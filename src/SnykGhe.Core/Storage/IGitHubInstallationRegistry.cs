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

        /// <summary>
        /// Writes the org's policy overlay authoritatively: every field in <paramref name="overlay"/> becomes
        /// the stored value (nulls clear the override), while the GitHub-seeded install fields are preserved.
        /// Used by the admin API. Distinct from <see cref="SetSuspendedAsync"/>, which the suspend webhook uses
        /// to flip only the suspended flag without touching the rest of the overlay.
        /// </summary>
        Task SetOrgPolicyAsync(string gitHubOrg, OrgPolicyOverlay overlay, CancellationToken cancellationToken);

        Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken);

        Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken);

        Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken);

        /// <summary>Returns the repo-level scan overrides, or null when none are stored.</summary>
        Task<RepoScanConfig?> FindRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken);

        /// <summary>Writes the repo-level exclude list authoritatively (an empty list clears it).</summary>
        Task SetRepoConfigAsync(string gitHubOrg, string repo, IReadOnlyList<string> excludeDirs, CancellationToken cancellationToken);

        /// <summary>Removes all repo-level overrides for a repo.</summary>
        Task RemoveRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken);
    }
}
