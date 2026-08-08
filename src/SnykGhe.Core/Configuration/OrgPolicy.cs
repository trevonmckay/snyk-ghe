using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Snyk;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Configuration
{
    /// <summary>Effective, fully-resolved policy for a single scan.</summary>
    public sealed class ResolvedPolicy
    {
        public required string GitHubOrg { get; init; }

        public string? SnykOrgId { get; init; }

        public required string SeverityThreshold { get; init; }

        public required string Ecosystem { get; init; }

        public bool Suspended { get; init; }

        /// <summary>
        /// Sanitized Snyk <c>--exclude</c> names for this scan: the global defaults, the org list, and (when a
        /// repo is in scope) the repo list, unioned and cleaned. Empty when nothing is configured.
        /// </summary>
        public IReadOnlyList<string> ExcludeDirs { get; init; } = [];

        /// <summary>
        /// Effective base-branch scan patterns (most-specific layer wins: repo, else org, else global default).
        /// Empty means "scan every PR". See <see cref="BranchFilter"/>.
        /// </summary>
        public IReadOnlyList<string> ScanTargetBranches { get; init; } = [];

        public SnykSeverity Threshold => SnykSeverityExtensions.Parse(SeverityThreshold);

        /// <summary>
        /// Whether a pull request targeting <paramref name="baseRef"/> should be scanned under this policy.
        /// <paramref name="defaultBranch"/> resolves the <c>$default</c> pattern token.
        /// </summary>
        public bool ShouldScanTargetBranch(string? baseRef, string? defaultBranch) =>
            BranchFilter.Matches(ScanTargetBranches, baseRef, defaultBranch);
    }

    /// <summary>
    /// Resolves the effective policy for a GitHub org (and optionally a specific repo) from the installation
    /// registry, layering any explicit per-org Snyk mapping and overrides over the global Snyk defaults.
    /// Unmapped orgs fall back to defaults so a freshly-installed org still scans (against the default Snyk
    /// org). Exclude lists are additive: global defaults, then the org list, then the repo list. Base-branch
    /// scan patterns instead resolve by override: the most specific layer that sets any pattern wins.
    /// </summary>
    public sealed class OrgPolicyResolver
    {
        private readonly IGitHubInstallationRegistry _registry;
        private readonly SnykOptions _defaults;
        private readonly ILogger<OrgPolicyResolver> _logger;

        public OrgPolicyResolver(
            IGitHubInstallationRegistry registry,
            IOptions<SnykOptions> options,
            ILogger<OrgPolicyResolver> logger)
        {
            _registry = registry;
            _defaults = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Resolves the policy for a scan. Pass <paramref name="repo"/> when a specific repository is in scope
        /// so its exclude overrides layer on; pass null (e.g. from the branch-delete cleanup path, which only
        /// needs the Snyk org) to resolve org-level policy alone.
        /// </summary>
        public async Task<ResolvedPolicy> ResolveAsync(string gitHubOrg, string? repo, CancellationToken cancellationToken)
        {
            var record = await _registry.FindAsync(gitHubOrg, cancellationToken);

            var orgExcludes = record?.ExcludeDirs ?? [];
            var orgBranches = record?.ScanTargetBranches ?? [];
            IReadOnlyList<string> repoExcludes = [];
            IReadOnlyList<string> repoBranches = [];
            if (!string.IsNullOrWhiteSpace(repo))
            {
                var repoConfig = await _registry.FindRepoConfigAsync(gitHubOrg, repo, cancellationToken);
                repoExcludes = repoConfig?.ExcludeDirs ?? [];
                repoBranches = repoConfig?.ScanTargetBranches ?? [];
            }

            return new ResolvedPolicy
            {
                GitHubOrg = gitHubOrg,
                SnykOrgId = record?.SnykOrgId ?? _defaults.DefaultSnykOrgId,
                SeverityThreshold = record?.SeverityThreshold ?? _defaults.DefaultSeverityThreshold,
                Ecosystem = record?.Ecosystem ?? _defaults.DefaultEcosystem,
                Suspended = record?.Suspended ?? false,
                ExcludeDirs = ResolveExcludeDirs(gitHubOrg, repo, orgExcludes, repoExcludes),
                ScanTargetBranches = ResolveScanTargetBranches(repoBranches, orgBranches),
            };
        }

        /// <summary>
        /// Base-branch scan patterns resolve by override, not union: the most specific layer that sets any
        /// pattern wins outright (repo, else org, else the global default). This lets a repo narrow — or, with
        /// <c>*</c>, widen — its org's policy, which an additive union could not. All layers empty ⇒ no filter
        /// ⇒ every PR is scanned (opt-in default).
        /// </summary>
        private IReadOnlyList<string> ResolveScanTargetBranches(
            IReadOnlyList<string> repoBranches,
            IReadOnlyList<string> orgBranches)
        {
            IReadOnlyList<string> winner =
                repoBranches.Count > 0 ? repoBranches :
                orgBranches.Count > 0 ? orgBranches :
                _defaults.ScanTargetBranches;

            return BranchFilter.Sanitize(winner);
        }

        private IReadOnlyList<string> ResolveExcludeDirs(
            string gitHubOrg,
            string? repo,
            IReadOnlyList<string> orgExcludes,
            IReadOnlyList<string> repoExcludes)
        {
            var combined = _defaults.DefaultExcludeDirs
                .Concat(orgExcludes)
                .Concat(repoExcludes)
                .ToList();

            // Defensive: a path-like entry that slipped past the admin write would fail the whole scan, so drop
            // it and say so rather than let it break scanning.
            var dropped = combined
                .Where(e => !string.IsNullOrWhiteSpace(e) && ExcludeList.IsPathLike(e.Trim()))
                .ToList();

            if (dropped.Count > 0)
            {
                _logger.LogWarning(
                    "Ignoring {Count} path-like Snyk exclude entr(ies) for {Org}/{Repo}: {Entries}. --exclude accepts names, not paths.",
                    dropped.Count, gitHubOrg, repo ?? "*", string.Join(", ", dropped));
            }

            return ExcludeList.Sanitize(combined);
        }
    }
}
